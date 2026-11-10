import os
import time
import threading
from collections import deque
from pathlib import Path
from typing import Dict, Any, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from core.database import Database
from core.version_mgr import VersionManager
from core.detector import ThreatDetector
from core.file_ops import calculate_sha256, get_file_metadata, is_safe_path

class SafeFSEventHandler(FileSystemEventHandler):
    """
    Real-time filesystem event listener utilizing kernel notification subsystems
    (ReadDirectoryChangesW on Windows, inotify on Linux) via Python Watchdog.
    """
    def __init__(self, db: Database, version_mgr: VersionManager,
                 detector: ThreatDetector, event_queue: deque):
        super().__init__()
        self.db = db
        self.version_mgr = version_mgr
        self.detector = detector
        self.event_queue = event_queue
        
        # Debounce dictionary: {norm_path: timestamp}
        self._debounce: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _should_debounce(self, path: str, cooldown: float = 1.0) -> bool:
        """OS file write operations frequently fire multiple raw notifications for a single save."""
        with self._lock:
            now = time.time()
            last_time = self._debounce.get(path, 0.0)
            if now - last_time < cooldown:
                return True
            self._debounce[path] = now
            return False

    def _is_ignored(self, path: str) -> bool:
        """Filters out temporary editor files, swap files, and internal backup paths."""
        norm = os.path.normpath(path).lower()
        name = os.path.basename(norm)

        # Ignore dotfiles, temp files, and editor swap files
        if (name.startswith(".") or name.startswith("~") or 
            name.endswith(".tmp") or name.endswith(".swp") or 
            name.endswith(".crdownload")):
            return True

        # Absolutely never monitor internal backup or data directory
        for blacklisted in config.SYSTEM_BLACKLIST_DIRECTORIES:
            if norm == blacklisted or norm.startswith(blacklisted + os.sep):
                return True

        return False

    def _find_folder_for_path(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Maps a modified file path to its parent monitored folder in the database."""
        folders = self.db.get_monitored_folders(active_only=True)
        norm_file = os.path.normpath(filepath)
        for folder in folders:
            folder_path = os.path.normpath(folder["path"])
            if norm_file.startswith(folder_path + os.sep) or norm_file == folder_path:
                return folder
        return None

    def _push_event(self, event_data: Dict[str, Any]):
        """Pushes event into in-memory queue for high-speed live dashboard streaming."""
        with self._lock:
            self.event_queue.append(event_data)
            # Cap in-memory queue to 200 events
            while len(self.event_queue) > 200:
                self.event_queue.popleft()

    def on_created(self, event: FileSystemEvent):
        if event.is_directory or self._is_ignored(event.src_path):
            return

        filepath = os.path.normpath(event.src_path)
        if self._should_debounce(filepath, cooldown=0.8):
            return

        folder = self._find_folder_for_path(filepath)
        if not folder:
            return

        folder_id = folder["id"]
        filename = os.path.basename(filepath)
        try:
            rel_path = os.path.relpath(filepath, folder["path"])
        except ValueError:
            rel_path = filename

        # Wait briefly for file write completion to calculate accurate hash
        time.sleep(0.05)
        sha256 = calculate_sha256(filepath)
        meta = get_file_metadata(filepath)

        file_id = self.db.upsert_file(
            folder_id=folder_id,
            path=filepath,
            filename=filename,
            relative_path=rel_path,
            sha256=sha256,
            size_bytes=meta["size_bytes"] if meta else 0,
            last_modified=meta["mtime"] if meta else time.time(),
            status="ACTIVE"
        )

        # Create initial baseline snapshot version
        self.version_mgr.create_version(
            file_id=file_id,
            filepath=filepath,
            change_type="INITIAL",
            notes="Initial snapshot on file creation"
        )

        log_id = self.db.add_activity_log(
            event_type="CREATED",
            file_path=filepath,
            filename=filename,
            folder_id=folder_id,
            previous_hash=None,
            new_hash=sha256,
            severity="INFO",
            details=f"New file created ({meta['size_bytes'] if meta else 0} bytes)"
        )

        self._push_event({
            "id": log_id,
            "event_type": "CREATED",
            "file_path": filepath,
            "filename": filename,
            "folder_label": folder["label"],
            "hash": sha256,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

        self.db.update_folder_file_count(folder_id)
        self.detector.process_event("CREATED", filepath)

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory or self._is_ignored(event.src_path):
            return

        filepath = os.path.normpath(event.src_path)
        if self._should_debounce(filepath, cooldown=config.DEBOUNCE_SECONDS):
            return

        folder = self._find_folder_for_path(filepath)
        if not folder:
            return

        folder_id = folder["id"]
        filename = os.path.basename(filepath)

        if not os.path.exists(filepath):
            return

        # Fetch current record in database to detect actual content hash change
        file_rec = self.db.get_file_by_path(filepath)
        old_hash = file_rec["sha256"] if file_rec else None

        new_hash = calculate_sha256(filepath)
        if not new_hash:
            return

        # If hash is unchanged (e.g. metadata or timestamp touch only), don't duplicate backups
        if old_hash and old_hash == new_hash:
            return

        meta = get_file_metadata(filepath)
        try:
            rel_path = os.path.relpath(filepath, folder["path"])
        except ValueError:
            rel_path = filename

        file_id = self.db.upsert_file(
            folder_id=folder_id,
            path=filepath,
            filename=filename,
            relative_path=rel_path,
            sha256=new_hash,
            size_bytes=meta["size_bytes"] if meta else 0,
            last_modified=meta["mtime"] if meta else time.time(),
            status="MODIFIED"
        )

        # Preserve the new modification version in SafeFS repository
        self.version_mgr.create_version(
            file_id=file_id,
            filepath=filepath,
            change_type="MODIFIED",
            notes="Automatic backup snapshot upon detected modification"
        )

        log_id = self.db.add_activity_log(
            event_type="MODIFIED",
            file_path=filepath,
            filename=filename,
            folder_id=folder_id,
            previous_hash=old_hash,
            new_hash=new_hash,
            severity="INFO",
            details="File content modified"
        )

        self._push_event({
            "id": log_id,
            "event_type": "MODIFIED",
            "file_path": filepath,
            "filename": filename,
            "folder_label": folder["label"],
            "hash": new_hash,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

        self.detector.process_event("MODIFIED", filepath)

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory or self._is_ignored(event.src_path):
            return

        filepath = os.path.normpath(event.src_path)
        folder = self._find_folder_for_path(filepath)
        folder_id = folder["id"] if folder else None
        filename = os.path.basename(filepath)

        file_rec = self.db.get_file_by_path(filepath)
        old_hash = file_rec["sha256"] if file_rec else None

        self.db.mark_file_deleted(filepath)
        if folder_id:
            self.db.update_folder_file_count(folder_id)

        log_id = self.db.add_activity_log(
            event_type="DELETED",
            file_path=filepath,
            filename=filename,
            folder_id=folder_id,
            previous_hash=old_hash,
            new_hash=None,
            severity="WARNING",
            details="File deleted from physical storage"
        )

        self._push_event({
            "id": log_id,
            "event_type": "DELETED",
            "file_path": filepath,
            "filename": filename,
            "folder_label": folder["label"] if folder else "Unknown",
            "hash": old_hash,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

        self.detector.process_event("DELETED", filepath)

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory or self._is_ignored(event.dest_path):
            return

        src_path = os.path.normpath(event.src_path)
        dest_path = os.path.normpath(event.dest_path)
        filename = os.path.basename(dest_path)

        folder = self._find_folder_for_path(dest_path)
        folder_id = folder["id"] if folder else None

        # Mark source path deleted/superseded
        self.db.mark_file_deleted(src_path)

        # Upsert destination path
        new_hash = calculate_sha256(dest_path)
        meta = get_file_metadata(dest_path)
        try:
            rel_path = os.path.relpath(dest_path, folder["path"]) if folder else filename
        except ValueError:
            rel_path = filename

        if folder_id:
            file_id = self.db.upsert_file(
                folder_id=folder_id,
                path=dest_path,
                filename=filename,
                relative_path=rel_path,
                sha256=new_hash,
                size_bytes=meta["size_bytes"] if meta else 0,
                last_modified=meta["mtime"] if meta else time.time(),
                status="ACTIVE"
            )
            self.version_mgr.create_version(
                file_id=file_id,
                filepath=dest_path,
                change_type="MOVED",
                notes=f"Renamed/Moved from {os.path.basename(src_path)}"
            )
            self.db.update_folder_file_count(folder_id)

        log_id = self.db.add_activity_log(
            event_type="MOVED",
            file_path=dest_path,
            filename=filename,
            folder_id=folder_id,
            previous_hash=None,
            new_hash=new_hash,
            severity="INFO",
            details=f"File moved/renamed from '{os.path.basename(src_path)}'"
        )

        self._push_event({
            "id": log_id,
            "event_type": "MOVED",
            "file_path": dest_path,
            "filename": filename,
            "folder_label": folder["label"] if folder else "Unknown",
            "hash": new_hash,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

        self.detector.process_event("MOVED", dest_path, src_path=src_path)


class MonitorManager:
    """
    Orchestrates the Watchdog Observer background daemon and dynamic directory watchers.
    """
    def __init__(self, db: Database, version_mgr: VersionManager, detector: ThreatDetector):
        self.db = db
        self.version_mgr = version_mgr
        self.detector = detector
        self.live_events = deque(maxlen=200)
        self.handler = SafeFSEventHandler(db, version_mgr, detector, self.live_events)
        
        self.observer = Observer()
        self.observer.daemon = True
        self._watches: Dict[int, Any] = {}  # {folder_id: watch_handle}
        self._is_running = False
        self._lock = threading.Lock()

    def start(self):
        """Starts the filesystem observer and registers all active monitored folders."""
        with self._lock:
            if self._is_running:
                return

            self.observer = Observer()
            self.observer.daemon = True
            folders = self.db.get_monitored_folders(active_only=True)
            for folder in folders:
                self._watch_folder(folder["id"], folder["path"])

            self.observer.start()
            self._is_running = True

    def stop(self):
        """Cleanly stops the observer thread."""
        with self._lock:
            if not self._is_running:
                return
            self.observer.stop()
            self.observer.join(timeout=3.0)
            self._watches.clear()
            self._is_running = False

    def _watch_folder(self, folder_id: int, folder_path: str):
        """Internal helper to attach a Watchdog watch on an existing directory."""
        if not os.path.isdir(folder_path):
            return
        try:
            watch = self.observer.schedule(self.handler, path=folder_path, recursive=True)
            self._watches[folder_id] = watch
        except Exception:
            pass

    def add_folder(self, folder_id: int, folder_path: str):
        """Adds a new folder to active monitoring dynamically without restarting observer."""
        with self._lock:
            if self._is_running and folder_id not in self._watches:
                self._watch_folder(folder_id, folder_path)

    def remove_folder(self, folder_id: int):
        """Removes a folder from active monitoring."""
        with self._lock:
            if folder_id in self._watches and self._is_running:
                try:
                    self.observer.unschedule(self._watches[folder_id])
                except Exception:
                    pass
                del self._watches[folder_id]

    def is_running(self) -> bool:
        return self._is_running and self.observer.is_alive()

    def get_status(self) -> Dict[str, Any]:
        """Provides health metrics on the filesystem monitoring subsystem."""
        return {
            "is_running": self.is_running(),
            "monitored_folders_count": len(self._watches),
            "buffered_event_count": len(self.live_events),
            "engine": "Watchdog / ReadDirectoryChangesW (Win32) / inotify (Linux)"
        }

    def get_recent_live_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.handler._lock:
            events = list(self.live_events)
            return events[-limit:]
