import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import config
from core.database import Database
from core.version_mgr import VersionManager
from core.file_ops import calculate_sha256, get_file_metadata

class IntegrityChecker:
    """
    Manages cryptographic file verification and baseline indexing.
    Demonstrates OS integrity assurance via SHA-256 block hashing.
    """
    def __init__(self, db: Database, version_mgr: VersionManager):
        self.db = db
        self.version_mgr = version_mgr

    def verify_file(self, file_id: int) -> Dict[str, Any]:
        """
        Calculates live SHA-256 hash for a specific file and compares with stored DB baseline.
        """
        file_rec = self.db.get_file_by_id(file_id)
        if not file_rec:
            return {"file_id": file_id, "status": "NOT_FOUND", "message": "File not tracked in database"}

        target_path = file_rec["path"]
        stored_hash = file_rec["sha256"]

        if not os.path.exists(target_path):
            self.db.update_file_status(file_id, status="MISSING")
            self.db.add_activity_log(
                event_type="INTEGRITY_CHECK",
                file_path=target_path,
                filename=file_rec["filename"],
                folder_id=file_rec["folder_id"],
                previous_hash=stored_hash,
                new_hash=None,
                severity="HIGH",
                details="Integrity verification failed: File physically missing from disk."
            )
            return {
                "file_id": file_id,
                "filename": file_rec["filename"],
                "status": "MISSING",
                "expected_hash": stored_hash,
                "current_hash": None,
                "message": "File is missing on physical storage."
            }

        live_hash = calculate_sha256(target_path)
        if live_hash is None:
            return {
                "file_id": file_id,
                "filename": file_rec["filename"],
                "status": "ERROR",
                "message": "OS permission denied or I/O error while reading file."
            }

        if stored_hash is None:
            # First-time hash baseline update
            meta = get_file_metadata(target_path)
            self.db.upsert_file(
                folder_id=file_rec["folder_id"],
                path=target_path,
                filename=file_rec["filename"],
                relative_path=file_rec["relative_path"],
                sha256=live_hash,
                size_bytes=meta["size_bytes"] if meta else 0,
                last_modified=meta["mtime"] if meta else 0.0,
                status="ACTIVE"
            )
            return {
                "file_id": file_id,
                "filename": file_rec["filename"],
                "status": "INITIALIZED",
                "hash": live_hash,
                "message": "Baseline cryptographic hash established."
            }

        if live_hash == stored_hash:
            return {
                "file_id": file_id,
                "filename": file_rec["filename"],
                "status": "VALID",
                "hash": live_hash,
                "message": "Cryptographic integrity verified intact. No unauthorized modifications."
            }
        else:
            # Hash mismatch! File content was modified
            self.db.update_file_status(file_id, status="MODIFIED", new_hash=live_hash)
            self.db.add_activity_log(
                event_type="INTEGRITY_CHECK",
                file_path=target_path,
                filename=file_rec["filename"],
                folder_id=file_rec["folder_id"],
                previous_hash=stored_hash,
                new_hash=live_hash,
                severity="MEDIUM",
                details="Integrity mismatch: Live file hash differs from recorded baseline."
            )
            return {
                "file_id": file_id,
                "filename": file_rec["filename"],
                "status": "MODIFIED",
                "expected_hash": stored_hash,
                "current_hash": live_hash,
                "message": "Integrity mismatch detected! Live disk contents differ from stored baseline."
            }

    def verify_all_files(self, folder_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Runs comprehensive integrity check across all monitored files.
        """
        files = self.db.get_files(folder_id=folder_id)
        results = []
        counts = {"VALID": 0, "MODIFIED": 0, "MISSING": 0, "ERROR": 0, "INITIALIZED": 0}

        for f in files:
            res = self.verify_file(f["id"])
            status = res.get("status", "ERROR")
            counts[status] = counts.get(status, 0) + 1
            if status != "VALID":
                results.append(res)

        return {
            "total_checked": len(files),
            "counts": counts,
            "anomalies": results
        }

    def scan_and_index_folder(self, folder_id: int) -> Dict[str, Any]:
        """
        Scans a monitored directory tree, indexes all existing files into the database,
        calculates baseline SHA-256 hashes, and creates initial snapshot backups.
        """
        folder = self.db.get_folder_by_id(folder_id)
        if not folder:
            return {"success": False, "error": "Folder not found in database"}

        root_path = Path(folder["path"]).resolve()
        if not root_path.exists():
            return {"success": False, "error": f"Folder does not exist on disk: {root_path}"}

        indexed_count = 0
        skipped_count = 0

        for dirpath, dirnames, filenames in os.walk(str(root_path)):
            # Skip hidden directories (.git, .safefs, etc.)
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

            for filename in filenames:
                if filename.startswith(".") or filename.endswith("~") or filename.endswith(".tmp"):
                    continue

                full_path = os.path.normpath(os.path.join(dirpath, filename))
                try:
                    rel_path = os.path.relpath(full_path, str(root_path))
                except ValueError:
                    rel_path = filename

                meta = get_file_metadata(full_path)
                if not meta or not meta["is_file"]:
                    skipped_count += 1
                    continue

                # Compute baseline SHA-256
                sha256 = calculate_sha256(full_path)
                file_id = self.db.upsert_file(
                    folder_id=folder_id,
                    path=full_path,
                    filename=filename,
                    relative_path=rel_path,
                    sha256=sha256,
                    size_bytes=meta["size_bytes"],
                    last_modified=meta["mtime"],
                    status="ACTIVE"
                )

                # Create baseline version #1 if none exist
                versions = self.db.get_file_versions(file_id)
                if not versions:
                    self.version_mgr.create_version(
                        file_id=file_id,
                        filepath=full_path,
                        change_type="INITIAL",
                        notes="Initial baseline snapshot captured during folder indexing"
                    )

                indexed_count += 1

        self.db.update_folder_file_count(folder_id)
        return {
            "success": True,
            "folder_id": folder_id,
            "folder_path": str(root_path),
            "indexed_count": indexed_count,
            "skipped_count": skipped_count
        }
