import sqlite3
import os
import json
import threading
from contextlib import contextmanager
from typing import List, Dict, Any, Optional
import config

DB_LOCK = threading.RLock()

class Database:
    def __init__(self, db_path: str = str(config.DATABASE_PATH)):
        self.db_path = db_path
        self.init_db()

    @contextmanager
    def get_connection(self):
        """Context manager providing thread-safe SQLite connection with WAL mode enabled."""
        with DB_LOCK:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def init_db(self):
        """Initialize all relational tables representing SafeFS OS data structures."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Monitored Folders table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitored_folders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    label TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_count INTEGER DEFAULT 0
                )
            """)

            # File Metadata & State table (Simulates Inode Table)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    folder_id INTEGER NOT NULL REFERENCES monitored_folders(id) ON DELETE CASCADE,
                    path TEXT UNIQUE NOT NULL,
                    filename TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    sha256 TEXT,
                    size_bytes INTEGER DEFAULT 0,
                    last_modified REAL,
                    status TEXT DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # File Versions (Snapshot & Rollback journal)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    version_number INTEGER NOT NULL,
                    backup_rel_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER DEFAULT 0,
                    change_type TEXT DEFAULT 'MODIFIED',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Event Logs (Audit trail of file system events)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    folder_id INTEGER,
                    file_path TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    previous_hash TEXT,
                    new_hash TEXT,
                    severity TEXT DEFAULT 'INFO',
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Security Alerts (Rule-based threat engine findings)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_files TEXT,
                    status TEXT DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP
                )
            """)

            # Recovery History (Safe restoration audit log)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recovery_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER,
                    version_id INTEGER,
                    target_path TEXT NOT NULL,
                    restored_version_hash TEXT NOT NULL,
                    pre_restore_backup_path TEXT,
                    status TEXT DEFAULT 'SUCCESS',
                    restored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)

            # System Settings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            # Create Indexes for fast queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_versions_file ON file_versions(file_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON activity_logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status)")

            # Seed default settings if empty
            default_settings = {
                "burst_modification_count": str(config.BURST_MODIFICATION_COUNT),
                "burst_window_seconds": str(config.BURST_WINDOW_SECONDS),
                "burst_deletion_count": str(config.BURST_DELETION_COUNT),
                "burst_deletion_window": str(config.BURST_DELETION_WINDOW),
                "mass_rename_count": str(config.MASS_RENAME_COUNT),
                "mass_rename_window": str(config.MASS_RENAME_WINDOW),
                "max_versions_per_file": str(config.MAX_VERSIONS_PER_FILE),
                "debounce_seconds": str(config.DEBOUNCE_SECONDS),
                "auto_restore_safety": "true"
            }
            for k, v in default_settings.items():
                cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    # --- Monitored Folders Operations ---
    def add_monitored_folder(self, path: str, label: Optional[str] = None) -> int:
        norm_path = os.path.normpath(path)
        if not label:
            label = os.path.basename(norm_path) or norm_path
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO monitored_folders (path, label, is_active) VALUES (?, ?, 1)",
                (norm_path, label)
            )
            return cursor.lastrowid

    def remove_monitored_folder(self, folder_id: int):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM monitored_folders WHERE id = ?", (folder_id,))

    def get_monitored_folders(self, active_only: bool = False) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if active_only:
                cursor.execute("SELECT * FROM monitored_folders WHERE is_active = 1 ORDER BY id DESC")
            else:
                cursor.execute("SELECT * FROM monitored_folders ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_folder_by_id(self, folder_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM monitored_folders WHERE id = ?", (folder_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def toggle_folder_active(self, folder_id: int, is_active: bool):
        with self.get_connection() as conn:
            conn.execute("UPDATE monitored_folders SET is_active = ? WHERE id = ?", (1 if is_active else 0, folder_id))

    def update_folder_file_count(self, folder_id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM files WHERE folder_id = ? AND status != 'DELETED'", (folder_id,))
            count = cursor.fetchone()[0]
            cursor.execute("UPDATE monitored_folders SET file_count = ? WHERE id = ?", (count, folder_id))

    # --- File Operations ---
    def upsert_file(self, folder_id: int, path: str, filename: str, relative_path: str,
                    sha256: Optional[str], size_bytes: int, last_modified: float,
                    status: str = 'ACTIVE') -> int:
        norm_path = os.path.normpath(path)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO files (folder_id, path, filename, relative_path, sha256, size_bytes, last_modified, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(path) DO UPDATE SET
                    folder_id = excluded.folder_id,
                    filename = excluded.filename,
                    relative_path = excluded.relative_path,
                    sha256 = excluded.sha256,
                    size_bytes = excluded.size_bytes,
                    last_modified = excluded.last_modified,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
            """, (folder_id, norm_path, filename, relative_path, sha256, size_bytes, last_modified, status))
            
            cursor.execute("SELECT id FROM files WHERE path = ?", (norm_path,))
            file_id = cursor.fetchone()[0]
            return file_id

    def get_file_by_path(self, path: str) -> Optional[Dict[str, Any]]:
        norm_path = os.path.normpath(path)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE path = ?", (norm_path,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_file_by_id(self, file_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_files(self, folder_id: Optional[int] = None, status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT f.*, mf.label as folder_label,
                       (SELECT COUNT(*) FROM file_versions v WHERE v.file_id = f.id) as version_count
                FROM files f
                LEFT JOIN monitored_folders mf ON f.folder_id = mf.id
                WHERE 1=1
            """
            params = []
            if folder_id:
                query += " AND f.folder_id = ?"
                params.append(folder_id)
            if status:
                query += " AND f.status = ?"
                params.append(status)
            if search:
                query += " AND (f.filename LIKE ? OR f.relative_path LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%"])
            query += " ORDER BY f.updated_at DESC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def mark_file_deleted(self, path: str):
        norm_path = os.path.normpath(path)
        with self.get_connection() as conn:
            conn.execute("UPDATE files SET status = 'DELETED', updated_at = CURRENT_TIMESTAMP WHERE path = ?", (norm_path,))

    def update_file_status(self, file_id: int, status: str, new_hash: Optional[str] = None):
        with self.get_connection() as conn:
            if new_hash:
                conn.execute("UPDATE files SET status = ?, sha256 = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                             (status, new_hash, file_id))
            else:
                conn.execute("UPDATE files SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                             (status, file_id))

    # --- Version Management Operations ---
    def add_file_version(self, file_id: int, backup_rel_path: str, sha256: str,
                         size_bytes: int, change_type: str = 'MODIFIED',
                         notes: Optional[str] = None) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COALESCE(MAX(version_number), 0) + 1 FROM file_versions WHERE file_id = ?", (file_id,))
            version_number = cursor.fetchone()[0]

            cursor.execute("""
                INSERT INTO file_versions (file_id, version_number, backup_rel_path, sha256, size_bytes, change_type, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (file_id, version_number, backup_rel_path, sha256, size_bytes, change_type, notes))
            return cursor.lastrowid

    def get_file_versions(self, file_id: int) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.*, f.filename, f.path as original_path
                FROM file_versions v
                JOIN files f ON v.file_id = f.id
                WHERE v.file_id = ?
                ORDER BY v.version_number DESC
            """, (file_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_version_by_id(self, version_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.*, f.filename, f.path as original_path, f.folder_id
                FROM file_versions v
                JOIN files f ON v.file_id = f.id
                WHERE v.id = ?
            """, (version_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def delete_version(self, version_id: int) -> Optional[str]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT backup_rel_path FROM file_versions WHERE id = ?", (version_id,))
            row = cursor.fetchone()
            if row:
                backup_rel_path = row[0]
                cursor.execute("DELETE FROM file_versions WHERE id = ?", (version_id,))
                return backup_rel_path
            return None

    def prune_file_versions(self, file_id: int, max_versions: int) -> List[str]:
        """Prune oldest versions exceeding max_versions limit, returns deleted backup_rel_paths."""
        deleted_paths = []
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, backup_rel_path FROM file_versions
                WHERE file_id = ?
                ORDER BY version_number ASC
            """, (file_id,))
            versions = cursor.fetchall()
            if len(versions) > max_versions:
                excess_count = len(versions) - max_versions
                to_delete = versions[:excess_count]
                for v_id, rel_path in to_delete:
                    cursor.execute("DELETE FROM file_versions WHERE id = ?", (v_id,))
                    deleted_paths.append(rel_path)
        return deleted_paths

    def get_all_backup_versions(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT v.*, f.filename, f.path as original_path, mf.label as folder_label
                FROM file_versions v
                JOIN files f ON v.file_id = f.id
                LEFT JOIN monitored_folders mf ON f.folder_id = mf.id
                WHERE 1=1
            """
            params = []
            if search:
                query += " AND (f.filename LIKE ? OR f.path LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%"])
            query += " ORDER BY v.created_at DESC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    # --- Activity Logs Operations ---
    def add_activity_log(self, event_type: str, file_path: str, filename: str,
                         folder_id: Optional[int] = None, previous_hash: Optional[str] = None,
                         new_hash: Optional[str] = None, severity: str = 'INFO',
                         details: Optional[str] = None) -> int:
        norm_path = os.path.normpath(file_path)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO activity_logs (event_type, folder_id, file_path, filename, previous_hash, new_hash, severity, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_type, folder_id, norm_path, filename, previous_hash, new_hash, severity, details))
            return cursor.lastrowid

    def get_activity_logs(self, limit: int = 100, offset: int = 0,
                          event_type: Optional[str] = None, severity: Optional[str] = None,
                          search: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM activity_logs WHERE 1=1"
            params = []
            if event_type and event_type != "ALL":
                query += " AND event_type = ?"
                params.append(event_type)
            if severity and severity != "ALL":
                query += " AND severity = ?"
                params.append(severity)
            if search:
                query += " AND (filename LIKE ? OR file_path LIKE ? OR details LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def count_activity_logs(self, event_type: Optional[str] = None, severity: Optional[str] = None, search: Optional[str] = None) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT COUNT(*) FROM activity_logs WHERE 1=1"
            params = []
            if event_type and event_type != "ALL":
                query += " AND event_type = ?"
                params.append(event_type)
            if severity and severity != "ALL":
                query += " AND severity = ?"
                params.append(severity)
            if search:
                query += " AND (filename LIKE ? OR file_path LIKE ? OR details LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
            cursor.execute(query, params)
            return cursor.fetchone()[0]

    def clear_activity_logs(self):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM activity_logs")

    # --- Security Alerts Operations ---
    def add_security_alert(self, rule_name: str, severity: str, title: str,
                           description: str, affected_files: List[str]) -> int:
        files_json = json.dumps(affected_files)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_alerts (rule_name, severity, title, description, affected_files)
                VALUES (?, ?, ?, ?, ?)
            """, (rule_name, severity, title, description, files_json))
            alert_id = cursor.lastrowid
            
            # Also log as high severity activity log
            cursor.execute("""
                INSERT INTO activity_logs (event_type, file_path, filename, severity, details)
                VALUES (?, ?, ?, ?, ?)
            """, ("THREAT_DETECTED", "MULTIPLE" if len(affected_files) > 1 else affected_files[0],
                  title, severity, description))
            return alert_id

    def get_security_alerts(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT * FROM security_alerts WHERE status = ? ORDER BY id DESC", (status,))
            else:
                cursor.execute("SELECT * FROM security_alerts ORDER BY id DESC")
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                try:
                    item["affected_files"] = json.loads(item["affected_files"])
                except Exception:
                    item["affected_files"] = []
                results.append(item)
            return results

    def resolve_security_alert(self, alert_id: int):
        with self.get_connection() as conn:
            conn.execute("UPDATE security_alerts SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP WHERE id = ?", (alert_id,))

    def dismiss_security_alert(self, alert_id: int):
        with self.get_connection() as conn:
            conn.execute("UPDATE security_alerts SET status = 'DISMISSED', resolved_at = CURRENT_TIMESTAMP WHERE id = ?", (alert_id,))

    # --- Recovery History ---
    def record_recovery(self, file_id: Optional[int], version_id: Optional[int],
                        target_path: str, restored_version_hash: str,
                        pre_restore_backup_path: Optional[str], status: str = 'SUCCESS',
                        details: Optional[str] = None) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO recovery_history (file_id, version_id, target_path, restored_version_hash, pre_restore_backup_path, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (file_id, version_id, target_path, restored_version_hash, pre_restore_backup_path, status, details))
            return cursor.lastrowid

    def get_recovery_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rh.*, f.filename
                FROM recovery_history rh
                LEFT JOIN files f ON rh.file_id = f.id
                ORDER BY rh.id DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # --- Settings Operations ---
    def get_settings(self) -> Dict[str, str]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            return {row["key"]: row["value"] for row in cursor.fetchall()}

    def update_settings(self, settings_dict: Dict[str, str]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for k, v in settings_dict.items():
                cursor.execute("""
                    INSERT INTO settings (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """, (k, str(v)))

    # --- Dashboard Summary Aggregates ---
    def get_dashboard_summary(self) -> Dict[str, Any]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Monitored Folders count
            cursor.execute("SELECT COUNT(*) FROM monitored_folders WHERE is_active = 1")
            active_folders = cursor.fetchone()[0]

            # Monitored Files count
            cursor.execute("SELECT COUNT(*) FROM files WHERE status != 'DELETED'")
            total_files = cursor.fetchone()[0]

            # Modified Files count
            cursor.execute("SELECT COUNT(*) FROM files WHERE status = 'MODIFIED'")
            modified_files = cursor.fetchone()[0]

            # Deleted Files count
            cursor.execute("SELECT COUNT(*) FROM files WHERE status = 'DELETED'")
            deleted_files = cursor.fetchone()[0]

            # Total Backup Versions
            cursor.execute("SELECT COUNT(*) FROM file_versions")
            total_versions = cursor.fetchone()[0]

            # Active Suspicious Activities (Alerts)
            cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE status = 'ACTIVE'")
            active_threats = cursor.fetchone()[0]

            # Recent file activities (last 10)
            cursor.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 10")
            recent_activities = [dict(row) for row in cursor.fetchall()]

            # Event distribution by type
            cursor.execute("SELECT event_type, COUNT(*) as count FROM activity_logs GROUP BY event_type")
            event_distribution = {row["event_type"]: row["count"] for row in cursor.fetchall()}

            # Threat severity distribution
            cursor.execute("SELECT severity, COUNT(*) as count FROM security_alerts GROUP BY severity")
            threat_distribution = {row["severity"]: row["count"] for row in cursor.fetchall()}

            return {
                "active_folders": active_folders,
                "total_files": total_files,
                "modified_files": modified_files,
                "deleted_files": deleted_files,
                "total_versions": total_versions,
                "active_threats": active_threats,
                "recent_activities": recent_activities,
                "event_distribution": event_distribution,
                "threat_distribution": threat_distribution
            }
