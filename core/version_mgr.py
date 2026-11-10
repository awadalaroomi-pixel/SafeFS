import os
import shutil
import time
import difflib
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
import config
from core.database import Database
from core.file_ops import calculate_sha256, get_file_metadata, read_file_preview

class VersionManager:
    """
    Manages SafeFS snapshot backups, version trees, and safe atomic restorations.
    Implements OS journaling principles and safety invariants.
    """
    def __init__(self, db: Database, backup_base_dir: Path = config.BACKUP_DIR):
        self.db = db
        self.backup_base_dir = Path(backup_base_dir).resolve()
        self.backup_base_dir.mkdir(parents=True, exist_ok=True)

    def _generate_backup_storage_path(self, folder_id: int, relative_path: str, sha256_hash: str) -> Tuple[Path, str]:
        """
        Generates a collision-resistant, organized destination path inside the backup repository.
        Returns (absolute_path, relative_path_from_backup_base).
        """
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        hash_short = (sha256_hash or "nohash")[:8]
        rel_obj = Path(relative_path)
        filename = rel_obj.name
        
        # Subdirectory under backups/folder_{id}/path_segments
        sub_dir = self.backup_base_dir / f"folder_{folder_id}" / rel_obj.parent
        sub_dir.mkdir(parents=True, exist_ok=True)
        
        backup_filename = f"{timestamp_str}_{hash_short}_{filename}"
        backup_full_path = sub_dir / backup_filename
        
        # Relative path stored in database
        backup_rel_path = str(backup_full_path.relative_to(self.backup_base_dir)).replace("\\", "/")
        return backup_full_path, backup_rel_path

    def create_version(self, file_id: int, filepath: str, change_type: str = 'MODIFIED',
                       notes: Optional[str] = None) -> Optional[int]:
        """
        Creates a new immutable snapshot version of a file.
        Preserves metadata and performs deduplication if the file has not changed.
        """
        filepath = os.path.normpath(filepath)
        if not os.path.isfile(filepath):
            return None

        file_record = self.db.get_file_by_id(file_id)
        if not file_record:
            return None

        # Check file size limit to prevent out-of-memory or storage exhaustion
        meta = get_file_metadata(filepath)
        if not meta:
            return None
            
        file_size = meta["size_bytes"]
        if file_size > config.MAX_FILE_SIZE_MB * 1024 * 1024:
            notes = (notes or "") + f" [Warning: File size ({file_size} B) exceeds max versioning threshold]"
            return None

        sha256_hash = calculate_sha256(filepath)
        if not sha256_hash:
            return None

        # Deduplication check: check if the most recent version has the identical SHA-256 hash
        existing_versions = self.db.get_file_versions(file_id)
        if existing_versions and existing_versions[0]["sha256"] == sha256_hash and change_type != 'PRE_RESTORE':
            # File contents are already backed up in latest snapshot
            return existing_versions[0]["id"]

        # Generate backup destination
        backup_full_path, backup_rel_path = self._generate_backup_storage_path(
            file_record["folder_id"], file_record["relative_path"], sha256_hash
        )

        try:
            # Copy file with metadata preservation (shutil.copy2 preserves timestamps)
            shutil.copy2(filepath, backup_full_path)
        except (PermissionError, OSError) as e:
            return None

        # Record in database
        version_id = self.db.add_file_version(
            file_id=file_id,
            backup_rel_path=backup_rel_path,
            sha256=sha256_hash,
            size_bytes=file_size,
            change_type=change_type,
            notes=notes
        )

        # Enforce version retention limit
        settings = self.db.get_settings()
        max_versions = int(settings.get("max_versions_per_file", config.MAX_VERSIONS_PER_FILE))
        deleted_rel_paths = self.db.prune_file_versions(file_id, max_versions)
        for pruned_rel in deleted_rel_paths:
            pruned_full = self.backup_base_dir / pruned_rel
            try:
                if pruned_full.exists():
                    os.remove(pruned_full)
            except OSError:
                pass

        return version_id

    def restore_version(self, version_id: int, reason: str = "Manual Restore") -> Tuple[bool, str]:
        """
        Restores a file to an earlier version with absolute OS safety.
        CRITICAL SAFETY RULE: Never overwrite target file without first creating an emergency
        snapshot (PRE_RESTORE) of the target file's current on-disk state.
        """
        version = self.db.get_version_by_id(version_id)
        if not version:
            return False, "Selected version record does not exist in SafeFS database."

        file_id = version["file_id"]
        file_record = self.db.get_file_by_id(file_id)
        if not file_record:
            return False, "Target file record not found."

        target_path = file_record["path"]
        backup_full_path = self.backup_base_dir / version["backup_rel_path"]

        # 1. Verify backup file exists and matches expected cryptographic hash
        if not backup_full_path.exists():
            return False, f"Backup storage file missing on disk: {backup_full_path.name}"

        backup_hash = calculate_sha256(str(backup_full_path))
        if backup_hash != version["sha256"]:
            return False, "Backup file integrity verification failed! Backup may be corrupt or altered."

        pre_restore_backup_path = None
        # 2. Safety Invariant: Snapshot current file before touching it if it exists
        if os.path.exists(target_path):
            pre_hash = calculate_sha256(target_path)
            pre_version_id = self.create_version(
                file_id=file_id,
                filepath=target_path,
                change_type="PRE_RESTORE",
                notes=f"Automatic safety snapshot prior to restoring version #{version['version_number']}"
            )
            if pre_version_id:
                pre_v = self.db.get_version_by_id(pre_version_id)
                if pre_v:
                    pre_restore_backup_path = pre_v["backup_rel_path"]

        # 3. Ensure target directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        # 4. Perform atomic replacement
        try:
            # Copy backup file to target path
            shutil.copy2(str(backup_full_path), target_path)
        except (PermissionError, OSError) as e:
            self.db.record_recovery(
                file_id=file_id,
                version_id=version_id,
                target_path=target_path,
                restored_version_hash=version["sha256"],
                pre_restore_backup_path=pre_restore_backup_path,
                status="FAILED",
                details=f"OS I/O error during restoration: {str(e)}"
            )
            return False, f"Failed to restore file due to OS permission or I/O error: {str(e)}"

        # 5. Verify restored file hash
        restored_hash = calculate_sha256(target_path)
        meta = get_file_metadata(target_path)
        
        self.db.upsert_file(
            folder_id=file_record["folder_id"],
            path=target_path,
            filename=file_record["filename"],
            relative_path=file_record["relative_path"],
            sha256=restored_hash,
            size_bytes=meta["size_bytes"] if meta else 0,
            last_modified=meta["mtime"] if meta else time.time(),
            status="ACTIVE"
        )

        # 6. Record in recovery history
        self.db.record_recovery(
            file_id=file_id,
            version_id=version_id,
            target_path=target_path,
            restored_version_hash=version["sha256"],
            pre_restore_backup_path=pre_restore_backup_path,
            status="SUCCESS",
            details=f"Restored to Version #{version['version_number']} ({version['created_at']}). Reason: {reason}"
        )

        # 7. Add activity log
        self.db.add_activity_log(
            event_type="RESTORED",
            file_path=target_path,
            filename=file_record["filename"],
            folder_id=file_record["folder_id"],
            previous_hash=pre_hash if 'pre_hash' in locals() else None,
            new_hash=restored_hash,
            severity="INFO",
            details=f"Restored file to Version #{version['version_number']}"
        )

        return True, f"Successfully restored '{file_record['filename']}' to Version #{version['version_number']}. Pre-restore snapshot created for safety."

    def delete_version(self, version_id: int) -> Tuple[bool, str]:
        """Deletes a backup version both from the database and disk storage."""
        version = self.db.get_version_by_id(version_id)
        if not version:
            return False, "Version record not found."
            
        backup_rel_path = self.db.delete_version(version_id)
        if backup_rel_path:
            full_path = self.backup_base_dir / backup_rel_path
            try:
                if full_path.exists():
                    os.remove(full_path)
            except OSError as e:
                return True, f"Version removed from DB, but failed to delete backup file: {str(e)}"
        return True, "Version deleted successfully."

    def get_version_file_path(self, version_id: int) -> Optional[Path]:
        """Returns the absolute path of a backup version file."""
        version = self.db.get_version_by_id(version_id)
        if not version:
            return None
        full_path = self.backup_base_dir / version["backup_rel_path"]
        return full_path if full_path.exists() else None

    def compute_diff(self, v1_id: int, v2_id: Optional[int] = None, current_file: bool = False) -> Dict[str, Any]:
        """
        Computes a unified text diff between:
        - v1 and v2 (if v2_id is provided)
        - v1 and the current file on disk (if current_file is True)
        """
        v1 = self.db.get_version_by_id(v1_id)
        if not v1:
            return {"error": "Base version not found"}

        p1 = self.backup_base_dir / v1["backup_rel_path"]
        read1 = read_file_preview(str(p1))
        if read1["is_binary"]:
            return {"diff": "Binary file comparison is not supported in text diff viewer.", "is_binary": True}

        lines1 = read1["content"].splitlines(keepends=True)

        if current_file:
            target_path = v1["original_path"]
            label2 = f"Current Live File ({target_path})"
            read2 = read_file_preview(target_path)
            if read2["is_binary"]:
                return {"diff": "Live file is binary; text diff unavailable.", "is_binary": True}
            lines2 = read2["content"].splitlines(keepends=True)
        elif v2_id:
            v2 = self.db.get_version_by_id(v2_id)
            if not v2:
                return {"error": "Comparison version not found"}
            p2 = self.backup_base_dir / v2["backup_rel_path"]
            label2 = f"Version #{v2['version_number']} ({v2['created_at']})"
            read2 = read_file_preview(str(p2))
            if read2["is_binary"]:
                return {"diff": "Comparison file is binary; text diff unavailable.", "is_binary": True}
            lines2 = read2["content"].splitlines(keepends=True)
        else:
            return {"error": "Must specify either comparison version or current_file=True"}

        label1 = f"Version #{v1['version_number']} ({v1['created_at']})"
        diff_lines = list(difflib.unified_diff(lines1, lines2, fromfile=label1, tofile=label2, lineterm=""))
        diff_text = "\n".join(diff_lines) if diff_lines else "Files are identical in content."

        return {
            "diff": diff_text,
            "is_binary": False,
            "v1_label": label1,
            "v2_label": label2,
            "has_differences": len(diff_lines) > 0
        }
