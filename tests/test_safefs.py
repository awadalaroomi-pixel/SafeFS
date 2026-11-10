import os
import sys
import time
import shutil
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path so tests can be run from any working directory
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.database import Database
from core.file_ops import calculate_sha256, is_safe_path, get_file_metadata, validate_monitored_folder_candidate
from core.version_mgr import VersionManager
from core.detector import ThreatDetector
from core.integrity import IntegrityChecker
from core.monitor import SafeFSEventHandler
from watchdog.events import FileCreatedEvent, FileModifiedEvent, FileDeletedEvent, FileMovedEvent

class TestSafeFS(unittest.TestCase):
    def setUp(self):
        # Create isolated temporary directory for test DB, test files, and test backups
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        
        self.db_path = str(self.base_path / "test_safefs.db")
        self.backup_path = self.base_path / "test_backups"
        self.monitored_path = self.base_path / "watched_folder"
        
        self.backup_path.mkdir(parents=True, exist_ok=True)
        self.monitored_path.mkdir(parents=True, exist_ok=True)

        self.db = Database(self.db_path)
        self.version_mgr = VersionManager(self.db, backup_base_dir=self.backup_path)
        self.detector = ThreatDetector(self.db)
        self.integrity_checker = IntegrityChecker(self.db, self.version_mgr)

    def tearDown(self):
        self.test_dir.cleanup()

    # --- 1. Database Operations Tests ---
    def test_database_crud(self):
        # Monitored folder operations
        folder_id = self.db.add_monitored_folder(str(self.monitored_path), "Test Watch")
        self.assertIsNotNone(folder_id)
        
        folders = self.db.get_monitored_folders()
        self.assertEqual(len(folders), 1)
        self.assertEqual(folders[0]["label"], "Test Watch")

        # File upsert
        sample_file = self.monitored_path / "test.txt"
        sample_file.write_text("Hello SafeFS Database!", encoding="utf-8")
        hash_val = calculate_sha256(str(sample_file))

        file_id = self.db.upsert_file(
            folder_id=folder_id,
            path=str(sample_file),
            filename="test.txt",
            relative_path="test.txt",
            sha256=hash_val,
            size_bytes=sample_file.stat().st_size,
            last_modified=sample_file.stat().st_mtime,
            status="ACTIVE"
        )
        self.assertIsNotNone(file_id)

        file_rec = self.db.get_file_by_id(file_id)
        self.assertEqual(file_rec["filename"], "test.txt")
        self.assertEqual(file_rec["sha256"], hash_val)

        # Activity logging
        log_id = self.db.add_activity_log(
            event_type="CREATED",
            file_path=str(sample_file),
            filename="test.txt",
            folder_id=folder_id,
            new_hash=hash_val,
            severity="INFO",
            details="Test log entry"
        )
        self.assertIsNotNone(log_id)
        self.assertEqual(self.db.count_activity_logs(), 1)

    # --- 2. File Operations & SHA-256 Hashing Tests ---
    def test_file_ops_and_sha256(self):
        test_file = self.monitored_path / "integrity_test.txt"
        test_file.write_text("Standard OS I/O buffer test", encoding="utf-8")

        # Hash calculation
        computed_hash = calculate_sha256(str(test_file))
        self.assertIsNotNone(computed_hash)
        self.assertEqual(len(computed_hash), 64)  # SHA-256 hex length is 64

        # Non-existent file returns None
        self.assertIsNone(calculate_sha256(str(self.monitored_path / "nonexistent.bin")))

        # Metadata extraction
        meta = get_file_metadata(str(test_file))
        self.assertIsNotNone(meta)
        self.assertTrue(meta["is_file"])
        self.assertFalse(meta["is_dir"])
        self.assertGreater(meta["size_bytes"], 0)

        # Path traversal security test
        inside_path = str(self.monitored_path / "sub" / "file.txt")
        outside_path = str(self.base_path / ".." / "escape.txt")
        self.assertTrue(is_safe_path(inside_path, str(self.monitored_path)))
        self.assertFalse(is_safe_path(outside_path, str(self.monitored_path)))

    # --- 3. Version Creation and Restoration Tests ---
    def test_version_creation_and_safe_restoration(self):
        folder_id = self.db.add_monitored_folder(str(self.monitored_path), "Versioning Test")
        target_file = self.monitored_path / "document.txt"
        
        # State 1: Original File
        target_file.write_text("Version 1 Initial Content", encoding="utf-8")
        h1 = calculate_sha256(str(target_file))

        file_id = self.db.upsert_file(
            folder_id=folder_id,
            path=str(target_file),
            filename="document.txt",
            relative_path="document.txt",
            sha256=h1,
            size_bytes=target_file.stat().st_size,
            last_modified=target_file.stat().st_mtime,
            status="ACTIVE"
        )

        v1_id = self.version_mgr.create_version(file_id, str(target_file), change_type="INITIAL")
        self.assertIsNotNone(v1_id)

        # State 2: Modified File
        target_file.write_text("Version 2 Maliciously Corrupted Content!", encoding="utf-8")
        h2 = calculate_sha256(str(target_file))
        self.assertNotEqual(h1, h2)

        v2_id = self.version_mgr.create_version(file_id, str(target_file), change_type="MODIFIED")
        self.assertIsNotNone(v2_id)

        versions = self.db.get_file_versions(file_id)
        self.assertEqual(len(versions), 2)

        # Test Rollback to Version 1 with Zero-Data-Loss Invariant
        success, msg = self.version_mgr.restore_version(v1_id, reason="Unit test recovery")
        self.assertTrue(success)

        # Verify target file on disk matches Version 1 exactly
        restored_content = target_file.read_text(encoding="utf-8")
        self.assertEqual(restored_content, "Version 1 Initial Content")
        self.assertEqual(calculate_sha256(str(target_file)), h1)

        # Verify that a PRE_RESTORE safety snapshot was automatically created!
        updated_versions = self.db.get_file_versions(file_id)
        change_types = [v["change_type"] for v in updated_versions]
        self.assertIn("PRE_RESTORE", change_types)

        # Verify recovery audit trail was recorded
        history = self.db.get_recovery_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "SUCCESS")

    # --- 4. File Integrity Verification Tests ---
    def test_file_integrity_verification(self):
        folder_id = self.db.add_monitored_folder(str(self.monitored_path), "Integrity Test")
        file_path = self.monitored_path / "secure_data.txt"
        file_path.write_text("Untampered Payload", encoding="utf-8")

        h_orig = calculate_sha256(str(file_path))
        file_id = self.db.upsert_file(
            folder_id=folder_id,
            path=str(file_path),
            filename="secure_data.txt",
            relative_path="secure_data.txt",
            sha256=h_orig,
            size_bytes=file_path.stat().st_size,
            last_modified=file_path.stat().st_mtime,
            status="ACTIVE"
        )

        # Check 1: File is untouched -> VALID
        res1 = self.integrity_checker.verify_file(file_id)
        self.assertEqual(res1["status"], "VALID")

        # Check 2: Modify file content without updating baseline -> MODIFIED
        file_path.write_text("Tampered with unauthorized edits!", encoding="utf-8")
        res2 = self.integrity_checker.verify_file(file_id)
        self.assertEqual(res2["status"], "MODIFIED")
        self.assertNotEqual(res2["current_hash"], res2["expected_hash"])

        # Check 3: Delete file physically from disk -> MISSING
        os.remove(file_path)
        res3 = self.integrity_checker.verify_file(file_id)
        self.assertEqual(res3["status"], "MISSING")

    # --- 5. Suspicious Activity Detection Engine Tests ---
    def test_threat_detection_rules(self):
        # Rule 1: Ransomware extension detection
        malicious_path = str(self.monitored_path / "financial_records.docx.locked")
        alert_id = self.detector.check_suspicious_extension(malicious_path)
        self.assertIsNotNone(alert_id)

        alerts = self.db.get_security_alerts()
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["rule_name"], "RANSOMWARE_EXTENSION")

        # Rule 2: Double extension deception
        trojan_path = str(self.monitored_path / "invoice.pdf.exe")
        alert2_id = self.detector.check_suspicious_extension(trojan_path)
        self.assertIsNotNone(alert2_id)

        # Rule 3: Burst modification simulation (trigger > threshold)
        for i in range(8):
            dummy_file = str(self.monitored_path / f"batch_file_{i}.txt")
            self.detector.check_modification_burst(dummy_file)

        burst_alerts = [a for a in self.db.get_security_alerts() if a["rule_name"] == "BURST_MODIFICATION"]
        self.assertGreater(len(burst_alerts), 0)

        # Rule 4: Mass deletion burst
        for i in range(5):
            dummy_del = str(self.monitored_path / f"wiped_file_{i}.txt")
            self.detector.check_deletion_burst(dummy_del)

        del_alerts = [a for a in self.db.get_security_alerts() if a["rule_name"] == "MASS_DELETION"]
        self.assertGreater(len(del_alerts), 0)

    # --- 6. Live Event Handler Simulation ---
    def test_event_handler_simulation(self):
        folder_id = self.db.add_monitored_folder(str(self.monitored_path), "Event Test")
        from collections import deque
        event_queue = deque()
        handler = SafeFSEventHandler(self.db, self.version_mgr, self.detector, event_queue)

        test_file = self.monitored_path / "simulated.txt"
        test_file.write_text("Simulated Event Writing", encoding="utf-8")

        # Simulate on_created
        evt_created = FileCreatedEvent(str(test_file))
        handler.on_created(evt_created)

        file_rec = self.db.get_file_by_path(str(test_file))
        self.assertIsNotNone(file_rec)
        self.assertEqual(file_rec["status"], "ACTIVE")

        # Simulate on_modified
        test_file.write_text("Simulated Event Writing - Altered", encoding="utf-8")
        evt_modified = FileModifiedEvent(str(test_file))
        handler.on_modified(evt_modified)

        versions = self.db.get_file_versions(file_rec["id"])
        self.assertGreaterEqual(len(versions), 1)

        # Simulate on_deleted
        evt_deleted = FileDeletedEvent(str(test_file))
        handler.on_deleted(evt_deleted)

        updated_rec = self.db.get_file_by_path(str(test_file))
        self.assertEqual(updated_rec["status"], "DELETED")

if __name__ == "__main__":
    unittest.main()
