import time
import os
from collections import deque
from pathlib import Path
import threading
from typing import Dict, Any, List, Optional
import config
from core.database import Database

class ThreatDetector:
    """
    Deterministic Rule-Based Threat Detection Engine.
    Emulates Host-based Intrusion Detection Systems (HIDS) and OS kernel audit heuristics
    to identify ransomware signatures, mass wiping, and anomalous file system mutations.
    """
    def __init__(self, db: Database):
        self.db = db
        self.lock = threading.Lock()
        
        # Sliding event windows for temporal heuristic analysis
        self._mod_events = deque()       # (timestamp, filepath)
        self._del_events = deque()       # (timestamp, filepath)
        self._rename_events = deque()    # (timestamp, src_path, dest_path)
        
        # Track last alert timestamps to prevent duplicate alert storms
        self._recent_alerts: Dict[str, float] = {}

    def _get_thresholds(self) -> Dict[str, float]:
        """Fetch active thresholds from database with config defaults."""
        settings = self.db.get_settings()
        return {
            "burst_mod_count": int(settings.get("burst_modification_count", config.BURST_MODIFICATION_COUNT)),
            "burst_mod_window": float(settings.get("burst_window_seconds", config.BURST_WINDOW_SECONDS)),
            "burst_del_count": int(settings.get("burst_deletion_count", config.BURST_DELETION_COUNT)),
            "burst_del_window": float(settings.get("burst_deletion_window", config.BURST_DELETION_WINDOW)),
            "mass_rename_count": int(settings.get("mass_rename_count", config.MASS_RENAME_COUNT)),
            "mass_rename_window": float(settings.get("mass_rename_window", config.MASS_RENAME_WINDOW)),
        }

    def _is_alert_suppressed(self, alert_key: str, cooldown_seconds: float = 8.0) -> bool:
        """Rate limit alerts of the exact same category to prevent alert fatigue."""
        now = time.time()
        last_time = self._recent_alerts.get(alert_key, 0.0)
        if now - last_time < cooldown_seconds:
            return True
        self._recent_alerts[alert_key] = now
        return False

    def check_suspicious_extension(self, filepath: str) -> Optional[int]:
        """
        Rule: Identifies if a file was renamed or created with known ransomware extensions.
        Severity: CRITICAL
        """
        path_obj = Path(filepath)
        filename = path_obj.name.lower()
        suffix = path_obj.suffix.lower()

        # Check known ransomware extensions
        for suspicious_ext in config.SUSPICIOUS_EXTENSIONS:
            if filename.endswith(suspicious_ext.lower()):
                alert_key = f"suspicious_ext_{filepath}"
                if self._is_alert_suppressed(alert_key):
                    return None
                    
                title = "Critical Ransomware Extension Mutation Detected"
                description = (
                    f"File '{path_obj.name}' was created or modified with high-risk ransomware extension '{suspicious_ext}'. "
                    f"This pattern strongly resembles crypto-ransomware file encryption. Immediate inspection or rollback is advised."
                )
                return self.db.add_security_alert(
                    rule_name="RANSOMWARE_EXTENSION",
                    severity="CRITICAL",
                    title=title,
                    description=description,
                    affected_files=[filepath]
                )

        # Check deceptive double extensions (e.g. document.pdf.exe or report.docx.scr)
        parts = filename.split(".")
        if len(parts) >= 3:
            exec_extensions = {".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".hta"}
            doc_extensions = {"pdf", "docx", "xlsx", "pptx", "jpg", "png", "txt", "zip"}
            if ("." + parts[-1]) in exec_extensions and parts[-2] in doc_extensions:
                alert_key = f"double_ext_{filepath}"
                if self._is_alert_suppressed(alert_key):
                    return None
                title = "Suspicious Executable Masked with Double Extension"
                description = (
                    f"File '{path_obj.name}' appears to masquerade as a legitimate document ('{parts[-2]}') "
                    f"while possessing an executable extension ('.{parts[-1]}'). Characteristic of trojan delivery."
                )
                return self.db.add_security_alert(
                    rule_name="DOUBLE_EXTENSION_DECEPTION",
                    severity="HIGH",
                    title=title,
                    description=description,
                    affected_files=[filepath]
                )

        return None

    def check_modification_burst(self, filepath: str) -> Optional[int]:
        """
        Rule: Detects rapid high-frequency modifications across multiple distinct files.
        Severity: HIGH (or CRITICAL if count is 2x threshold)
        """
        with self.lock:
            now = time.time()
            thresholds = self._get_thresholds()
            cutoff = now - thresholds["burst_mod_window"]

            # Evict events outside rolling time window
            while self._mod_events and self._mod_events[0][0] < cutoff:
                self._mod_events.popleft()

            self._mod_events.append((now, filepath))

            # Count distinct files altered in the window
            distinct_files = list({f for t, f in self._mod_events})
            count = len(distinct_files)

            if count >= thresholds["burst_mod_count"]:
                alert_key = "modification_burst"
                if self._is_alert_suppressed(alert_key, cooldown_seconds=6.0):
                    return None

                severity = "CRITICAL" if count >= thresholds["burst_mod_count"] * 2 else "HIGH"
                title = f"Rapid Modification Burst Detected ({count} files in {thresholds['burst_mod_window']}s)"
                description = (
                    f"Detected {count} distinct files modified within a rapid {thresholds['burst_mod_window']} second window. "
                    f"High-velocity file rewriting is a primary behavioral indicator of automated file encryptors (ransomware), "
                    f"data exfiltration preparation, or uncontrolled batch scripts."
                )
                return self.db.add_security_alert(
                    rule_name="BURST_MODIFICATION",
                    severity=severity,
                    title=title,
                    description=description,
                    affected_files=distinct_files[:10]  # Store first 10 for sample inspection
                )
        return None

    def check_deletion_burst(self, filepath: str) -> Optional[int]:
        """
        Rule: Detects rapid mass deletion of files within a short temporal window.
        Severity: CRITICAL
        """
        with self.lock:
            now = time.time()
            thresholds = self._get_thresholds()
            cutoff = now - thresholds["burst_del_window"]

            while self._del_events and self._del_events[0][0] < cutoff:
                self._del_events.popleft()

            self._del_events.append((now, filepath))

            distinct_files = list({f for t, f in self._del_events})
            count = len(distinct_files)

            if count >= thresholds["burst_del_count"]:
                alert_key = "deletion_burst"
                if self._is_alert_suppressed(alert_key, cooldown_seconds=6.0):
                    return None

                title = f"Mass File Deletion Burst Detected ({count} files in {thresholds['burst_del_window']}s)"
                description = (
                    f"Detected {count} files deleted in rapid succession within {thresholds['burst_del_window']} seconds. "
                    f"This rapid purging pattern is characteristic of wiper malware, malicious file destruction, "
                    f"or catastrophic directory pruning scripts."
                )
                return self.db.add_security_alert(
                    rule_name="MASS_DELETION",
                    severity="CRITICAL",
                    title=title,
                    description=description,
                    affected_files=distinct_files[:10]
                )
        return None

    def check_rename_burst(self, src_path: str, dest_path: str) -> Optional[int]:
        """
        Rule: Detects mass renaming operations across multiple files.
        Severity: HIGH
        """
        with self.lock:
            now = time.time()
            thresholds = self._get_thresholds()
            cutoff = now - thresholds["mass_rename_window"]

            while self._rename_events and self._rename_events[0][0] < cutoff:
                self._rename_events.popleft()

            self._rename_events.append((now, src_path, dest_path))
            count = len(self._rename_events)

            if count >= thresholds["mass_rename_count"]:
                alert_key = "rename_burst"
                if self._is_alert_suppressed(alert_key, cooldown_seconds=6.0):
                    return None

                renamed_sample = [f"{Path(s).name} -> {Path(d).name}" for t, s, d in list(self._rename_events)[:5]]
                title = f"Mass File Renaming Burst ({count} operations in {thresholds['mass_rename_window']}s)"
                description = (
                    f"Detected {count} file renaming operations within {thresholds['mass_rename_window']} seconds. "
                    f"Mass renaming is frequently used by ransomware to append arbitrary extensions or obfuscate directory trees."
                )
                return self.db.add_security_alert(
                    rule_name="MASS_RENAMING",
                    severity="HIGH",
                    title=title,
                    description=description,
                    affected_files=renamed_sample
                )
        return None

    def process_event(self, event_type: str, filepath: str, src_path: Optional[str] = None):
        """
        Dispatches incoming file system events through all heuristic detection rules.
        """
        # Always check for suspicious extensions on file changes and creations
        self.check_suspicious_extension(filepath)

        if event_type == "MODIFIED":
            self.check_modification_burst(filepath)
        elif event_type == "DELETED":
            self.check_deletion_burst(filepath)
        elif event_type == "MOVED":
            if src_path:
                self.check_suspicious_extension(filepath)
                self.check_rename_burst(src_path, filepath)
