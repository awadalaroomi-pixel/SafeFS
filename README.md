# SafeFS – Intelligent File System Monitoring and Version Recovery System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-black.svg)](https://palletsprojects.com/p/flask/)
[![Engine](https://img.shields.io/badge/Monitoring-Watchdog%20IOCP%20%2F%20inotify-emerald.svg)](https://python-watchdog.readthedocs.io/)
[![Security](https://img.shields.io/badge/Integrity-SHA--256-critical.svg)](https://csrc.nist.gov/publications/detail/fips/180-4/final)
[![Tests](https://img.shields.io/badge/Tests-Passing-success.svg)](#8-testing--validation)

**SafeFS** is an advanced, production-grade Operating Systems capstone project that implements real-time local file system monitoring, heuristic Host Intrusion Detection (HIDS), cryptographic data integrity verification, and transactional version snapshots with safe atomic recovery.

SafeFS is built to demonstrate core **Operating Systems principles** through practical systems engineering: kernel I/O interrupts, Virtual File System (VFS) abstractions, Inode data structures, Copy-on-Write (CoW) journaling, thread concurrency, and process control block accounting.

---

## 1. Operating Systems Concepts Demonstrated

| Operating Systems Concept | Real-World OS Mechanism | SafeFS Implementation |
| :--- | :--- | :--- |
| **Virtual File System (VFS)** | OS file abstraction layer decoupling system calls from storage drivers | Uniform path normalization, traversal mitigation (`is_safe_path`), and decoupled file access |
| **Index Nodes (Inodes / FCB)** | Data structures containing file size, timestamps, permissions, and block pointers | SQLite `files` relational schema isolating file identity from disk content blocks |
| **Event-Driven Asynchronous I/O** | `inotify(7)` on Linux, `ReadDirectoryChangesW` / IOCP on Windows | Python `Watchdog` background daemon capturing non-blocking OS interrupts |
| **Copy-on-Write (CoW) & Journaling** | Point-in-time snapshots and transactional undo logs (ZFS, WAFL, ext4) | Immutable snapshot version store capturing file states before mutations or rollbacks |
| **Zero-Data-Loss Safety Invariant** | Atomic replacement and rollback safety | Mandatory `PRE_RESTORE` snapshot created before replacing any on-disk file during recovery |
| **Cryptographic Integrity** | Silent data corruption (bit-rot) and timestomping detection | 64 KB chunk-streamed SHA-256 block hashing comparing live disk bytes with stored baselines |
| **Concurrency & Synchronization** | Race conditions between file writes, watch interrupts, and DB updates | `threading.RLock()` mutexes, temporal write debouncing, and SQLite Write-Ahead Logging (WAL) |
| **Process Control Block (PCB)** | OS process accounting (PID, memory paging, CPU slices, threads) | Telemetry via `psutil` capturing resident memory (RSS), virtual memory (VMS), and CPU scheduling |

---

## 2. System Architecture

```
safefs/
├── app.py                     # Flask web server & REST API controller
├── config.py                  # Core system configuration, safety limits & detection rules
├── requirements.txt           # Python dependencies (flask, watchdog, psutil)
├── run.py                     # Primary launcher with automatic lab environment setup
├── README.md                  # Comprehensive academic documentation
├── core/
│   ├── __init__.py
│   ├── database.py            # SQLite schema (WAL mode, foreign keys, thread-safe context)
│   ├── file_ops.py            # Streaming SHA-256 hashing, path sanitizer & traversal guard
│   ├── monitor.py             # Watchdog event handler (debounce, multi-threaded observer)
│   ├── detector.py            # Rule-based threat engine (ransomware bursts, wiping, extensions)
│   ├── version_mgr.py         # Snapshot repository, diff engine & safe atomic restorations
│   ├── integrity.py           # Cryptographic baseline indexing & verification
│   └── system_info.py         # Host hardware & process PCB telemetry via psutil
├── templates/
│   ├── base.html              # Cyber DevSecOps dark shell (sidebar, topbar, modal containers)
│   ├── dashboard.html         # Main overview (live stat counters, Chart.js telemetry, activity stream)
│   ├── explorer.html          # Monitored file table, integrity badges, version viewer modal
│   ├── monitoring.html        # Live kernel event feed with filter chips & pause/resume controls
│   ├── versions.html          # Version repository, unified diff viewer, download & restore
│   ├── recovery.html          # Disaster recovery center with pre-restore safety guarantees
│   ├── threats.html           # HIDS alert console, severity breakdown & mitigation actions
│   ├── logs.html              # Activity audit logs with multi-column filtering, search & pagination
│   ├── system.html            # Per-core CPU load, RAM allocation, disk I/O, process PCB metrics
│   ├── settings.html          # Monitored directory management & detection threshold editor
│   └── os_concepts.html       # University Operating Systems academic deep-dive guide
├── static/
│   ├── css/
│   │   └── style.css          # Premium cybersecurity dark UI with glowing accents & responsive layout
│   └── js/
│       ├── main.js            # Global toast notifications, modal controllers & status updater
│       ├── dashboard.js       # Chart.js telemetry graphs & live statistics polling
│       ├── monitoring.js      # Live kernel event stream controller & filtering
│       └── explorer.js        # File tree navigation, SHA-256 verification & diff modals
├── tests/
│   ├── __init__.py
│   └── test_safefs.py         # Automated functional test suite (isolated temporary directories)
└── demo/
    └── generate_test_data.py  # Interactive evaluation CLI to simulate benign & malicious OS events
```

---

## 3. Core Features

### A. Professional Dashboard
- Real-time numerical stat counters: Monitored files, active directories, modified files, deleted files, active threats, and total backup snapshots.
- Interactive Chart.js visualizations: Event Type Distribution (Doughnut) and Threat Severity Matrix (Bar).
- Auto-updating recent activity feed polling every 4 seconds.

### B. Real-Time File System Monitoring
- Subscribes directly to kernel file system notifications (`inotify` on Linux / `ReadDirectoryChangesW` on Windows) via Watchdog.
- Detects `CREATED`, `MODIFIED`, `DELETED`, and `MOVED` (rename) events.
- Intelligent temporal debouncing (1.0s window) prevents multiple redundant notifications fired during single-file writes.

### C. File Version Control
- Preserves immutable file snapshots inside isolated, non-executable backup storage (`data/backups/`).
- Content deduplication: Avoids duplicate snapshots if file content SHA-256 is unchanged.
- Unified Text Differential Analysis: Built-in visual diff engine to compare previous versions against current live disk state.
- Downloadable previous snapshots and manual version deletion.

### D. Rule-Based Threat Detection (HIDS)
- **Rapid Modification Burst**: Detects $> 5$ distinct file modifications within 5 seconds (characteristic of crypto-ransomware file encryptors). Severity: **HIGH** / **CRITICAL**.
- **Mass Deletion Burst**: Detects $\ge 3$ rapid file purges within 5 seconds (data wiper behavior). Severity: **CRITICAL**.
- **Ransomware Extension Mutation**: Detects unauthorized extensions (`.locked`, `.crypto`, `.enc`, `.crypted`, `.locky`, `.wanacry`, `.ransom`, `.vault`). Severity: **CRITICAL**.
- **Double Extension Deception**: Detects executable masquerading (e.g. `invoice.pdf.exe`). Severity: **HIGH**.
- **Mass File Renaming**: Detects rapid batch renaming operations. Severity: **HIGH**.

### E. File Integrity Verification
- Streaming 64 KB block SHA-256 cryptographic hashing to verify integrity without exhausting RAM.
- Compares live file bytes with baseline database records to detect tampering, silent corruption, or unauthorized modifications.
- Single-file and folder-wide verification actions with visual status badges (`VALID`, `MODIFIED`, `MISSING`).

### F. Disaster Recovery Center
- **Zero-Data-Loss Invariant**: SafeFS will **never** overwrite an on-disk target file during rollback without first creating an automatic `PRE_RESTORE` safety snapshot of its current state.
- Interactive recovery wizard to locate files, compare timestamps, inspect hashes, and execute atomic rollbacks.
- Complete disaster recovery audit trail recording restored version hashes, pre-restore backup paths, and execution timestamps.

### G. Activity Logs & System Telemetry
- Activity audit trail with multi-column filtering by event type, severity level, and search keywords.
- Process Control Block (PCB) telemetry via `psutil`: PID, thread count, RSS/VMS memory, and CPU slices.
- Multi-core CPU scheduling graphs and host disk I/O metrics.

---

## 4. Safety & Security Guarantees

SafeFS operates under strict security boundaries:
1. **Explicit Folder Scope**: Operates **only** on directories explicitly added by the user. Root drives (`C:\`, `/`) and OS system directories (`C:\Windows`, `/etc`, `/sys`) are rejected by `validate_monitored_folder_candidate()`.
2. **Recursive Monitoring Protection**: The internal SafeFS application directory and backup store (`data/backups/`) are strictly blacklisted from monitoring to prevent infinite recursive event loops.
3. **Path Traversal Mitigation**: Every path supplied via HTTP requests or file operations is sanitized using `is_safe_path()` to ensure it cannot escape authorized directory roots.
4. **No Arbitrary File Execution**: SafeFS never executes monitored files. Backups are stored as passive data blobs.

---

## 5. Installation Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed.
- Windows (10/11/Server) or Linux (Ubuntu, Debian, Fedora, Arch).

### Setup

1. **Clone or Navigate to the SafeFS Directory**:
   ```bash
   cd C:\Users\awada\.gemini\antigravity\scratch\safefs
   ```

2. **Create a Python Virtual Environment (Recommended)**:
   - On Windows:
     ```powershell
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - On Linux / macOS:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 6. Execution Instructions

### Starting SafeFS

Run the launcher script:
```bash
python run.py
```

*Note: On first launch, SafeFS automatically initializes the SQLite database schema and creates a sample `demo_workspace` so the dashboard is immediately populated with live data.*

### Accessing the Web Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 7. Interactive Evaluation & Demonstration Guide

To demonstrate SafeFS to a university professor or evaluator without manual file tampering, an interactive simulation script is included:

```bash
python demo/generate_test_data.py
```

This presents an interactive CLI menu:
```
============================================================
 SafeFS - Interactive Operating Systems Demo Console
============================================================
1. Simulate Benign File Modification (Auto-versioning test)
2. Simulate Accidental File Deletion (Recovery test)
3. Simulate Ransomware Rapid Modification Burst (HIDS alert)
4. Simulate Ransomware Extension (.locked) Mutation
5. Simulate Trojan Double Extension (invoice.pdf.exe)
6. Simulate Mass File Renaming Burst
7. Reset Demo Environment
8. Exit
============================================================
```

### Demonstration Steps:
1. **Scenario 1 (Automatic Versioning)**: Select `1`. In the SafeFS web browser, watch the Live Monitoring stream capture the event, and check the File Explorer to see Version #2 created with a unified diff available.
2. **Scenario 2 (Ransomware Burst Detection)**: Select `3`. Immediately look at the SafeFS Dashboard and Threat Detection page. A **CRITICAL / HIGH** alert is triggered with clear explanation and affected file list.
3. **Scenario 3 (Ransomware Extension)**: Select `4`. The HIDS rule engine flags the `.locked` extension instantly as a Critical incident.
4. **Scenario 4 (Disaster Recovery)**: Open the **Recovery Center** (`/recovery`), select any file, and restore an older version. Observe that the current version was safely snapshotted before the restore completed.

---

## 8. Testing & Validation

SafeFS includes an automated test suite executed in isolated temporary directories (`tempfile.TemporaryDirectory`) to guarantee test isolation without touching personal files:

```bash
python -m unittest discover -s tests
```

### Test Coverage:
- `test_database_crud`: Database schema initialization, monitored folders, file upserts, and activity logs.
- `test_file_ops_and_sha256`: Streaming SHA-256 calculation, metadata extraction, and path traversal guards.
- `test_version_creation_and_safe_restoration`: Snapshot creation, deduplication, atomic rollback, and pre-restore safety snapshot invariant verification.
- `test_file_integrity_verification`: `VALID`, `MODIFIED` (tampered), and `MISSING` integrity states.
- `test_threat_detection_rules`: Ransomware extension detection, double-extension deception, and temporal modification/deletion bursts.
- `test_event_handler_simulation`: End-to-end Watchdog event callback processing.

---

## 9. Technology Stack Summary

- **Programming Language**: Python 3
- **Web Backend**: Flask 3.1
- **Real-Time Monitoring**: Watchdog 7.1 (`ReadDirectoryChangesW` / `inotify`)
- **System Telemetry**: Psutil 7.2
- **Cryptographic Verification**: Hashlib SHA-256 (64 KB streaming buffers)
- **Database Engine**: SQLite 3 (WAL journal mode, foreign keys, thread-safe locking)
- **Frontend Architecture**: HTML5, Modern CSS3 Cyberpunk/DevSecOps dark theme, JavaScript (ES6+), Chart.js
- **Compatible Operating Systems**: Windows 10/11/Server, Linux (Ubuntu, Debian, Fedora, Arch)
