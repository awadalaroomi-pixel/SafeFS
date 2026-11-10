# SafeFS: Intelligent File System Monitoring and Version Recovery System
## Comprehensive Academic Technical Report & Systems Architecture Document

**Course:** Operating Systems / Advanced Systems Programming  
**System Name:** SafeFS (Safe File System Monitor & Recovery)  
**Author:** Awad Ali (awadalaroomi@gmail.com)  
**Technology Stack:** Python 3, Flask, SQLite (WAL Mode), Watchdog, Psutil, SHA-256 Cryptographic Engine, HTML5/CSS3/JavaScript (Chart.js)  
**Environment:** Cross-Platform (Microsoft Windows 10/11 & Linux Kernel 5.x/6.x)

---

## 1. Executive Summary & Abstract

Traditional file management utilities provide static directory listings and manual file manipulation without visibility into real-time kernel I/O operations, modification histories, or malicious behavioral patterns. In enterprise and academic computing environments, modern cybersecurity threats—particularly crypto-ransomware and data wipers—exploit this lack of real-time visibility to rapidly overwrite or encrypt file system trees within seconds.

**SafeFS** is an intelligent, event-driven local file management, monitoring, and version recovery system. Designed as an academic Operating Systems capstone project, SafeFS bridges core theoretical OS principles with practical systems programming:
1. **Event-Driven Kernel I/O:** Hooks directly into OS file system notifications (`ReadDirectoryChangesW` / I/O Completion Ports on Windows, `inotify` on Linux) to capture non-blocking file events without CPU-intensive polling.
2. **Virtual Inode Table:** Simulates an OS Inode / File Control Block (FCB) data structure in a relational schema, decoupling file identifiers and directory paths from disk block contents and cryptographic checksums.
3. **Copy-on-Write (CoW) Snapshots:** Automatically archives point-in-time immutable versions before modifications are committed, with content deduplication.
4. **Zero-Data-Loss Safety Invariant:** Enforces transactional integrity during file recovery; an automatic `PRE_RESTORE` snapshot of the target on-disk file is guaranteed before any overwrite operation can proceed.
5. **Cryptographic Block Hashing:** Streamed 64 KB block SHA-256 verification detects unauthorized tampering, bit-rot, and malware timestomping.
6. **Host Intrusion Detection (HIDS):** A deterministic, rule-based threat engine analyzes temporal event bursts and extension mutations to identify ransomware encryption phases, mass deletion wiping, and executable masquerading.

---

## 2. Operating Systems Concepts & Theoretical Mapping

### 2.1 Virtual File System (VFS) & Inode Abstraction
* **Theory:** Modern operating systems abstract diverse physical storage formats (NTFS, ext4, FAT32) beneath a unified Virtual File System (VFS). Within the VFS, an Inode (UNIX) or File Control Block (Windows MFT entry) uniquely identifies a file, storing metadata (size, permissions, timestamps, block pointers) separately from directory name entries.
* **SafeFS Implementation:** SafeFS canonicalizes all incoming file paths (`os.path.normpath`, `Path.resolve()`) and decouples path references from stored content state. In `core/database.py`, the `files` table serves as the system's Inode table:
  ```sql
  CREATE TABLE files (
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
  );
  ```

### 2.2 Event-Driven Asynchronous I/O vs. Polling
* **Theory:** Periodic directory scanning ($O(N)$ tree traversal) introduces disk thrashing, high CPU cycles, and race windows where transient modifications are missed. Modern kernels offer interrupt-driven event queues where the file system driver notifies subscribed user-space processes when an I/O request packet (IRP) completes.
* **SafeFS Implementation:** Using Python's `Watchdog` library (`core/monitor.py`), SafeFS subscribes to kernel-level file system hooks:
  - **Windows:** Leverages `ReadDirectoryChangesW` with I/O Completion Ports (IOCP) to asynchronously buffer directory changes.
  - **Linux:** Leverages `inotify_init(2)` and `inotify_add_watch(2)` to receive kernel events via file descriptors.
  - **Debouncing:** Rapid successive write calls from editors (which often emit 2 to 4 raw OS write events for a single save operation) are passed through an adaptive temporal debounce filter (`_should_debounce()`), preventing redundant versioning.

### 2.3 Copy-on-Write (CoW) Journaling & Transactional Restoration
* **Theory:** Advanced file systems (ZFS, Btrfs, WAFL) avoid in-place data overwrites. When a block is modified, the new data is written to a fresh block, and metadata pointers are atomically updated. This preserves previous versions and guarantees crash consistency.
* **SafeFS Implementation:** When a monitored file is modified, `core/version_mgr.py` intercepts the event, computes the new SHA-256 hash, and compares it against the prior snapshot. If altered, the live file is preserved in dedicated, isolated backup storage (`data/backups/folder_{id}/...`).
* **The Zero-Data-Loss Invariant:**
  $$\text{Target File Exists} \implies \text{Snapshot}(\text{Current State}, \text{'PRE\_RESTORE'}) \to \text{Atomic Copy}(\text{Backup}, \text{Target})$$
  SafeFS will **never** overwrite an on-disk target file during restoration without first taking an automated safety snapshot of the target's existing bytes.

### 2.4 Cryptographic Block Integrity vs. Metadata Timestamps
* **Theory:** Standard operating system metadata attributes such as `st_mtime` (last modified time) can be altered trivially by user-space applications (e.g. `touch -d` or the Win32 `SetFileTime` API), a tactic frequently employed by malware known as *timestomping*. Furthermore, silent storage decay (*bit-rot*) alters data blocks without updating inode timestamps.
* **SafeFS Implementation:** `core/file_ops.py` implements streaming 64 KB block SHA-256 hashing (`calculate_sha256()`). Reading files in 65,536-byte chunks allows verification of multi-gigabyte files with constant $O(1)$ memory consumption. Any mismatch between disk state and recorded database baselines immediately raises an integrity alarm (`MODIFIED` or `INTEGRITY_DRIFT`).

### 2.5 Concurrency, Race Conditions & Mutex Synchronization
* **Theory:** Concurrent execution across multiple threads (Watchdog observer thread, Flask request worker threads, background integrity scanners) accessing shared database and storage state introduces critical section hazards.
* **SafeFS Implementation:**
  - **Re-entrant Mutex Locks:** State mutations are guarded by Python's `threading.RLock()`.
  - **SQLite Write-Ahead Logging (WAL):** Concurrency is maximized by enabling `PRAGMA journal_mode=WAL;`. Readers do not block writers, and writers do not block readers, providing ACID guarantees under high event velocity.

### 2.6 Process Control Block (PCB) Accounting & Resource Telemetry
* **Theory:** The operating system kernel tracks process execution state through Process Control Blocks (PCBs), logging memory paging (Resident Set Size vs. Virtual Memory Size), scheduling priorities, CPU user/system times, and thread descriptors.
* **SafeFS Implementation:** `core/system_info.py` queries live host metrics and SafeFS process statistics via `psutil`:
  - Process PID, RSS (Resident Memory), VMS (Virtual Memory), and active OS thread handles.
  - Per-core CPU utilization percentages, system boot time, and total system uptime.
  - Physical host storage utilization and real-time disk read/write byte throughput.

---

## 3. Heuristic Threat Detection Engine (HIDS)

SafeFS incorporates a deterministic, rule-based Host Intrusion Detection System (`core/detector.py`). It analyzes sliding temporal event windows ($\Delta t$) and file naming mutations to detect unauthorized actions:

| Rule Identifier | Trigger Heuristic | Severity | OS Security Context |
| :--- | :--- | :--- | :--- |
| **`BURST_MODIFICATION`** | $\ge 5$ distinct files modified within $\le 5.0$ seconds | **HIGH** / **CRITICAL** | Automated cryptographic encryption phase of ransomware or unauthorized batch scripting. |
| **`MASS_DELETION`** | $\ge 3$ files deleted within $\le 5.0$ seconds | **CRITICAL** | Data wiper malware activity or destructive directory purging commands (`rm -rf` / `rmdir /s`). |
| **`RANSOMWARE_EXTENSION`** | File created or renamed to match known ransomware suffixes (`.locked`, `.crypto`, `.enc`, `.crypted`, `.locky`, `.wanacry`, `.ransom`, `.vault`, `.onion`, `.dark`, etc.) | **CRITICAL** | Signature of ransomware appending extensions to encrypted files. |
| **`DOUBLE_EXTENSION`** | File masquerades as document while possessing executable extension (e.g. `invoice.pdf.exe`, `report.docx.scr`) | **HIGH** | Social engineering trojan delivery exploiting default OS hide-known-extensions behavior. |
| **`MASS_RENAMING`** | $\ge 4$ file renaming operations within $\le 5.0$ seconds | **HIGH** | Batch file obfuscation or ransomware staging. |

---

## 4. System Verification & Test Matrix

All tests run in isolated temporary directory environments (`tempfile.TemporaryDirectory`) to ensure zero impact on user files:

```bash
python tests/test_safefs.py
```

### Automated Test Results:
```text
test_database_crud (__main__.TestSafeFS) ... ok
test_event_handler_simulation (__main__.TestSafeFS) ... ok
test_file_integrity_verification (__main__.TestSafeFS) ... ok
test_file_ops_and_sha256 (__main__.TestSafeFS) ... ok
test_threat_detection_rules (__main__.TestSafeFS) ... ok
test_version_creation_and_safe_restoration (__main__.TestSafeFS) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.504s

OK
```

### HTTP REST API Verification Matrix:
All 13 endpoints and template views were verified under automated synthetic test client requests:
- `GET /` &rarr; `200 OK` (Dashboard)
- `GET /explorer` &rarr; `200 OK` (File Inode Explorer)
- `GET /monitoring` &rarr; `200 OK` (Live Event Stream)
- `GET /versions` &rarr; `200 OK` (Version Snapshot History)
- `GET /recovery` &rarr; `200 OK` (Disaster Recovery Center)
- `GET /threats` &rarr; `200 OK` (HIDS Threat Console)
- `GET /logs` &rarr; `200 OK` (Activity Audit Logs)
- `GET /system` &rarr; `200 OK` (System Hardware & PCB Telemetry)
- `GET /settings` &rarr; `200 OK` (Settings & Directory Registry)
- `GET /os-concepts` &rarr; `200 OK` (OS Theory Deep-Dive)
- `GET /api/stats` &rarr; `200 OK` (JSON Summary)
- `GET /api/system/stats` &rarr; `200 OK` (JSON Hardware Telemetry)
- `GET /api/threats` &rarr; `200 OK` (JSON Security Alerts)

---

## 5. Security & Safety Model

1. **Explicit Whitelisting:** SafeFS only operates on folders explicitly registered by the user. System root drives (`C:\`, `/`) and critical operating system directories (`C:\Windows`, `/etc`, `/sys`, `/bin`) are strictly rejected.
2. **Infinite Recursion Guard:** The SafeFS application directory and internal backup repository (`data/backups/`) are hardcoded into an immutable blacklist, preventing infinite event loops.
3. **Path Traversal Guard:** All API operations validate file paths against their parent monitored roots using canonical resolution (`os.path.commonpath`), neutralizing `../` directory traversal attacks.
4. **Passive Storage:** Backup versions are stored as non-executable data objects. SafeFS never executes monitored or restored files.

---

## 6. Conclusion

SafeFS successfully implements a functional, robust, and visually impressive Operating Systems project. By integrating kernel-level event listening, cryptographic hashing, Copy-on-Write versioning, and real-time heuristic security, it demonstrates the practical application of foundational Operating Systems theory in modern software development and cybersecurity.
