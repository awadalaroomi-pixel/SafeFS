"""
SafeFS - Intelligent File System Monitoring & Version Recovery System
Main Execution Launcher
"""

import sys
import os
from pathlib import Path

# Ensure project directory is in python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import config
from app import app, db, integrity_checker, monitor_mgr

def initialize_quickstart_workspace():
    """
    Creates an initial safe demo directory if no monitored folders exist,
    allowing instant out-of-the-box demonstration of SafeFS.
    """
    existing_folders = db.get_monitored_folders()
    if not existing_folders:
        demo_dir = BASE_DIR / "demo_workspace"
        demo_dir.mkdir(parents=True, exist_ok=True)
        
        # Populate initial files
        f1 = demo_dir / "sample_project_report.docx"
        if not f1.exists():
            f1.write_text("Operating Systems SafeFS Research Document.\nVersion 1.0 baseline content.", encoding="utf-8")
        
        f2 = demo_dir / "system_architecture.c"
        if not f2.exists():
            f2.write_text("// SafeFS Kernel Hook Module\nint init_module(void) { return 0; }\n", encoding="utf-8")

        folder_id = db.add_monitored_folder(str(demo_dir.resolve()), "Default Lab Workspace")
        monitor_mgr.add_folder(folder_id, str(demo_dir.resolve()))
        integrity_checker.scan_and_index_folder(folder_id)
        print(f"[+] Initialized default monitored laboratory folder at: {demo_dir.resolve()}")

def main():
    print(r"""
===================================================================
  ____             __      _____ ____  
 / ___|  __ _ / _| ___|  ___/ ___| 
 \___ \ / _` | |_ / _ \ |_  \___ \ 
  ___) | (_| |  _|  __/  _|  ___) |
 |____/ \__,_|_|  \___|_|   |____/  
   SafeFS - Intelligent File System Monitoring & Recovery System
===================================================================
    """)
    print("[*] Initializing SafeFS SQLite Database and Storage Engine...")
    initialize_quickstart_workspace()

    print(f"[*] Real-Time File System Observer: ACTIVE (Watchdog)")
    print(f"[*] Host Telemetry Engine: ACTIVE (Psutil)")
    print(f"[*] Rule-Based Threat Detection: ACTIVE (HIDS Heuristics)")
    print(f"[*] Web Server Running at: http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print("[*] Press CTRL+C to terminate.")
    print("=" * 67 + "\n")

    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=False)

if __name__ == "__main__":
    main()
