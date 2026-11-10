"""
SafeFS - Interactive Academic Demonstration Script
Simulates real-world Operating System file operations, benign updates,
and malicious malware activity (ransomware encryption bursts, mass deletion,
suspicious extensions) to demonstrate SafeFS during university evaluation.
"""

import os
import sys
import time
import shutil
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.database import Database
from core.integrity import IntegrityChecker
from core.version_mgr import VersionManager

DEMO_DIR = BASE_DIR / "demo_workspace"

def setup_demo_environment():
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    db = Database()
    version_mgr = VersionManager(db)
    integrity = IntegrityChecker(db, version_mgr)

    # Check if demo folder is already registered
    folders = db.get_monitored_folders()
    demo_str = str(DEMO_DIR.resolve())
    folder_id = None
    for f in folders:
        if os.path.normpath(f["path"]) == os.path.normpath(demo_str):
            folder_id = f["id"]
            break

    if not folder_id:
        folder_id = db.add_monitored_folder(demo_str, "Demo Laboratory Workspace")
        print(f"[*] Registered demo directory with SafeFS [Folder ID: {folder_id}]")

    # Generate initial benchmark files if empty
    initial_files = {
        "operating_systems_thesis.docx": "SafeFS Thesis Chapter 1: Introduction to Virtual File Systems and Inode architecture.\nOriginal Author: SafeFS Engineering Team.\nBaseline Status: Clean.",
        "kernel_module.c": "#include <linux/module.h>\n#include <linux/init.h>\n\nMODULE_LICENSE(\"GPL\");\nMODULE_AUTHOR(\"SafeFS\");\n\nstatic int __init safefs_init(void) {\n    pr_info(\"SafeFS Kernel Hook Loaded\\n\");\n    return 0;\n}\nmodule_init(safefs_init);",
        "financial_ledger.csv": "TransactionID,Date,Amount,Description\n101,2026-11-01,1500.00,Server Hosting\n102,2026-11-02,320.50,Hardware Storage\n103,2026-11-05,4800.00,Security Audit",
        "research_notes.txt": "Notes on inotify vs ReadDirectoryChangesW:\n- inotify uses non-blocking kernel event descriptors.\n- Win32 uses completion routines and asynchronous IOCP."
    }

    for fname, content in initial_files.items():
        fpath = DEMO_DIR / fname
        if not fpath.exists():
            fpath.write_text(content, encoding="utf-8")

    # Index folder
    integrity.scan_and_index_folder(folder_id)
    print(f"[+] Demo environment initialized at: {DEMO_DIR}")
    return folder_id

def simulate_benign_edit():
    target = DEMO_DIR / "operating_systems_thesis.docx"
    print(f"[*] Simulating user modification on '{target.name}'...")
    with open(target, "a", encoding="utf-8") as f:
        f.write(f"\n[Updated at {time.strftime('%H:%M:%S')}]: Added Chapter 2 - Concurrency & Lock-Free Data Structures.")
    print("[+] Modification written to disk. SafeFS Watchdog will capture and version this change.")

def simulate_file_deletion():
    target = DEMO_DIR / "financial_ledger.csv"
    if target.exists():
        print(f"[*] Simulating accidental/unauthorized deletion of '{target.name}'...")
        os.remove(target)
        print("[+] File deleted from physical disk. SafeFS marked status DELETED with recovery points intact.")
    else:
        print(f"[-] '{target.name}' is already deleted. Use Recovery Center to restore it first!")

def simulate_ransomware_burst():
    print("[!] SIMULATING RANSOMWARE RAPID MODIFICATION BURST...")
    print("[!] Modifying 8 distinct files within 1 second...")
    for i in range(1, 9):
        fpath = DEMO_DIR / f"work_file_{i}.txt"
        fpath.write_text(f"Encrypted payload simulation #{i} - {time.time()}", encoding="utf-8")
        time.sleep(0.08)
    print("[+] Rapid burst written. SafeFS Rule 'BURST_MODIFICATION' triggered with HIGH/CRITICAL alert!")

def simulate_ransomware_extension():
    print("[!] SIMULATING RANSOMWARE EXTENSION MUTATION (.locked)...")
    target = DEMO_DIR / "confidential_research.pdf.locked"
    target.write_text("YOUR FILES ARE ENCRYPTED. SIMULATED RANSOMWARE DEMO.", encoding="utf-8")
    print(f"[+] Created '{target.name}'. SafeFS Rule 'RANSOMWARE_EXTENSION' triggered with CRITICAL alert!")

def simulate_double_extension():
    print("[!] SIMULATING DOUBLE EXTENSION TROJAN MASQUERADE...")
    target = DEMO_DIR / "urgent_invoice_nov2026.pdf.exe"
    target.write_text("Simulated binary payload masquerading as PDF", encoding="utf-8")
    print(f"[+] Created '{target.name}'. SafeFS Rule 'DOUBLE_EXTENSION_DECEPTION' triggered with HIGH alert!")

def simulate_mass_rename():
    print("[!] SIMULATING RAPID MASS FILE RENAMING...")
    for i in range(1, 6):
        orig = DEMO_DIR / f"report_{i}.dat"
        orig.write_text(f"Report data #{i}", encoding="utf-8")
        time.sleep(0.05)
        new_path = DEMO_DIR / f"report_{i}.dat.renamed"
        if new_path.exists():
            os.remove(new_path)
        os.rename(orig, new_path)
    print("[+] Mass rename executed. SafeFS Rule 'MASS_RENAMING' triggered with HIGH alert!")

def clean_demo():
    print("[*] Resetting demo workspace...")
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)
    setup_demo_environment()
    print("[+] Reset complete.")

def main():
    folder_id = setup_demo_environment()
    while True:
        print("\n" + "="*60)
        print(" SafeFS - Interactive Operating Systems Demo Console")
        print("="*60)
        print("1. Simulate Benign File Modification (Auto-versioning test)")
        print("2. Simulate Accidental File Deletion (Recovery test)")
        print("3. Simulate Ransomware Rapid Modification Burst (HIDS alert)")
        print("4. Simulate Ransomware Extension (.locked) Mutation")
        print("5. Simulate Trojan Double Extension (invoice.pdf.exe)")
        print("6. Simulate Mass File Renaming Burst")
        print("7. Reset Demo Environment")
        print("8. Exit")
        print("="*60)
        choice = input("Select demonstration scenario (1-8): ").strip()

        if choice == "1":
            simulate_benign_edit()
        elif choice == "2":
            simulate_file_deletion()
        elif choice == "3":
            simulate_ransomware_burst()
        elif choice == "4":
            simulate_ransomware_extension()
        elif choice == "5":
            simulate_double_extension()
        elif choice == "6":
            simulate_mass_rename()
        elif choice == "7":
            clean_demo()
        elif choice == "8":
            print("[*] Exiting demo console.")
            break
        else:
            print("[-] Invalid choice. Please select 1-8.")

if __name__ == "__main__":
    main()
