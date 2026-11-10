import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "safefs.db"
BACKUP_DIR = DATA_DIR / "backups"

# Ensure essential data directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# Detection Engine Thresholds (Rule-Based)
BURST_MODIFICATION_COUNT = 5       # Max modifications permitted in BURST_WINDOW_SECONDS before trigger
BURST_WINDOW_SECONDS = 5.0          # Time window in seconds for burst detection
BURST_DELETION_COUNT = 3           # Max deletions permitted in BURST_DELETION_WINDOW_SECONDS
BURST_DELETION_WINDOW = 5.0        # Time window for deletion burst
MASS_RENAME_COUNT = 4              # Max renames in MASS_RENAME_WINDOW
MASS_RENAME_WINDOW = 5.0           # Time window for rename burst

# Known ransomware extensions
SUSPICIOUS_EXTENSIONS = [
    ".locked", ".crypto", ".enc", ".crypted", ".locky", ".wanacry", 
    ".ransom", ".vault", ".onion", ".dark", ".aes", ".kraken", 
    ".zepto", ".cerber", ".wcry"
]

# File Management & Safety Limits
MAX_VERSIONS_PER_FILE = 20         # Maximum number of backups kept per file
MAX_FILE_SIZE_MB = 100             # Maximum file size hashed/versioned to prevent OOM
DEBOUNCE_SECONDS = 1.0             # Debounce window for rapid successive write events on same file

# Paths prohibited from monitoring to ensure OS safety and prevent infinite recursive monitoring loops
SYSTEM_BLACKLIST_DIRECTORIES = [
    str(DATA_DIR.resolve()).lower(),
    str(BACKUP_DIR.resolve()).lower(),
    str(BASE_DIR.resolve()).lower(),
]

# Web Server Settings
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = False
