import hashlib
import os
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import config

def calculate_sha256(filepath: str, block_size: int = 65536) -> Optional[str]:
    """
    Calculate the SHA-256 cryptographic hash of a file using streaming chunks.
    Demonstrates OS file I/O streaming to handle large files safely without high memory usage.
    """
    if not os.path.isfile(filepath):
        return None
    
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(block_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None

def is_safe_path(target_path: str, base_directory: str) -> bool:
    """
    Validates that target_path resides strictly inside base_directory.
    Prevents directory traversal attacks (e.g., ../../etc/passwd or Windows equivalent).
    """
    try:
        target_resolved = Path(target_path).resolve()
        base_resolved = Path(base_directory).resolve()
        return base_resolved == target_resolved or base_resolved in target_resolved.parents
    except Exception:
        return False

def get_file_metadata(filepath: str) -> Optional[Dict[str, Any]]:
    """
    Extracts OS-level file attributes and metadata (size, timestamps, permissions).
    Directly reflects OS Inode/File Control Block (FCB) data structures.
    """
    try:
        stat_result = os.stat(filepath)
        size_bytes = stat_result.st_size
        mtime = stat_result.st_mtime
        ctime = stat_result.st_ctime
        mode = oct(stat_result.st_mode)[-3:]
        
        return {
            "size_bytes": size_bytes,
            "mtime": mtime,
            "ctime": ctime,
            "mode": mode,
            "is_dir": os.path.isdir(filepath),
            "is_file": os.path.isfile(filepath),
        }
    except (FileNotFoundError, PermissionError, OSError):
        return None

def format_bytes(size: float) -> str:
    """Converts raw byte counts into human-readable strings."""
    if size is None:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024.0:
            return f"{size:3.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def read_file_preview(filepath: str, max_lines: int = 150) -> Dict[str, Any]:
    """
    Safely reads file content for preview/diffing.
    Handles binary files gracefully by checking for null bytes.
    """
    if not os.path.isfile(filepath):
        return {"is_binary": False, "content": "File not found.", "line_count": 0}
    
    try:
        # Check first 1KB for null bytes to detect binary file
        with open(filepath, "rb") as f:
            sample = f.read(1024)
            if b"\x00" in sample:
                return {
                    "is_binary": True,
                    "content": "[Binary file cannot be previewed as text]",
                    "line_count": 0
                }

        # Try UTF-8 first, fallback to Latin-1
        lines = []
        for encoding in ["utf-8", "latin-1"]:
            try:
                with open(filepath, "r", encoding=encoding, errors="replace") as f:
                    for i, line in enumerate(f):
                        if i >= max_lines:
                            lines.append("\n... [Preview truncated: file exceeds maximum preview length] ...")
                            break
                        lines.append(line)
                return {
                    "is_binary": False,
                    "content": "".join(lines),
                    "line_count": len(lines)
                }
            except Exception:
                continue
                
        return {"is_binary": True, "content": "[Unable to decode file text]", "line_count": 0}
    except PermissionError:
        return {"is_binary": False, "content": "[Permission Denied: OS access restricted]", "line_count": 0}
    except Exception as e:
        return {"is_binary": False, "content": f"[Error reading file: {str(e)}]", "line_count": 0}

def validate_monitored_folder_candidate(folder_path: str) -> Tuple[bool, str]:
    """
    Verifies that a folder path is valid for SafeFS monitoring:
    - Path must exist and be a directory
    - Must not be system root (e.g. C:\\ or /)
    - Must not be inside SafeFS application or backup directory
    - Must not be Windows/System32 or /etc
    """
    if not folder_path or not folder_path.strip():
        return False, "Folder path cannot be empty."
    
    path_obj = Path(folder_path).resolve()
    if not path_obj.exists():
        return False, f"Directory does not exist: {path_obj}"
    
    if not path_obj.is_dir():
        return False, f"Path is not a directory: {path_obj}"
    
    # Check for root directories
    if str(path_obj) == path_obj.anchor or len(path_obj.parts) <= 1:
        return False, "For safety reasons, root drives or root partitions cannot be monitored."
    
    # Check against blacklisted system and app paths
    norm_path = str(path_obj).lower()
    for blacklisted in config.SYSTEM_BLACKLIST_DIRECTORIES:
        if norm_path == blacklisted or norm_path.startswith(blacklisted + os.sep):
            return False, "Cannot monitor SafeFS internal data or backup directory."
            
    # Windows system directory checks
    windir = os.environ.get("WINDIR", "C:\\Windows").lower()
    if norm_path == windir or norm_path.startswith(windir + os.sep):
        return False, "Monitoring Windows system directories is prohibited."

    return True, "Path is valid."
