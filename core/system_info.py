import os
import platform
import time
import datetime
from typing import Dict, Any, List
import psutil
from core.file_ops import format_bytes

def get_system_telemetry() -> Dict[str, Any]:
    """
    Collects real-time OS-level performance metrics and kernel hardware statistics
    demonstrating Operating Systems resource management and process monitoring.
    Robustly handles environments where specific Windows PDH performance counters may be disabled.
    """
    # 1. CPU Telemetry
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
    except Exception:
        cpu_percent = 0.0

    try:
        cpu_cores_logical = psutil.cpu_count(logical=True) or 1
        cpu_cores_physical = psutil.cpu_count(logical=False) or 1
        per_cpu_percent = psutil.cpu_percent(interval=None, percpu=True) or [cpu_percent]
    except Exception:
        cpu_cores_logical = 1
        cpu_cores_physical = 1
        per_cpu_percent = [cpu_percent]
    
    try:
        cpu_freq = psutil.cpu_freq()
        freq_current = f"{cpu_freq.current:.1f} MHz" if cpu_freq else "N/A"
    except Exception:
        freq_current = "N/A"

    # 2. Virtual Memory (RAM)
    try:
        mem = psutil.virtual_memory()
        mem_total = format_bytes(mem.total)
        mem_avail = format_bytes(mem.available)
        mem_used = format_bytes(mem.used)
        mem_percent = mem.percent
    except Exception:
        mem_total = "N/A"
        mem_avail = "N/A"
        mem_used = "N/A"
        mem_percent = 0.0

    try:
        swap = psutil.swap_memory()
        swap_total = format_bytes(swap.total)
        swap_used = format_bytes(swap.used)
        swap_percent = swap.percent
    except Exception:
        swap_total = "N/A"
        swap_used = "N/A"
        swap_percent = 0.0

    memory_info = {
        "total": mem_total,
        "available": mem_avail,
        "used": mem_used,
        "percent": mem_percent,
        "swap_total": swap_total,
        "swap_used": swap_used,
        "swap_percent": swap_percent
    }

    # 3. Storage / Disk Usage (Host drive)
    try:
        disk = psutil.disk_usage(os.path.abspath(os.sep))
        disk_total = format_bytes(disk.total)
        disk_used = format_bytes(disk.used)
        disk_free = format_bytes(disk.free)
        disk_percent = disk.percent
    except Exception:
        disk_total = "N/A"
        disk_used = "N/A"
        disk_free = "N/A"
        disk_percent = 0.0

    try:
        disk_io = psutil.disk_io_counters()
        read_bytes = format_bytes(disk_io.read_bytes) if disk_io else "N/A"
        write_bytes = format_bytes(disk_io.write_bytes) if disk_io else "N/A"
    except Exception:
        read_bytes = "N/A"
        write_bytes = "N/A"

    storage_info = {
        "total": disk_total,
        "used": disk_used,
        "free": disk_free,
        "percent": disk_percent,
        "read_bytes": read_bytes,
        "write_bytes": write_bytes
    }

    # 4. Process Telemetry (SafeFS Engine instance)
    try:
        current_proc = psutil.Process(os.getpid())
        with current_proc.oneshot():
            proc_mem = current_proc.memory_info()
            proc_threads = current_proc.num_threads()
            proc_cpu = current_proc.cpu_percent(interval=None)
            proc_create_time = datetime.datetime.fromtimestamp(current_proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")

        process_info = {
            "pid": current_proc.pid,
            "rss_memory": format_bytes(proc_mem.rss),
            "vms_memory": format_bytes(proc_mem.vms),
            "threads": proc_threads,
            "cpu_percent": proc_cpu,
            "started_at": proc_create_time
        }
    except Exception as e:
        process_info = {
            "pid": os.getpid(),
            "rss_memory": "N/A",
            "vms_memory": "N/A",
            "threads": 1,
            "cpu_percent": 0.0,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    # 5. OS & Kernel Metadata
    try:
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = int(time.time() - psutil.boot_time())
        uptime_str = str(datetime.timedelta(seconds=uptime_seconds))
        boot_str = boot_time.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        uptime_str = "N/A"
        boot_str = "N/A"

    os_info = {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "boot_time": boot_str,
        "uptime": uptime_str
    }

    return {
        "cpu": {
            "percent": cpu_percent,
            "logical_cores": cpu_cores_logical,
            "physical_cores": cpu_cores_physical,
            "per_core": per_cpu_percent,
            "frequency": freq_current
        },
        "memory": memory_info,
        "storage": storage_info,
        "process": process_info,
        "os": os_info,
        "timestamp": time.strftime("%H:%M:%S")
    }
