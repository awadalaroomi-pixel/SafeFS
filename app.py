import os
import atexit
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, abort
import config
from core.database import Database
from core.file_ops import format_bytes, validate_monitored_folder_candidate, read_file_preview
from core.version_mgr import VersionManager
from core.detector import ThreatDetector
from core.integrity import IntegrityChecker
from core.monitor import MonitorManager
from core.system_info import get_system_telemetry

app = Flask(__name__)
app.config["SECRET_KEY"] = "safefs-operating-systems-secret-key-2026"

# Core Subsystems Initialization
db = Database()
version_mgr = VersionManager(db)
detector = ThreatDetector(db)
integrity_checker = IntegrityChecker(db, version_mgr)
monitor_mgr = MonitorManager(db, version_mgr, detector)

# Start real-time filesystem monitor daemon
monitor_mgr.start()

# Clean shutdown handler
@atexit.register
def shutdown():
    monitor_mgr.stop()

# Custom Jinja Template Filters
@app.template_filter("filesize")
def filter_filesize(size):
    return format_bytes(size)

@app.template_filter("truncate_hash")
def filter_truncate_hash(h, length=12):
    if not h:
        return "N/A"
    return h[:length] + "..." if len(h) > length else h

# ----------------- WEB PAGE ROUTES -----------------

@app.route("/")
def dashboard_page():
    return render_template("dashboard.html", active_page="dashboard")

@app.route("/explorer")
def explorer_page():
    folders = db.get_monitored_folders()
    return render_template("explorer.html", active_page="explorer", folders=folders)

@app.route("/monitoring")
def monitoring_page():
    folders = db.get_monitored_folders()
    return render_template("monitoring.html", active_page="monitoring", folders=folders)

@app.route("/versions")
def versions_page():
    return render_template("versions.html", active_page="versions")

@app.route("/recovery")
def recovery_page():
    return render_template("recovery.html", active_page="recovery")

@app.route("/threats")
def threats_page():
    return render_template("threats.html", active_page="threats")

@app.route("/logs")
def logs_page():
    return render_template("logs.html", active_page="logs")

@app.route("/system")
def system_page():
    return render_template("system.html", active_page="system")

@app.route("/settings")
def settings_page():
    folders = db.get_monitored_folders()
    current_settings = db.get_settings()
    return render_template("settings.html", active_page="settings", folders=folders, settings=current_settings)

@app.route("/os-concepts")
def os_concepts_page():
    return render_template("os_concepts.html", active_page="os_concepts")


# ----------------- REST API ENDPOINTS -----------------

@app.route("/api/stats")
def api_stats():
    """Aggregated dashboard telemetry and monitoring status."""
    summary = db.get_dashboard_summary()
    status = monitor_mgr.get_status()
    summary["monitor_status"] = status
    return jsonify(summary)

@app.route("/api/events/live")
def api_live_events():
    """Live file event stream for dashboard status indicators."""
    limit = request.args.get("limit", 40, type=int)
    events = monitor_mgr.get_recent_live_events(limit=limit)
    return jsonify({"events": events, "monitor_active": monitor_mgr.is_running()})

@app.route("/api/folders", methods=["GET"])
def api_get_folders():
    folders = db.get_monitored_folders()
    return jsonify(folders)

@app.route("/api/folders/add", methods=["POST"])
def api_add_folder():
    """Registers a new user-selected folder, starts watchdog watch, and performs baseline indexing."""
    data = request.get_json() or {}
    folder_path = data.get("path", "").strip()
    label = data.get("label", "").strip()

    is_valid, msg = validate_monitored_folder_candidate(folder_path)
    if not is_valid:
        return jsonify({"success": False, "error": msg}), 400

    try:
        folder_id = db.add_monitored_folder(folder_path, label=label or None)
        # Register in Watchdog observer
        monitor_mgr.add_folder(folder_id, folder_path)
        # Index files and capture initial snapshot baselines
        index_res = integrity_checker.scan_and_index_folder(folder_id)

        db.add_activity_log(
            event_type="FOLDER_ADDED",
            file_path=folder_path,
            filename=os.path.basename(folder_path),
            folder_id=folder_id,
            severity="INFO",
            details=f"Folder added to SafeFS monitoring. {index_res.get('indexed_count', 0)} files indexed."
        )

        return jsonify({
            "success": True,
            "folder_id": folder_id,
            "message": f"Successfully registered folder and indexed {index_res.get('indexed_count', 0)} files."
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to add folder: {str(e)}"}), 500

@app.route("/api/folders/remove", methods=["POST"])
def api_remove_folder():
    data = request.get_json() or {}
    folder_id = data.get("folder_id")
    if not folder_id:
        return jsonify({"success": False, "error": "Folder ID is required"}), 400

    folder = db.get_folder_by_id(folder_id)
    if folder:
        monitor_mgr.remove_folder(folder_id)
        db.remove_monitored_folder(folder_id)
        db.add_activity_log(
            event_type="FOLDER_REMOVED",
            file_path=folder["path"],
            filename=folder["label"],
            folder_id=folder_id,
            severity="WARNING",
            details="Folder removed from SafeFS monitoring"
        )

    return jsonify({"success": True, "message": "Folder removed successfully."})

@app.route("/api/folders/scan", methods=["POST"])
def api_scan_folder():
    data = request.get_json() or {}
    folder_id = data.get("folder_id")
    if not folder_id:
        return jsonify({"success": False, "error": "Folder ID is required"}), 400

    res = integrity_checker.scan_and_index_folder(folder_id)
    return jsonify(res)

@app.route("/api/files")
def api_get_files():
    folder_id = request.args.get("folder_id", type=int)
    status = request.args.get("status")
    search = request.args.get("search")
    files = db.get_files(folder_id=folder_id, status=status, search=search)
    return jsonify(files)

@app.route("/api/files/<int:file_id>/versions")
def api_get_file_versions(file_id):
    versions = db.get_file_versions(file_id)
    return jsonify(versions)

@app.route("/api/files/restore", methods=["POST"])
def api_restore_file():
    """
    Restores file with strict Operating System safety invariant:
    Pre-restores snapshot of live target before overwrite.
    """
    data = request.get_json() or {}
    version_id = data.get("version_id")
    reason = data.get("reason", "Manual restoration via SafeFS UI")

    if not version_id:
        return jsonify({"success": False, "error": "Version ID is required"}), 400

    success, message = version_mgr.restore_version(version_id, reason=reason)
    status_code = 200 if success else 400
    return jsonify({"success": success, "message": message}), status_code

@app.route("/api/files/verify", methods=["POST"])
def api_verify_integrity():
    data = request.get_json() or {}
    file_id = data.get("file_id")
    folder_id = data.get("folder_id")

    if file_id:
        result = integrity_checker.verify_file(file_id)
        return jsonify(result)
    else:
        result = integrity_checker.verify_all_files(folder_id=folder_id)
        return jsonify(result)

@app.route("/api/files/preview")
def api_preview_file():
    file_id = request.args.get("file_id", type=int)
    version_id = request.args.get("version_id", type=int)

    if version_id:
        v_path = version_mgr.get_version_file_path(version_id)
        if not v_path:
            return jsonify({"error": "Version file not found on disk"}), 404
        preview = read_file_preview(str(v_path))
        return jsonify(preview)
    elif file_id:
        file_rec = db.get_file_by_id(file_id)
        if not file_rec:
            return jsonify({"error": "File record not found"}), 404
        preview = read_file_preview(file_rec["path"])
        return jsonify(preview)

    return jsonify({"error": "file_id or version_id must be provided"}), 400

@app.route("/api/versions/diff")
def api_version_diff():
    v1_id = request.args.get("v1_id", type=int)
    v2_id = request.args.get("v2_id", type=int)
    current_file = request.args.get("current_file", "false").lower() == "true"

    if not v1_id:
        return jsonify({"error": "v1_id is required"}), 400

    diff_result = version_mgr.compute_diff(v1_id, v2_id=v2_id, current_file=current_file)
    return jsonify(diff_result)

@app.route("/api/versions/download/<int:version_id>")
def api_download_version(version_id):
    version = db.get_version_by_id(version_id)
    if not version:
        abort(404)

    v_path = version_mgr.get_version_file_path(version_id)
    if not v_path or not v_path.exists():
        abort(404)

    return send_file(
        str(v_path),
        as_attachment=True,
        download_name=f"v{version['version_number']}_{version['filename']}"
    )

@app.route("/api/versions/<int:version_id>", methods=["DELETE"])
def api_delete_version(version_id):
    success, msg = version_mgr.delete_version(version_id)
    return jsonify({"success": success, "message": msg})

@app.route("/api/all-versions")
def api_all_versions():
    search = request.args.get("search")
    versions = db.get_all_backup_versions(search=search)
    return jsonify(versions)

@app.route("/api/recovery/history")
def api_recovery_history():
    history = db.get_recovery_history(limit=50)
    return jsonify(history)

@app.route("/api/threats")
def api_get_threats():
    status = request.args.get("status")
    alerts = db.get_security_alerts(status=status)
    return jsonify(alerts)

@app.route("/api/threats/<int:alert_id>/resolve", methods=["POST"])
def api_resolve_threat(alert_id):
    db.resolve_security_alert(alert_id)
    return jsonify({"success": True, "message": "Alert marked as resolved."})

@app.route("/api/threats/<int:alert_id>/dismiss", methods=["POST"])
def api_dismiss_threat(alert_id):
    db.dismiss_security_alert(alert_id)
    return jsonify({"success": True, "message": "Alert dismissed."})

@app.route("/api/logs")
def api_get_logs():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    event_type = request.args.get("event_type")
    severity = request.args.get("severity")
    search = request.args.get("search")

    logs = db.get_activity_logs(limit=limit, offset=offset, event_type=event_type, severity=severity, search=search)
    total_count = db.count_activity_logs(event_type=event_type, severity=severity, search=search)

    return jsonify({"logs": logs, "total": total_count, "limit": limit, "offset": offset})

@app.route("/api/logs/clear", methods=["POST"])
def api_clear_logs():
    db.clear_activity_logs()
    return jsonify({"success": True, "message": "Activity logs cleared."})

@app.route("/api/system/stats")
def api_system_stats():
    telemetry = get_system_telemetry()
    telemetry["monitor_status"] = monitor_mgr.get_status()
    return jsonify(telemetry)

@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    return jsonify(db.get_settings())

@app.route("/api/settings/update", methods=["POST"])
def api_update_settings():
    data = request.get_json() or {}
    db.update_settings(data)
    return jsonify({"success": True, "message": "Settings updated successfully."})

@app.route("/api/monitor/toggle", methods=["POST"])
def api_toggle_monitor():
    data = request.get_json() or {}
    enable = data.get("enable", True)

    if enable and not monitor_mgr.is_running():
        monitor_mgr.start()
        status_msg = "Monitoring engine started."
    elif not enable and monitor_mgr.is_running():
        monitor_mgr.stop()
        status_msg = "Monitoring engine paused."
    else:
        status_msg = "Status unchanged."

    return jsonify({
        "success": True,
        "is_running": monitor_mgr.is_running(),
        "message": status_msg
    })

if __name__ == "__main__":
    print(f"[*] Starting SafeFS Operating Systems Server on {config.FLASK_HOST}:{config.FLASK_PORT}...")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
