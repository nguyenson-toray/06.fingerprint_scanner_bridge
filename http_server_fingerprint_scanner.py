# -*- coding: utf-8 -*-
"""
Desktop Bridge App v2.0 - Local HTTP Server
Chạy trên máy tính user để làm cầu nối giữa ERPNext Web UI và Scanner

v2.0 changes:
- /api/version: version + capability check for the web UI
- Job-based capture: POST /api/fingerprint/capture returns a job_id immediately,
  enrollment runs in a background thread (no more 30s-vs-90s timeout mismatch)
- SSE /api/events/<job_id>: real-time structured events pushed to the web UI
  (replaces 200ms log polling + string parsing)
- Persistent scanner session: connect once per dialog session, auto-disconnect
  after idle timeout (no init/disconnect per finger)
- Session duplicate check: warns if a new template matches a finger already
  enrolled in this session (ZKFPM_DBMatch)
- CORS restricted to configured origins (biometric data protection);
  override via bridge_config.json next to the exe
"""

import json
import logging
import base64
import time
import threading
import uuid
import webbrowser
import sys
import os
from flask import Flask, request, jsonify, render_template_string, Response
from flask_cors import CORS

# Import scanner module
from functions_fingerprint_scanner import (
    FingerprintScanner, SCANNER_CONFIG, FINGERPRINT_CONFIG,
    get_finger_name, ERROR_CODES, EnrollmentCancelled
)

VERSION = "2.0.0"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- configuration

DESKTOP_CONFIG = {
    "host": "127.0.0.1",
    "port": 8080,
    "debug": False,
    "auto_open_browser": False
}

# Origins allowed to call this bridge from the browser.
# Override with bridge_config.json (same folder as exe):
#   { "allowed_origins": ["https://erp.tiqn.com.vn"], "port": 8080 }
# Use ["*"] to disable the restriction (not recommended).
DEFAULT_ALLOWED_ORIGINS = [
    "https://erp.tiqn.com.vn",
    "https://erp.tiqn.com.vn:8888",
    "https://erp.tiqn.local",
    "https://erp.tiqn.local:8888",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]


def _base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def load_bridge_config():
    path = os.path.join(_base_dir(), 'bridge_config.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            logger.info(f"Loaded bridge_config.json: {cfg}")
            return cfg
        except Exception as e:
            logger.error(f"Invalid bridge_config.json ignored: {e}")
    return {}


_cfg = load_bridge_config()
ALLOWED_ORIGINS = _cfg.get('allowed_origins', DEFAULT_ALLOWED_ORIGINS)
DESKTOP_CONFIG['port'] = int(_cfg.get('port', DESKTOP_CONFIG['port']))

IDLE_DISCONNECT_SECONDS = int(_cfg.get('idle_disconnect_seconds', 300))
JOB_MAX_AGE_SECONDS = 3600
JOB_STREAM_TIMEOUT_SECONDS = 300

# Flask app
app = Flask(__name__)
CORS(app, origins=ALLOWED_ORIGINS)


@app.before_request
def _log_blocked_origin():
    """Log requests whose Origin is not allowed — the #1 cause of the web UI
    reporting 'cannot connect' while the bridge logs 200 responses."""
    origin = request.headers.get('Origin')
    if origin and '*' not in ALLOWED_ORIGINS and origin not in ALLOWED_ORIGINS:
        print(f"⛔ CORS:BLOCKED origin '{origin}' — web UI cannot read responses!")
        print(f"   → Add it to bridge_config.json: {{\"allowed_origins\": [\"{origin}\"]}}")

# ---------------------------------------------------------------- shared state

scanner = None
scanner_lock = threading.Lock()
last_activity = time.time()

# finger_index -> merged template captured in the current dialog session
# (used to warn when the operator scans the same physical finger twice)
session_templates = {}

jobs = {}          # job_id -> job dict
jobs_lock = threading.Lock()

# Optimized log storage (for the local status page + legacy clients)
app_logs = []
MAX_LOGS = 50


class DesktopBridgeLogger:
    """Compact logger feeding the status page activity log"""

    @staticmethod
    def log(level, message):
        timestamp = time.strftime("%H:%M:%S")
        if isinstance(message, str) and len(message) > 100:
            message = message[:97] + "..."

        app_logs.append({
            "timestamp": timestamp,
            "level": level,
            "message": message
        })
        if len(app_logs) > MAX_LOGS:
            app_logs.pop(0)

        try:
            print(f"[{timestamp}] {level}: {message}")
        except (AttributeError, OSError):
            pass

    @staticmethod
    def info(message):
        DesktopBridgeLogger.log("info", message)

    @staticmethod
    def success(message):
        DesktopBridgeLogger.log("success", message)

    @staticmethod
    def warning(message):
        DesktopBridgeLogger.log("warning", message)

    @staticmethod
    def error(message):
        DesktopBridgeLogger.log("error", message)


DesktopBridgeLogger.info(f"Desktop Bridge v{VERSION} starting...")


# ---------------------------------------------------------------- scanner session

def _ensure_scanner_connected():
    """Connect the scanner if needed. Caller must hold scanner_lock."""
    global scanner
    if scanner and scanner.is_connected:
        try:
            if scanner.zkfp.ZKFPM_GetDeviceCount() > 0:
                return True
        except Exception:
            pass
        # Device vanished — full reconnect
        try:
            scanner.disconnect()
        except Exception:
            pass
        scanner = None

    scanner = FingerprintScanner()
    if scanner.connect():
        DesktopBridgeLogger.success(f"CONN:OK:{scanner.img_width}x{scanner.img_height}")
        return True
    scanner = None
    return False


def _touch_activity():
    global last_activity
    last_activity = time.time()


def _idle_watchdog():
    """Auto-disconnect the scanner after idle timeout (frees the USB device)."""
    global scanner
    while True:
        time.sleep(30)
        try:
            if not (scanner and scanner.is_connected):
                continue
            if time.time() - last_activity < IDLE_DISCONNECT_SECONDS:
                continue
            if not scanner_lock.acquire(blocking=False):
                continue
            try:
                running = any(j['status'] == 'running' for j in jobs.values())
                if not running and time.time() - last_activity >= IDLE_DISCONNECT_SECONDS:
                    scanner.disconnect()
                    session_templates.clear()
                    DesktopBridgeLogger.info("IDLE:AUTO_DISCONNECT")
            finally:
                scanner_lock.release()
        except Exception as e:
            logger.warning(f"Idle watchdog error: {e}")


# ---------------------------------------------------------------- job management

def _prune_jobs():
    """Drop finished jobs older than JOB_MAX_AGE_SECONDS. Caller holds jobs_lock."""
    now = time.time()
    for job_id in list(jobs.keys()):
        job = jobs[job_id]
        if job['status'] != 'running' and now - job['created'] > JOB_MAX_AGE_SECONDS:
            del jobs[job_id]


def _job_emit(job, evt):
    """Append an event to the job history (SSE stream reads from here)."""
    evt = dict(evt)
    evt['seq'] = len(job['history']) + 1
    evt['ts'] = time.strftime("%H:%M:%S")
    job['history'].append(evt)
    _log_event_readable(evt)


def _log_event_readable(evt):
    """Mirror structured events into the status-page activity log."""
    t = evt.get('type')
    if t == 'scan_waiting':
        DesktopBridgeLogger.info(f"S{evt.get('attempt')}/{evt.get('total')}:waiting")
    elif t == 'scan_success':
        DesktopBridgeLogger.success(
            f"S{evt.get('attempt')}/{evt.get('total')}:OK Q{evt.get('quality')}")
    elif t == 'scan_retry':
        DesktopBridgeLogger.warning(
            f"RETRY:S{evt.get('attempt')}:{evt.get('code')}:{evt.get('message')}")
    elif t == 'lift_finger':
        DesktopBridgeLogger.info("LIFT_FINGER")
    elif t == 'merge_start':
        DesktopBridgeLogger.info("MERGE:START")
    elif t == 'complete':
        DesktopBridgeLogger.success(
            f"ENROLL:OK:Q{evt.get('quality_score')}:S{evt.get('template_size')}")
    elif t == 'failed':
        DesktopBridgeLogger.error(f"ENROLL:FAIL:{evt.get('code')}:{evt.get('message')}")
    elif t == 'job_started':
        DesktopBridgeLogger.info(f"ENROLL:START:{evt.get('finger_name')}")


def _check_session_duplicate(finger_index, template):
    """Match a new template against other fingers enrolled this session."""
    threshold = FINGERPRINT_CONFIG.get('match_threshold', 45)
    for other_index, other_template in session_templates.items():
        if other_index == finger_index:
            continue
        score = scanner.match_templates(other_template, template)
        if score >= threshold:
            return other_index, score
    return None, None


def _run_capture_job(job, finger_index):
    """Background thread: run the full enrollment and record the result."""
    def cb(evt):
        _job_emit(job, evt)

    if not scanner_lock.acquire(timeout=5):
        job['status'] = 'failed'
        _job_emit(job, {'type': 'failed', 'code': 2002, 'message': 'Scanner busy'})
        return
    try:
        if not _ensure_scanner_connected():
            job['status'] = 'failed'
            _job_emit(job, {'type': 'failed', 'code': 1003,
                            'message': 'Could not connect to scanner'})
            return

        scanner.event_callback = cb
        try:
            template = scanner.enroll_fingerprint(finger_index, cancel_event=job['cancel'])
        finally:
            scanner.event_callback = None

        if template:
            quality = scanner._calculate_quality_score(template)
            dup_index, dup_score = _check_session_duplicate(finger_index, template)
            session_templates[finger_index] = template

            result = {
                'template_data': base64.b64encode(template).decode('utf-8'),
                'template_size': len(template),
                'quality_score': quality,
                'finger_index': finger_index,
                'finger_name': get_finger_name(finger_index),
            }
            if dup_index is not None:
                result['duplicate_of'] = dup_index
                result['duplicate_finger_name'] = get_finger_name(dup_index)
                result['duplicate_score'] = dup_score

            job['result'] = result
            job['status'] = 'completed'
            _job_emit(job, dict(result, type='complete'))
        else:
            job['status'] = 'failed'
            # Scanner emits its own 'failed' event on every failure path;
            # add a safety net in case it did not.
            if not job['history'] or job['history'][-1]['type'] != 'failed':
                _job_emit(job, {'type': 'failed', 'code': 2002,
                                'message': 'Enrollment failed'})

    except EnrollmentCancelled:
        job['status'] = 'failed'
        _job_emit(job, {'type': 'failed', 'code': 2006, 'message': 'Cancelled by user'})
    except Exception as e:
        logger.error(f"Capture job error: {e}")
        job['status'] = 'failed'
        _job_emit(job, {'type': 'failed', 'code': 2002, 'message': str(e)[:100]})
    finally:
        _touch_activity()
        scanner_lock.release()


# ---------------------------------------------------------------- basic endpoints

@app.route('/api/test', methods=['GET'])
def test_connection():
    """Test API connection"""
    return jsonify({
        "success": True,
        "message": "OK",
        "version": VERSION,
        "timestamp": time.strftime("%H:%M:%S")
    })


@app.route('/api/version', methods=['GET'])
def get_version():
    """Version + capability check for the web UI"""
    return jsonify({
        "success": True,
        "version": VERSION,
        "api": "v2",
        "features": ["sse", "jobs", "match_check", "finger_lift",
                     "persistent_session", "session_duplicate_check"]
    })


@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get recent logs (status page + legacy clients)"""
    return jsonify({
        "success": True,
        "logs": app_logs[-50:],
        "total_logs": len(app_logs)
    })


@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Clear logs"""
    global app_logs
    app_logs = []
    DesktopBridgeLogger.info("LOGS:CLEARED")
    return jsonify({"success": True, "message": "OK"})


@app.route('/api/logs/since', methods=['GET'])
def get_logs_since():
    """Get logs since specific timestamp (legacy clients)"""
    since = request.args.get('since', '')
    if not since:
        return jsonify({
            "success": True,
            "logs": app_logs[-5:] if len(app_logs) > 5 else app_logs
        })
    filtered_logs = [log for log in app_logs if log['timestamp'] >= since]
    return jsonify({"success": True, "logs": filtered_logs})


# ---------------------------------------------------------------- scanner session endpoints

@app.route('/api/scanner/status', methods=['GET'])
def get_scanner_status():
    """Get scanner status"""
    try:
        if scanner and scanner.is_connected:
            status = {
                "connected": True,
                "device_info": f"{SCANNER_CONFIG['model']} - USB Connected "
                               f"({scanner.img_width}x{scanner.img_height})"
            }
        else:
            status = {"connected": False, "device_info": "Scanner not connected"}
        return jsonify({"success": True, "status": status, "version": VERSION})
    except Exception as e:
        logger.error(f"Error getting scanner status: {e}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route('/api/scanner/initialize', methods=['POST'])
def initialize_scanner():
    """Initialize scanner (persistent session — fast no-op if already connected)"""
    if not scanner_lock.acquire(timeout=5):
        return jsonify({"success": False, "message": "Scanner busy"}), 409
    try:
        DesktopBridgeLogger.info("INIT:START")
        _touch_activity()
        if _ensure_scanner_connected():
            session_templates.clear()  # new dialog session
            return jsonify({
                "success": True,
                "message": "Scanner initialized successfully",
                "device_info": f"{SCANNER_CONFIG['model']} - USB Connected "
                               f"({scanner.img_width}x{scanner.img_height})"
            })
        DesktopBridgeLogger.error("INIT:FAIL:1003")
        return jsonify({"success": False, "message": "Could not connect to scanner"})
    except Exception as e:
        DesktopBridgeLogger.error(f"INIT:ERR:{str(e)[:50]}")
        return jsonify({"success": False, "message": f"Error initializing scanner: {str(e)}"})
    finally:
        scanner_lock.release()


@app.route('/api/scanner/disconnect', methods=['POST'])
def disconnect_scanner():
    """Disconnect scanner (called when the web dialog closes)"""
    global scanner
    if not scanner_lock.acquire(timeout=2):
        # A capture job is running — it owns the scanner right now
        return jsonify({"success": False, "message": "Scanner busy"}), 409
    try:
        if scanner:
            scanner.disconnect()
            scanner = None
        session_templates.clear()
        DesktopBridgeLogger.info("DISC:OK")
        return jsonify({"success": True, "message": "Scanner disconnected successfully"})
    except Exception as e:
        logger.error(f"Error disconnecting scanner: {e}")
        return jsonify({"success": False, "message": f"Error disconnecting scanner: {str(e)}"})
    finally:
        scanner_lock.release()


# ---------------------------------------------------------------- capture (v2 jobs)

@app.route('/api/fingerprint/capture', methods=['POST'])
def capture_fingerprint():
    """Start an enrollment job. Returns job_id immediately; progress via SSE."""
    data = request.get_json(silent=True) or {}
    try:
        finger_index = int(data.get('finger_index', -1))
    except (TypeError, ValueError):
        finger_index = -1
    employee_id = data.get('employee_id', '')

    if finger_index < 0 or finger_index > 9:
        return jsonify({"success": False, "message": "Invalid finger index (0-9)"}), 400

    with jobs_lock:
        if any(j['status'] == 'running' for j in jobs.values()):
            return jsonify({"success": False,
                            "message": "Another scan is already in progress"}), 409
        _prune_jobs()
        job = {
            'id': uuid.uuid4().hex,
            'status': 'running',
            'result': None,
            'history': [],
            'cancel': threading.Event(),
            'created': time.time(),
            'finger_index': finger_index,
            'employee_id': employee_id,
        }
        jobs[job['id']] = job

    _touch_activity()
    DesktopBridgeLogger.info(f"JOB:{job['id'][:8]}:{employee_id}:{get_finger_name(finger_index)}")

    threading.Thread(target=_run_capture_job, args=(job, finger_index), daemon=True).start()
    return jsonify({"success": True, "job_id": job['id']})


@app.route('/api/events/<job_id>', methods=['GET'])
def stream_job_events(job_id):
    """SSE stream of enrollment events for a job.

    Events are replayed from history using seq numbers, so a reconnecting
    EventSource never misses or duplicates events (client skips seq <= last seen).
    """
    job = jobs.get(job_id)
    if not job:
        return jsonify({"success": False, "message": "Job not found"}), 404

    def generate():
        idx = 0
        last_yield = time.time()
        deadline = job['created'] + JOB_STREAM_TIMEOUT_SECONDS
        while time.time() < deadline:
            history = job['history']
            while idx < len(history):
                evt = history[idx]
                idx += 1
                last_yield = time.time()
                yield f"data: {json.dumps(evt)}\n\n"
                if evt['type'] in ('complete', 'failed'):
                    return
            if time.time() - last_yield > 10:
                last_yield = time.time()
                yield ": keep-alive\n\n"
            time.sleep(0.1)
        yield "data: %s\n\n" % json.dumps(
            {'type': 'failed', 'code': 2001, 'message': 'Stream timeout', 'seq': -1})

    headers = {
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    }
    return Response(generate(), mimetype='text/event-stream', headers=headers)


@app.route('/api/fingerprint/job/<job_id>', methods=['GET'])
def get_job_status(job_id):
    """Job status/result fallback (used if the SSE stream drops)."""
    job = jobs.get(job_id)
    if not job:
        return jsonify({"success": False, "message": "Job not found"}), 404
    return jsonify({
        "success": True,
        "status": job['status'],
        "result": job['result'],
        "events": job['history'],
    })


@app.route('/api/fingerprint/cancel/<job_id>', methods=['POST'])
def cancel_job(job_id):
    """Cancel a running enrollment job."""
    job = jobs.get(job_id)
    if not job:
        return jsonify({"success": False, "message": "Job not found"}), 404
    job['cancel'].set()
    DesktopBridgeLogger.warning(f"JOB:{job_id[:8]}:CANCEL")
    return jsonify({"success": True})


@app.route('/api/fingerprint/test', methods=['POST'])
def test_fingerprint_enrollment():
    """Synchronous test enrollment (status page only)."""
    data = request.get_json(silent=True) or {}
    finger_index = int(data.get('finger_index', 3))

    if not scanner_lock.acquire(timeout=2):
        return jsonify({"success": False, "message": "Scanner busy"}), 409
    try:
        if not _ensure_scanner_connected():
            return jsonify({"success": False, "message": "Scanner not connected"})

        finger_name = get_finger_name(finger_index)
        DesktopBridgeLogger.info(f"TEST:START:{finger_name}")

        scanner.event_callback = lambda evt: _log_event_readable(
            dict(evt, seq=0, ts=time.strftime("%H:%M:%S")))
        try:
            template_data = scanner.enroll_fingerprint(finger_index)
        finally:
            scanner.event_callback = None

        if template_data:
            quality_score = scanner._calculate_quality_score(template_data)
            return jsonify({
                "success": True,
                "message": f"Test enrollment completed for {finger_name}",
                "template_data": base64.b64encode(template_data).decode('utf-8'),
                "template_size": len(template_data),
                "finger_index": finger_index,
                "quality_score": quality_score,
                "finger_name": finger_name
            })
        return jsonify({"success": False, "message": "Test enrollment failed"})
    except Exception as e:
        DesktopBridgeLogger.error(f"TEST:ERR:{str(e)[:50]}")
        return jsonify({"success": False, "message": f"Test error: {str(e)}"})
    finally:
        _touch_activity()
        scanner_lock.release()


# ---------------------------------------------------------------- attendance device sync

@app.route('/api/sync/attendance_device', methods=['POST'])
def sync_to_attendance_device():
    """Sync fingerprints to attendance device"""
    try:
        data = request.get_json()
        device_config = data.get('device_config')
        employee_list = data.get('employee_list')

        # Import ZK library
        try:
            from zk import ZK, const
            from zk.base import Finger
        except ImportError:
            return jsonify({
                "success": False,
                "message": "pyzk library not installed"
            })

        device_ip = device_config.get('ip')
        device_port = device_config.get('port', 4370)
        device_name = device_config.get('name', 'Attendance Device')

        logger.info(f"Syncing to attendance device: {device_name} ({device_ip}:{device_port})")

        # Connect to attendance device
        zk = ZK(device_ip, port=device_port, timeout=10)
        conn = zk.connect()

        if not conn:
            return jsonify({
                "success": False,
                "message": f"Could not connect to attendance device {device_name}"
            })

        try:
            conn.disable_device()

            success_count = 0
            total_count = len(employee_list)

            for employee_data in employee_list:
                try:
                    employee_id = employee_data.get('employee')
                    attendance_device_id = employee_data.get('attendance_device_id')
                    employee_name = employee_data.get('employee_name', '')
                    fingerprints = employee_data.get('fingerprints', [])

                    if not attendance_device_id or not fingerprints:
                        continue

                    # Delete existing user
                    try:
                        conn.delete_user(user_id=attendance_device_id)
                    except Exception:
                        pass

                    # Create new user
                    if len(employee_name) > 24:
                        employee_name = employee_name[:24]

                    conn.set_user(
                        user_id=attendance_device_id,
                        name=employee_name,
                        privilege=const.USER_DEFAULT
                    )

                    # Get user UID
                    users = conn.get_users()
                    user = next((u for u in users if u.user_id == attendance_device_id), None)

                    if user:
                        # Prepare templates
                        templates_to_send = []

                        for i in range(10):
                            finger_data = next((fp for fp in fingerprints if fp.get('finger_index') == i), None)

                            if finger_data and finger_data.get('template_data'):
                                try:
                                    template_bytes = base64.b64decode(finger_data['template_data'])
                                    finger_obj = Finger(uid=user.uid, fid=i, valid=True, template=template_bytes)
                                    templates_to_send.append(finger_obj)
                                except Exception:
                                    finger_obj = Finger(uid=user.uid, fid=i, valid=False, template=b'')
                                    templates_to_send.append(finger_obj)
                            else:
                                finger_obj = Finger(uid=user.uid, fid=i, valid=False, template=b'')
                                templates_to_send.append(finger_obj)

                        # Send templates to device
                        conn.save_user_template(user, templates_to_send)
                        success_count += 1

                        logger.info(f"Synced employee {employee_id} successfully")

                except Exception as e:
                    logger.error(f"Error syncing employee {employee_data.get('employee')}: {e}")
                    continue

            logger.info(f"Sync completed: {success_count}/{total_count} employees")

            return jsonify({
                "success": True,
                "message": f"Successfully synced {success_count}/{total_count} employees to {device_name}",
                "success_count": success_count,
                "total_count": total_count
            })

        finally:
            conn.enable_device()
            conn.disconnect()

    except Exception as e:
        logger.error(f"Error syncing to attendance device: {e}")
        return jsonify({
            "success": False,
            "message": f"Sync error: {str(e)}"
        })


# ---------------------------------------------------------------- status page

@app.route('/')
def index():
    """Main page with status and controls"""
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fingerprint Scanner Desktop Bridge v{{ version }}</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 30px; }
            .status { padding: 15px; border-radius: 5px; margin: 20px 0; }
            .status.connected { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
            .status.disconnected { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
            .button { padding: 10px 20px; margin: 5px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; }
            .button.primary { background: #007bff; color: white; }
            .button.success { background: #28a745; color: white; }
            .button.danger { background: #dc3545; color: white; }
            .button:hover { opacity: 0.8; }
            .info { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .log { background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 12px; max-height: 200px; overflow-y: auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 Fingerprint Scanner Desktop Bridge</h1>
                <p>v{{ version }} — local bridge on port {{ port }}</p>
            </div>

            <div id="status-container">
                <div class="status disconnected" id="scanner-status">
                    <strong>Scanner Status:</strong> <span id="status-text">Checking...</span>
                </div>
            </div>

            <div style="text-align: center; margin: 20px 0;">
                <button class="button success" onclick="initializeScanner()">Initialize Scanner</button>
                <button class="button danger" onclick="disconnectScanner()">Disconnect Scanner</button>
                <button class="button primary" onclick="refreshStatus()">Refresh Status</button>
                <button class="button primary" onclick="testEnrollment()">🧪 Test 3-Scan Enrollment</button>
            </div>

            <div class="info">
                <h3>🌐 API Endpoints (v2):</h3>
                <ul>
                    <li><code>GET /api/version</code> - Version and capabilities</li>
                    <li><code>GET /api/test</code> - Test connection</li>
                    <li><code>GET /api/scanner/status</code> - Get scanner status</li>
                    <li><code>POST /api/scanner/initialize</code> - Connect scanner (persistent session)</li>
                    <li><code>POST /api/scanner/disconnect</code> - Disconnect scanner</li>
                    <li><code>POST /api/fingerprint/capture</code> - Start enrollment job (returns job_id)</li>
                    <li><code>GET /api/events/&lt;job_id&gt;</code> - SSE stream of enrollment events</li>
                    <li><code>GET /api/fingerprint/job/&lt;job_id&gt;</code> - Job status/result</li>
                    <li><code>POST /api/fingerprint/cancel/&lt;job_id&gt;</code> - Cancel running job</li>
                    <li><code>GET /api/logs</code> - Recent activity logs</li>
                    <li><code>POST /api/sync/attendance_device</code> - Sync to attendance device</li>
                </ul>
            </div>

            <div id="log-container">
                <h3>📝 Activity Log:</h3>
                <div class="log" id="activity-log">
                    Application started...\\n
                </div>
            </div>
        </div>

        <script>
            let logContainer = document.getElementById('activity-log');

            function log(message) {
                logContainer.textContent += new Date().toLocaleTimeString() + ' - ' + message + '\\n';
                logContainer.scrollTop = logContainer.scrollHeight;
            }

            function updateStatus(connected, deviceInfo) {
                const statusDiv = document.getElementById('scanner-status');
                const statusText = document.getElementById('status-text');

                if (connected) {
                    statusDiv.className = 'status connected';
                    statusText.textContent = deviceInfo;
                } else {
                    statusDiv.className = 'status disconnected';
                    statusText.textContent = deviceInfo || 'Not connected';
                }
            }

            function refreshStatus() {
                fetch('/api/scanner/status')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            updateStatus(data.status.connected, data.status.device_info);
                        } else {
                            log('Error: ' + data.message);
                        }
                    })
                    .catch(error => log('Error checking status: ' + error));
            }

            function initializeScanner() {
                log('Initializing scanner...');
                fetch('/api/scanner/initialize', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            log('Scanner initialized: ' + data.device_info);
                            refreshStatus();
                        } else {
                            log('Initialization failed: ' + data.message);
                        }
                    })
                    .catch(error => log('Error initializing: ' + error));
            }

            function disconnectScanner() {
                log('Disconnecting scanner...');
                fetch('/api/scanner/disconnect', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            log('Scanner disconnected');
                            refreshStatus();
                        } else {
                            log('Disconnect failed: ' + data.message);
                        }
                    })
                    .catch(error => log('Error disconnecting: ' + error));
            }

            function testEnrollment() {
                log('🧪 Starting test enrollment (Left Index)...');
                fetch('/api/fingerprint/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ finger_index: 3 })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        log('✅ Test completed: ' + data.message);
                        log('📊 Quality: ' + data.quality_score + '%, Size: ' + data.template_size + ' bytes');
                    } else {
                        log('❌ Test failed: ' + data.message);
                    }
                })
                .catch(error => log('❌ Test error: ' + error));
            }

            // Auto-refresh status every 5 seconds
            setInterval(refreshStatus, 5000);
            refreshStatus();
        </script>
    </body>
    </html>
    '''
    return render_template_string(html_template, port=DESKTOP_CONFIG['port'], version=VERSION)


def _port_in_use(host, port):
    """Check if something is already listening on host:port.

    On Windows two processes can silently bind the same port (SO_REUSEADDR),
    with browser traffic still going to the OLD process — so we must detect
    an existing instance ourselves instead of relying on a bind error.
    """
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def start_desktop_app():
    """Start the desktop bridge application"""
    if _port_in_use(DESKTOP_CONFIG['host'], DESKTOP_CONFIG['port']):
        print("=" * 50)
        print(f"❌ Port {DESKTOP_CONFIG['port']} is already in use!")
        print("   Another Fingerprint Scanner Bridge is still running on this machine.")
        print("   → Close it first (Task Manager: 'Fingerprint Scanner.exe' /")
        print("     'Fingerprint Scanner Bridge.exe'), then start this app again.")
        print("=" * 50)
        try:
            input("Press Enter to exit...")
        except Exception:
            time.sleep(10)
        return

    print(f"🚀 Starting Fingerprint Scanner Desktop Bridge v{VERSION}")
    print("=" * 50)
    print(f"🌐 Server running on: http://{DESKTOP_CONFIG['host']}:{DESKTOP_CONFIG['port']}")
    print(f"📡 API Base URL: http://{DESKTOP_CONFIG['host']}:{DESKTOP_CONFIG['port']}/api")
    print(f"🔒 Allowed origins: {ALLOWED_ORIGINS}")
    print("=" * 50)

    # Idle auto-disconnect watchdog
    threading.Thread(target=_idle_watchdog, daemon=True).start()

    # Open browser automatically (if enabled)
    if DESKTOP_CONFIG.get('auto_open_browser', False):
        def open_browser():
            time.sleep(1.5)
            webbrowser.open(f"http://{DESKTOP_CONFIG['host']}:{DESKTOP_CONFIG['port']}")

        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()
        print("🌐 Browser will open automatically...")

    # Start Flask server (threaded: SSE streams + API calls run concurrently)
    try:
        app.run(
            host=DESKTOP_CONFIG['host'],
            port=DESKTOP_CONFIG['port'],
            debug=DESKTOP_CONFIG['debug'],
            use_reloader=False,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Desktop Bridge stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")


if __name__ == "__main__":
    start_desktop_app()
