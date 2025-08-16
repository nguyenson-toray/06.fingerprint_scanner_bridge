# -*- coding: utf-8 -*-
"""
Desktop Bridge App - Local HTTP Server
Chạy trên máy tính user để làm cầu nối giữa ERPNext Web UI và Scanner
"""

import json
import logging
import base64
import ctypes
import time
from typing import Optional, Dict, Any
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import threading
import webbrowser
import sys
import os

# Import scanner module
from functions_fingerprint_scanner import FingerprintScanner, SCANNER_CONFIG, get_finger_name

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for web browser access

# Global scanner instance
scanner = None
scanner_status = {"connected": False, "device_info": "Not connected"}

# Global log storage
app_logs = []
MAX_LOGS = 100

class DesktopBridgeLogger:
    """Custom logger để capture logs cho web UI"""
    
    @staticmethod
    def log(level, message):
        """Add log entry"""
        import time
        import sys
        timestamp = time.strftime("%H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "message": message
        }
        app_logs.append(log_entry)
        
        # Keep only latest logs
        if len(app_logs) > MAX_LOGS:
            app_logs.pop(0)
        
        # Also log to console with immediate flush (if console available)
        try:
            print(f"[{timestamp}] {level.upper()}: {message}")
            if sys.stdout:
                sys.stdout.flush()  # Force immediate output
        except (AttributeError, OSError):
            # No console available (windowed exe), skip console output
            pass
    
    @staticmethod
    def info(message):
        # Handle structured data from scanner
        if isinstance(message, dict):
            if message.get("type") == "scan_attempt":
                attempt = message.get("attempt")
                total = message.get("total")
                status = message.get("status")
                display = message.get("display", f"LẦN {attempt}")
                scan_message = message.get("message", "")
                
                # Log the large attempt number
                DesktopBridgeLogger.log("info", f"{display}")
                if scan_message:
                    DesktopBridgeLogger.log(status, scan_message)
            elif message.get("type") == "enrollment_complete":
                finger_name = message.get("finger_name")
                scans = message.get("scans", [])
                final_quality = message.get("final_quality", 0)
                
                DesktopBridgeLogger.log("success", f"🎉 ENROLLMENT COMPLETED: {finger_name}")
                for scan in scans:
                    DesktopBridgeLogger.log("success", f"✅ LẦN {scan['attempt']}: Quality {scan['quality']}% ({scan['size']} bytes)")
                DesktopBridgeLogger.log("success", f"🏆 FINAL QUALITY: {final_quality}%")
            else:
                DesktopBridgeLogger.log("info", str(message))
        else:
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

# Initialize logs
DesktopBridgeLogger.info("Desktop Bridge starting...")

# Desktop app configuration
DESKTOP_CONFIG = {
    "host": "127.0.0.1",
    "port": 8080,
    "debug": False,
    "auto_open_browser": False  # Default: do not auto-open browser
}

@app.route('/api/test', methods=['GET'])
def test_connection():
    """Test API connection"""
    DesktopBridgeLogger.info("API test connection requested")
    return jsonify({
        "success": True,
        "message": "Desktop Bridge API is running",
        "version": "1.0.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get recent logs"""
    return jsonify({
        "success": True,
        "logs": app_logs[-50:],  # Return last 50 logs
        "total_logs": len(app_logs)
    })

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Clear logs"""
    global app_logs
    app_logs = []
    DesktopBridgeLogger.info("Logs cleared")
    return jsonify({
        "success": True,
        "message": "Logs cleared successfully"
    })

@app.route('/api/scanner/status', methods=['GET'])
def get_scanner_status():
    """Get scanner status"""
    global scanner, scanner_status
    
    try:
        if scanner and scanner.is_connected:
            scanner_status = {
                "connected": True,
                "device_info": f"{SCANNER_CONFIG['model']} - USB Connected ({scanner.img_width}x{scanner.img_height})"
            }
        else:
            scanner_status = {
                "connected": False,
                "device_info": "Scanner not connected"
            }
        
        return jsonify({
            "success": True,
            "status": scanner_status
        })
    except Exception as e:
        logger.error(f"Error getting scanner status: {e}")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        })

@app.route('/api/scanner/initialize', methods=['POST'])
def initialize_scanner():
    """Initialize scanner"""
    global scanner, scanner_status
    
    try:
        DesktopBridgeLogger.info("Initializing scanner...")
        scanner = FingerprintScanner(ui_logger=DesktopBridgeLogger)
        
        if scanner.connect():
            scanner_status = {
                "connected": True,
                "device_info": f"{SCANNER_CONFIG['model']} - USB Connected ({scanner.img_width}x{scanner.img_height})"
            }
            
            DesktopBridgeLogger.success(f"Scanner connected: {scanner.img_width}x{scanner.img_height}")
            return jsonify({
                "success": True,
                "message": "Scanner initialized successfully",
                "device_info": scanner_status["device_info"]
            })
        else:
            scanner_status = {
                "connected": False,
                "device_info": "Failed to connect"
            }
            
            DesktopBridgeLogger.error("Failed to connect to scanner")
            return jsonify({
                "success": False,
                "message": "Could not connect to scanner"
            })
            
    except Exception as e:
        DesktopBridgeLogger.error(f"Error initializing scanner: {e}")
        return jsonify({
            "success": False,
            "message": f"Error initializing scanner: {str(e)}"
        })

@app.route('/api/scanner/disconnect', methods=['POST'])
def disconnect_scanner():
    """Disconnect scanner"""
    global scanner, scanner_status
    
    try:
        if scanner:
            scanner.disconnect()
            scanner = None
            
        scanner_status = {
            "connected": False,
            "device_info": "Disconnected"
        }
        
        logger.info("Scanner disconnected")
        return jsonify({
            "success": True,
            "message": "Scanner disconnected successfully"
        })
        
    except Exception as e:
        logger.error(f"Error disconnecting scanner: {e}")
        return jsonify({
            "success": False,
            "message": f"Error disconnecting scanner: {str(e)}"
        })

@app.route('/api/logs/since', methods=['GET'])
def get_logs_since():
    """Get logs since specific timestamp"""
    global app_logs
    
    since = request.args.get('since', '')
    
    if not since:
        return jsonify({
            "success": True,
            "logs": app_logs[-5:] if len(app_logs) > 5 else app_logs
        })
    
    # Filter logs since timestamp
    filtered_logs = []
    for log in app_logs:
        if log['timestamp'] > since:
            filtered_logs.append(log)
    
    return jsonify({
        "success": True,
        "logs": filtered_logs
    })

@app.route('/api/fingerprint/test', methods=['POST'])
def test_fingerprint_enrollment():
    """Test endpoint to demonstrate 3-scan enrollment process"""
    global scanner
    
    try:
        data = request.get_json()
        finger_index = int(data.get('finger_index', 1))  # Default to index finger
        
        if not scanner or not scanner.is_connected:
            return jsonify({
                "success": False,
                "message": "Scanner not connected"
            })
        
        finger_name = get_finger_name(finger_index)
        DesktopBridgeLogger.info(f"🧪 TEST MODE: Starting 3-scan enrollment for {finger_name}")
        DesktopBridgeLogger.info("This will demonstrate the 3-scan process with colored indicators")
        
        # Perform enrollment with detailed logging
        template_data = scanner.enroll_fingerprint(finger_index)
        
        if template_data:
            quality_score = scanner._calculate_quality_score(template_data)
            template_b64 = base64.b64encode(template_data).decode('utf-8')
            
            return jsonify({
                "success": True,
                "message": f"Test enrollment completed for {finger_name}",
                "template_data": template_b64,
                "template_size": len(template_data),
                "finger_index": finger_index,
                "quality_score": quality_score,
                "finger_name": finger_name
            })
        else:
            return jsonify({
                "success": False,
                "message": "Test enrollment failed"
            })
            
    except Exception as e:
        DesktopBridgeLogger.error(f"Test enrollment error: {e}")
        return jsonify({
            "success": False,
            "message": f"Test error: {str(e)}"
        })

@app.route('/api/fingerprint/capture', methods=['POST'])
def capture_fingerprint():
    """Capture fingerprint"""
    global scanner
    
    try:
        data = request.get_json()
        finger_index = int(data.get('finger_index', 0))
        employee_id = data.get('employee_id')
        
        if not scanner or not scanner.is_connected:
            return jsonify({
                "success": False,
                "message": "Scanner not connected"
            })
        
        if finger_index < 0 or finger_index > 9:
            return jsonify({
                "success": False,
                "message": "Invalid finger index (0-9)"
            })
        
        finger_name = get_finger_name(finger_index)
        DesktopBridgeLogger.info(f"Starting enrollment for employee {employee_id}, {finger_name} (Index: {finger_index})")
        DesktopBridgeLogger.info("📷 This will require 3 fingerprint scans for optimal quality")
        
        # Capture fingerprint using 3-scan enrollment process
        template_data = scanner.enroll_fingerprint(finger_index)
        
        if template_data:
            # Encode to base64
            template_b64 = base64.b64encode(template_data).decode('utf-8')
            
            # Calculate quality score
            quality_score = scanner._calculate_quality_score(template_data)
            
            DesktopBridgeLogger.success(f"Fingerprint captured successfully: {len(template_data)} bytes, Quality: {quality_score}%")
            
            return jsonify({
                "success": True,
                "message": "Fingerprint captured successfully",
                "template_data": template_b64,
                "template_size": len(template_data),
                "finger_index": finger_index,
                "quality_score": quality_score,
                "quality": quality_score  # Alternative property name
            })
        else:
            logger.error("Failed to capture fingerprint")
            return jsonify({
                "success": False,
                "message": "Failed to capture fingerprint. Please try again."
            })
            
    except Exception as e:
        logger.error(f"Error capturing fingerprint: {e}")
        return jsonify({
            "success": False,
            "message": f"Error capturing fingerprint: {str(e)}"
        })

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
                    except:
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
                                except:
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

@app.route('/')
def index():
    """Main page with status and controls"""
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fingerprint Scanner Desktop Bridge</title>
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
                <p>Local bridge application running on port {{ port }}</p>
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
                <button class="button info" onclick="testEnrollment()">🧪 Test 3-Scan Enrollment</button>
            </div>
            
            <div class="info">
                <h3>📋 Usage Instructions:</h3>
                <ol>
                    <li>Make sure your ZKTeco fingerprint scanner is connected via USB</li>
                    <li>Ensure libzkfp.dll is available in system PATH or current directory</li>
                    <li>Click "Initialize Scanner" to connect</li>
                    <li>Use ERPNext web interface to capture fingerprints</li>
                    <li>This application will bridge the communication between web and hardware</li>
                </ol>
            </div>
            
            <div class="info">
                <h3>🌐 API Endpoints:</h3>
                <ul>
                    <li><code>GET /api/test</code> - Test connection</li>
                    <li><code>GET /api/scanner/status</code> - Get scanner status</li>
                    <li><code>POST /api/scanner/initialize</code> - Initialize scanner</li>
                    <li><code>POST /api/scanner/disconnect</code> - Disconnect scanner</li>
                    <li><code>POST /api/fingerprint/capture</code> - Capture fingerprint (3-scan enrollment)</li>
                    <li><code>POST /api/fingerprint/test</code> - Test 3-scan enrollment process</li>
                    <li><code>GET /api/logs</code> - Get recent activity logs</li>
                    <li><code>GET /api/logs/since?since=timestamp</code> - Get logs since timestamp</li>
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
                log('Checking scanner status...');
                fetch('/api/scanner/status')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            updateStatus(data.status.connected, data.status.device_info);
                            log('Status updated: ' + data.status.device_info);
                        } else {
                            log('Error: ' + data.message);
                        }
                    })
                    .catch(error => {
                        log('Error checking status: ' + error);
                    });
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
                    .catch(error => {
                        log('Error initializing: ' + error);
                    });
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
                    .catch(error => {
                        log('Error disconnecting: ' + error);
                    });
            }
            
            function testEnrollment() {
                log('🧪 Starting test enrollment process...');
                fetch('/api/fingerprint/test', { 
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        finger_index: 1  // Test with left index finger
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        log(`✅ Test completed: ${data.message}`);
                        log(`📊 Quality: ${data.quality_score}%, Size: ${data.template_size} bytes`);
                    } else {
                        log(`❌ Test failed: ${data.message}`);
                    }
                })
                .catch(error => {
                    log('❌ Test error: ' + error);
                });
            }
            
            // Auto-refresh status every 5 seconds
            setInterval(refreshStatus, 5000);
            
            // Initial status check
            refreshStatus();
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html_template, port=DESKTOP_CONFIG['port'])

def start_desktop_app():
    """Start the desktop bridge application"""
    print("🚀 Starting Fingerprint Scanner Desktop Bridge")
    print("=" * 50)
    print(f"🌐 Server running on: http://{DESKTOP_CONFIG['host']}:{DESKTOP_CONFIG['port']}")
    print(f"📡 API Base URL: http://{DESKTOP_CONFIG['host']}:{DESKTOP_CONFIG['port']}/api")
    print("=" * 50)
    
    # Open browser automatically (if enabled)
    if DESKTOP_CONFIG.get('auto_open_browser', False):
        def open_browser():
            time.sleep(1.5)  # Wait for server to start
            webbrowser.open(f"http://{DESKTOP_CONFIG['host']}:{DESKTOP_CONFIG['port']}")
        
        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()
        print("🌐 Browser will open automatically...")
    else:
        print("💻 Browser auto-open disabled. Visit the URL manually if needed.")
    
    # Start Flask server
    try:
        app.run(
            host=DESKTOP_CONFIG['host'],
            port=DESKTOP_CONFIG['port'],
            debug=DESKTOP_CONFIG['debug'],
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n🛑 Desktop Bridge stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

if __name__ == "__main__":
    start_desktop_app()