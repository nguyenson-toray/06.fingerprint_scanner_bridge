# -*- coding: utf-8 -*-
"""
Fingerprint scanning logic (ZKTeco / libzkfp.dll)

v2.0 changes:
- Event-driven enrollment: emits structured events via event_callback
  (consumed by the HTTP bridge and streamed to the web UI over SSE).
- Per-scan retry: a low-quality scan retries that attempt instead of
  failing the whole 3-scan enrollment.
- Cross-scan consistency check with ZKFPM_DBMatch: rejects a scan that
  does not match the first scan (user switched finger).
- Finger-lift detection between scans: waits until the sensor is empty
  before starting the next scan (better template diversity, no fixed sleeps).
- Cancellation support via threading.Event.
"""
import sys, os
import logging
import ctypes
import time
import base64
from typing import Optional

logger = logging.getLogger(__name__)

# Cấu hình mặc định
SCANNER_CONFIG = {
    'model': 'ZKTeco Scanner',
    'timeout': 30,              # seconds to wait for a finger per scan
    'dll_path': 'libzkfp.dll'
}

FINGERPRINT_CONFIG = {
    'scan_count': 3,
    'quality_threshold': 45,    # heuristic score 0-100, see _calculate_quality_score
    'min_template_size': 200,   # bytes; smaller usually means a partial capture
    'match_threshold': 45,      # min ZKFPM_DBMatch score between scans of the same finger
    'max_retries_per_scan': 2,  # extra attempts allowed per scan before failing enrollment
    'template_size': 2048,
    'finger_lift_seconds': 0.6, # sensor must be empty this long to count as "finger lifted"
    'finger_lift_max_wait': 15, # give up waiting for lift after this many seconds
}

# Error codes for compact logging
ERROR_CODES = {
    # Connection errors (1xxx)
    1001: "DLL_NOT_FOUND",
    1002: "SDK_INIT_FAILED",
    1003: "NO_DEVICE_FOUND",
    1004: "DEVICE_OPEN_FAILED",
    1005: "DB_CACHE_FAILED",
    1006: "DEVICE_DISCONNECTED",

    # Scan errors (2xxx)
    2001: "SCAN_TIMEOUT",
    2002: "SCAN_ERROR",
    2003: "QUALITY_LOW",
    2004: "TEMPLATE_INVALID",
    2005: "SCAN_MISMATCH",
    2006: "CANCELLED",

    # Process errors (3xxx)
    3001: "MERGE_FAILED",
    3002: "BUFFER_OVERFLOW",
    3003: "INVALID_FINGER_INDEX",

    # Success codes (1-4)
    1: "CONNECTED",
    2: "SCAN_SUCCESS",
    3: "ENROLLMENT_COMPLETE",
    4: "DISCONNECTED"
}


class EnrollmentCancelled(Exception):
    """Raised when the enrollment job is cancelled by the client."""
    pass


class TZKFPCapParams(ctypes.Structure):
    """Cấu trúc tham số quét vân tay"""
    _fields_ = [
        ("imgWidth", ctypes.c_uint),
        ("imgHeight", ctypes.c_uint),
        ("nDPI", ctypes.c_uint)
    ]


class FingerprintScanner:
    """Lớp quản lý kết nối và quét vân tay sử dụng libzkfp.dll"""

    def __init__(self, event_callback=None):
        self.zkfp = None
        self.handle = None
        self.hDBCache = None
        self.is_connected = False
        self.img_width = 0
        self.img_height = 0
        self.template_buf_size = FINGERPRINT_CONFIG.get('template_size', 2048)
        self.merge_count = FINGERPRINT_CONFIG.get('scan_count', 3)
        # Called with a dict {"type": ..., ...} for every enrollment event
        self.event_callback = event_callback

    # ------------------------------------------------------------------ events

    def _emit(self, event_type, **payload):
        payload['type'] = event_type
        if self.event_callback:
            try:
                self.event_callback(payload)
            except Exception as e:
                logger.warning(f"event_callback error: {e}")
        # Compact console/log trace
        trace = {k: v for k, v in payload.items() if k != 'type'}
        logger.info(f"EVT:{event_type}:{trace}")

    @staticmethod
    def _check_cancel(cancel_event):
        if cancel_event is not None and cancel_event.is_set():
            raise EnrollmentCancelled()

    # ------------------------------------------------------------------ quality

    def _calculate_quality_score(self, template_data: bytes) -> int:
        """Heuristic quality score (0-100) from template size and data density.

        Note: libzkfp does not expose a per-image quality value through
        ZKFPM_AcquireFingerprint, so this is a proxy. The real quality gate
        is the cross-scan ZKFPM_DBMatch consistency check in enroll_fingerprint.
        """
        if not template_data:
            return 0

        template_size = len(template_data)
        non_zero_bytes = sum(1 for byte in template_data if byte != 0)

        if template_size == 0:
            return 0

        density_ratio = non_zero_bytes / template_size
        size_factor = min(template_size / 500, 1.0)

        quality_score = int((density_ratio * size_factor) * 100)
        return min(quality_score, 100)

    def match_templates(self, template1: bytes, template2: bytes) -> int:
        """Match two templates with ZKFPM_DBMatch. Returns score, or -1 on error."""
        if not (self.zkfp and self.hDBCache and template1 and template2):
            return -1
        try:
            buf1 = (ctypes.c_ubyte * len(template1))(*template1)
            buf2 = (ctypes.c_ubyte * len(template2))(*template2)
            score = self.zkfp.ZKFPM_DBMatch(
                self.hDBCache, buf1, len(template1), buf2, len(template2))
            return int(score)
        except Exception as e:
            logger.warning(f"DBMatch error: {e}")
            return -1

    # ------------------------------------------------------------------ connect

    def connect(self) -> bool:
        """Kết nối với thiết bị scanner vân tay"""
        # Force cleanup any existing connections first
        if self.is_connected:
            self.disconnect()
            time.sleep(0.5)  # Give time for cleanup

        # Always cleanup before attempting new connection
        self._cleanup()
        time.sleep(0.2)  # Brief delay for resource cleanup

        try:
            # Load DLL with priority order
            try:
                dll_loaded = False
                searched_paths = []

                # Priority 1: C:\Windows\SysWOW64 (default folder when installing driver)
                syswow64_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'SysWOW64', 'libzkfp.dll')
                searched_paths.append(f"1. SysWOW64: {syswow64_path}")
                if os.path.exists(syswow64_path):
                    try:
                        self.zkfp = ctypes.CDLL(syswow64_path)
                        logger.info(f"DLL:SysWOW64:{syswow64_path}")
                        dll_loaded = True
                    except Exception as e:
                        logger.warning(f"Failed to load from SysWOW64: {e}")

                # Priority 2: Executable directory (same folder as exe when frozen)
                if not dll_loaded:
                    if getattr(sys, 'frozen', False):
                        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
                    else:
                        exe_dir = os.path.dirname(os.path.abspath(__file__))
                    exe_dir_path = os.path.join(exe_dir, "libzkfp.dll")

                    searched_paths.append(f"2. Executable dir: {exe_dir_path}")
                    if os.path.exists(exe_dir_path):
                        try:
                            self.zkfp = ctypes.CDLL(os.path.abspath(exe_dir_path))
                            logger.info(f"DLL:ExeDir:{exe_dir_path}")
                            dll_loaded = True
                        except Exception as e:
                            logger.warning(f"Failed to load from executable directory: {e}")

                # Priority 3: Current working directory
                if not dll_loaded:
                    current_dir_path = os.path.join(os.getcwd(), "libzkfp.dll")
                    searched_paths.append(f"3. Current dir: {current_dir_path}")
                    if os.path.exists(current_dir_path):
                        try:
                            self.zkfp = ctypes.CDLL(os.path.abspath(current_dir_path))
                            logger.info(f"DLL:CurDir:{current_dir_path}")
                            dll_loaded = True
                        except Exception as e:
                            logger.warning(f"Failed to load from current directory: {e}")

                # Priority 4: Use SCANNER_CONFIG['dll_path'] (fallback)
                if not dll_loaded:
                    dll_path = SCANNER_CONFIG.get("dll_path", "libzkfp.dll")
                    searched_paths.append(f"4. Config path: {dll_path}")
                    try:
                        self.zkfp = ctypes.windll.LoadLibrary(dll_path)
                        logger.info(f"DLL:Config:windll:{dll_path}")
                        dll_loaded = True
                    except Exception as e1:
                        try:
                            self.zkfp = ctypes.CDLL(dll_path)
                            logger.info(f"DLL:Config:CDLL:{dll_path}")
                            dll_loaded = True
                        except Exception as e2:
                            logger.warning(f"Failed to load using SCANNER_CONFIG (windll): {e1}")
                            logger.warning(f"Failed to load using SCANNER_CONFIG (CDLL): {e2}")

                if not dll_loaded:
                    logger.error("Could not load libzkfp.dll from any location")
                    for path in searched_paths:
                        logger.error(f"   {path}")
                    raise Exception("Could not load libzkfp.dll from any location")

            except Exception as e:
                logger.error(f"DLL:ERR:{str(e)[:50]}")
                return False

            # Khai báo hàm
            self._declare_functions()

            # Khởi tạo SDK với retry logic
            init_attempts = 3
            for attempt in range(init_attempts):
                try:
                    init_result = self.zkfp.ZKFPM_Init()
                    if init_result == 0:
                        break
                    logger.warning(f"SDK Init attempt {attempt + 1} failed with code: {init_result}")
                    if attempt < init_attempts - 1:
                        time.sleep(0.5)
                        try:
                            self.zkfp.ZKFPM_Terminate()
                        except Exception:
                            pass
                        time.sleep(0.3)
                except Exception as e:
                    logger.warning(f"SDK Init attempt {attempt + 1} exception: {e}")
                    if attempt < init_attempts - 1:
                        time.sleep(0.5)
            else:
                logger.error("SDK:INIT:FAIL:1002")
                return False

            # Kiểm tra số thiết bị
            device_count = self.zkfp.ZKFPM_GetDeviceCount()
            if device_count == 0:
                logger.error("DEV:NOT_FOUND:1003")
                self.zkfp.ZKFPM_Terminate()
                return False

            # Mở thiết bị đầu tiên
            self.handle = self.zkfp.ZKFPM_OpenDevice(0)
            if not self.handle:
                logger.error("DEV:OPEN:FAIL:1004")
                self.zkfp.ZKFPM_Terminate()
                return False

            # Lấy thông số thiết bị
            params = TZKFPCapParams()
            if self.zkfp.ZKFPM_GetCaptureParams(self.handle, ctypes.byref(params)) == 0:
                self.img_width = params.imgWidth
                self.img_height = params.imgHeight

            # Khởi tạo DB Cache cho merge/match
            self.hDBCache = self.zkfp.ZKFPM_DBInit()
            if not self.hDBCache:
                logger.error("DB:CACHE:FAIL:1005")
                self.zkfp.ZKFPM_CloseDevice(self.handle)
                self.zkfp.ZKFPM_Terminate()
                return False

            self.is_connected = True
            logger.info(f"CONN:{self.img_width}x{self.img_height}:1")
            return True

        except Exception as e:
            logger.error(f"CONN:ERR:{str(e)[:50]}")
            self._cleanup()
            return False

    def _declare_functions(self):
        """Khai báo các hàm DLL"""
        self.zkfp.ZKFPM_Init.restype = ctypes.c_int
        self.zkfp.ZKFPM_Terminate.restype = ctypes.c_int
        self.zkfp.ZKFPM_GetDeviceCount.restype = ctypes.c_int

        self.zkfp.ZKFPM_OpenDevice.argtypes = [ctypes.c_int]
        self.zkfp.ZKFPM_OpenDevice.restype = ctypes.c_void_p

        self.zkfp.ZKFPM_CloseDevice.argtypes = [ctypes.c_void_p]
        self.zkfp.ZKFPM_CloseDevice.restype = ctypes.c_int

        self.zkfp.ZKFPM_GetCaptureParams.argtypes = [ctypes.c_void_p, ctypes.POINTER(TZKFPCapParams)]
        self.zkfp.ZKFPM_GetCaptureParams.restype = ctypes.c_int

        self.zkfp.ZKFPM_AcquireFingerprint.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint)
        ]
        self.zkfp.ZKFPM_AcquireFingerprint.restype = ctypes.c_int

        # DB cache functions (merge + match)
        self.zkfp.ZKFPM_DBInit.restype = ctypes.c_void_p

        self.zkfp.ZKFPM_DBMerge.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint)
        ]
        self.zkfp.ZKFPM_DBMerge.restype = ctypes.c_int

        self.zkfp.ZKFPM_DBMatch.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint
        ]
        self.zkfp.ZKFPM_DBMatch.restype = ctypes.c_int

        self.zkfp.ZKFPM_DBFree.argtypes = [ctypes.c_void_p]
        self.zkfp.ZKFPM_DBFree.restype = ctypes.c_int

    def disconnect(self):
        """Ngắt kết nối thiết bị scanner"""
        if self.is_connected:
            try:
                self._cleanup()
                self.is_connected = False
                logger.info("DISC:4")
                return True
            except Exception as e:
                logger.error(f"DISC:ERR:{str(e)[:50]}")
                return False
        return True

    def _cleanup(self):
        """Dọn dẹp tài nguyên với error handling"""
        try:
            if self.hDBCache and self.zkfp:
                try:
                    self.zkfp.ZKFPM_DBFree(self.hDBCache)
                except Exception as e:
                    logger.warning(f"Error freeing DB cache: {e}")
                self.hDBCache = None

            if self.handle and self.zkfp:
                try:
                    self.zkfp.ZKFPM_CloseDevice(self.handle)
                except Exception as e:
                    logger.warning(f"Error closing device: {e}")
                self.handle = None

            if self.zkfp:
                try:
                    self.zkfp.ZKFPM_Terminate()
                except Exception as e:
                    logger.warning(f"Error terminating SDK: {e}")

        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")

        self.is_connected = False
        self.hDBCache = None
        self.handle = None

    def health_check(self) -> bool:
        """Quick check that the device is still present, reconnect if not."""
        if not (self.is_connected and self.zkfp):
            return False
        try:
            if self.zkfp.ZKFPM_GetDeviceCount() > 0:
                return True
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
        # Device vanished — try one reconnect
        self.is_connected = False
        return self.connect()

    # ------------------------------------------------------------------ capture

    def _acquire_once(self, timeout=None, cancel_event=None) -> Optional[bytes]:
        """Poll the sensor until one fingerprint is captured or timeout."""
        timeout = timeout or SCANNER_CONFIG.get('timeout', 30)
        image_buf = (ctypes.c_ubyte * (self.img_width * self.img_height))()
        template_buf = (ctypes.c_ubyte * self.template_buf_size)()
        template_len = ctypes.c_uint(self.template_buf_size)

        start = time.time()
        while time.time() - start < timeout:
            self._check_cancel(cancel_event)
            template_len.value = self.template_buf_size  # reset buffer size each attempt
            ret = self.zkfp.ZKFPM_AcquireFingerprint(
                self.handle,
                image_buf,
                self.img_width * self.img_height,
                template_buf,
                ctypes.byref(template_len)
            )
            if ret == 0:
                return bytes(template_buf[:template_len.value])
            time.sleep(0.05)
        return None

    def wait_finger_lift(self, cancel_event=None) -> bool:
        """Block until the sensor has been empty for finger_lift_seconds.

        Prevents the next scan from instantly re-capturing the same placement,
        which is the main cause of poor merged templates.
        """
        lift_seconds = FINGERPRINT_CONFIG.get('finger_lift_seconds', 0.6)
        max_wait = FINGERPRINT_CONFIG.get('finger_lift_max_wait', 15)

        image_buf = (ctypes.c_ubyte * (self.img_width * self.img_height))()
        template_buf = (ctypes.c_ubyte * self.template_buf_size)()
        template_len = ctypes.c_uint(self.template_buf_size)

        start = time.time()
        last_present = time.time()
        while time.time() - start < max_wait:
            self._check_cancel(cancel_event)
            template_len.value = self.template_buf_size
            ret = self.zkfp.ZKFPM_AcquireFingerprint(
                self.handle,
                image_buf,
                self.img_width * self.img_height,
                template_buf,
                ctypes.byref(template_len)
            )
            if ret == 0:
                last_present = time.time()   # finger still on sensor
            elif time.time() - last_present >= lift_seconds:
                return True
            time.sleep(0.05)
        return False  # proceed anyway after max_wait

    def enroll_fingerprint(self, finger_index: int, cancel_event=None) -> Optional[bytes]:
        """3-scan enrollment with per-scan retry, match check and lift detection.

        Emits events through event_callback; returns the merged template or None.
        May raise EnrollmentCancelled.
        """
        if not self.health_check():
            self._emit('failed', code=1006, message='Scanner not connected')
            return None
        if not self.hDBCache:
            self._emit('failed', code=1005, message='DB cache not initialized')
            return None

        cfg = FINGERPRINT_CONFIG
        finger_name = get_finger_name(finger_index)
        self._emit('job_started', finger_index=finger_index,
                   finger_name=finger_name, total=self.merge_count)

        collected = []
        quality = 0
        for attempt in range(1, self.merge_count + 1):
            retries_left = cfg.get('max_retries_per_scan', 2)
            while True:
                self._check_cancel(cancel_event)
                self._emit('scan_waiting', attempt=attempt, total=self.merge_count)

                template = self._acquire_once(cancel_event=cancel_event)
                if template is None:
                    self._emit('failed', code=2001, message='Scan timeout')
                    return None

                quality = self._calculate_quality_score(template)
                problem = None
                if len(template) < cfg.get('min_template_size', 200) or \
                        quality < cfg.get('quality_threshold', 45):
                    problem = (2003, f'Low quality (Q{quality})')
                elif collected:
                    score = self.match_templates(collected[0], template)
                    if 0 <= score < cfg.get('match_threshold', 45):
                        problem = (2005, f'Does not match scan 1 (score {score})')

                if problem is None:
                    break

                if retries_left <= 0:
                    self._emit('failed', code=problem[0], message=problem[1])
                    return None
                retries_left -= 1
                self._emit('scan_retry', attempt=attempt, code=problem[0],
                           message=problem[1], retries_left=retries_left)
                self.wait_finger_lift(cancel_event)

            collected.append(template)
            self._emit('scan_success', attempt=attempt, total=self.merge_count,
                       quality=quality, size=len(template))

            if attempt < self.merge_count:
                self._emit('lift_finger', next_attempt=attempt + 1)
                self.wait_finger_lift(cancel_event)

        # Merge the 3 templates
        try:
            self._emit('merge_start')

            merged_template_buf = (ctypes.c_ubyte * self.template_buf_size)()
            merged_template_len = ctypes.c_uint(self.template_buf_size)

            templates_c = [(ctypes.c_ubyte * len(t))(*t) for t in collected]

            ret_merge = self.zkfp.ZKFPM_DBMerge(
                self.hDBCache,
                templates_c[0],
                templates_c[1],
                templates_c[2],
                merged_template_buf,
                ctypes.byref(merged_template_len)
            )

            if ret_merge == 0:
                final_template = bytes(merged_template_buf[:merged_template_len.value])
                logger.info(f"E:{finger_name}:Q{self._calculate_quality_score(final_template)}"
                            f":S{len(final_template)}")
                return final_template

            self._emit('failed', code=3001, message=f'Merge failed ({ret_merge})')
            return None

        except Exception as e:
            logger.error(f"M:{str(e)}")
            self._emit('failed', code=3001, message=f'Merge error: {str(e)[:80]}')
            return None


# Standard finger index mapping — MUST stay in sync with:
# - customize_erpnext/api/utilities.py (get_finger_name / get_finger_index)
# - fingerprint_scanner_dialog.js (data-finger buttons)
# 0..4 = left little -> left thumb, 5..9 = right thumb -> right little (ZKTeco convention)
def get_finger_name(finger_index):
    """Get finger name from index (standardized English names)"""
    finger_names = {
        0: "Left Little",
        1: "Left Ring",
        2: "Left Middle",
        3: "Left Index",
        4: "Left Thumb",
        5: "Right Thumb",
        6: "Right Index",
        7: "Right Middle",
        8: "Right Ring",
        9: "Right Little"
    }
    return finger_names.get(finger_index, f"Finger {finger_index}")


def get_finger_index(finger_name):
    """Get finger index from name"""
    finger_map = {
        'Left Little': 0, 'Left Ring': 1, 'Left Middle': 2, 'Left Index': 3, 'Left Thumb': 4,
        'Right Thumb': 5, 'Right Index': 6, 'Right Middle': 7, 'Right Ring': 8, 'Right Little': 9
    }
    return finger_map.get(finger_name, -1)


# Test mode
if __name__ == "__main__":
    print("🔍 Fingerprint Scanner Standalone Test (v2)")
    print("=" * 40)

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def print_event(evt):
        print(f"  EVENT: {evt}")

    scanner = FingerprintScanner(event_callback=print_event)

    if scanner.connect():
        print(f"✅ Scanner connected: {scanner.img_width}x{scanner.img_height}")

        if len(sys.argv) > 1 and sys.argv[1] == "test":
            print("\n🔍 Test mode - enrollment for finger index 3 (Left Index)...")
            template = scanner.enroll_fingerprint(3)

            if template:
                quality = scanner._calculate_quality_score(template)
                print(f"\n🎉 Template captured successfully!")
                print(f"📊 Final Quality Score: {quality}%")
                print(f"📏 Template Size: {len(template)} bytes")

                template_b64 = base64.b64encode(template).decode('utf-8')
                print(f"📋 Base64 (first 50 chars): {template_b64[:50]}...")

                with open('fingerprint_template.txt', 'w') as f:
                    f.write(template_b64)
                print("💾 Template saved to fingerprint_template.txt")
            else:
                print("❌ Failed to capture fingerprint")
        else:
            print("\nUsage: python functions_fingerprint_scanner.py test")

        scanner.disconnect()
    else:
        print("❌ Could not connect to scanner")
        print("\nChecklist:")
        print("- Scanner is connected via USB")
        print("- libzkfp.dll is available in system PATH or current directory")
        print("- No other application is using the scanner")
        print("- Driver is properly installed")
