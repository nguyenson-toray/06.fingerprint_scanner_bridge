# -*- coding: utf-8 -*-
"""
Chứa logic quét vân tay
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
    'timeout': 30,
    'dll_path': 'libzkfp.dll'
}

FINGERPRINT_CONFIG = {
    'scan_count': 3,
    'quality_threshold': 50,
    'template_size': 2048
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

class TZKFPCapParams(ctypes.Structure):
    """Cấu trúc tham số quét vân tay"""
    _fields_ = [
        ("imgWidth", ctypes.c_uint),
        ("imgHeight", ctypes.c_uint), 
        ("nDPI", ctypes.c_uint)
    ]

class FingerprintScanner:
    """Lớp quản lý kết nối và quét vân tay sử dụng libzkfp.dll"""
    
    def __init__(self, ui_logger=None):
        self.zkfp = None
        self.handle = None
        self.hDBCache = None
        self.is_connected = False
        self.img_width = 0
        self.img_height = 0
        self.template_buf_size = FINGERPRINT_CONFIG.get('template_size', 2048)
        self.merge_count = FINGERPRINT_CONFIG.get('scan_count', 3)
        self.ui_logger = ui_logger
    
    def _log(self, message, level="info"):
        if self.ui_logger:
            if hasattr(self.ui_logger, level):
                getattr(self.ui_logger, level)(message)
        else:
            print(message)
    
    def _log_scan_attempt(self, attempt_number, total_attempts, status="waiting", error_code=None, extra_data=None):
        """Optimized scan attempt logging with error codes"""
        # Map status to error codes
        status_codes = {
            "success": 2,
            "failure": 2001,
            "waiting": None,
            "in_progress": None
        }

        code = error_code or status_codes.get(status)

        if self.ui_logger:
            # Send compact structured data
            log_data = {
                "type": "scan",
                "attempt": attempt_number,
                "total": total_attempts,
                "status": status,
                "code": code
            }
            if extra_data:
                log_data.update(extra_data)
            self.ui_logger.info(log_data)

        # Minimal console output
        if code:
            print(f"[{attempt_number}/{total_attempts}] {code}: {ERROR_CODES.get(code, 'UNKNOWN')}")
        else:
            print(f"[{attempt_number}/{total_attempts}] {status.upper()}")

        # Compact logger entry
        if code:
            logger.info(f"S{attempt_number}/{total_attempts}:{code}")
        else:
            logger.info(f"S{attempt_number}/{total_attempts}:{status}")
    
    def _calculate_quality_score(self, template_data: bytes) -> int:
        """Calculate simple quality score based on template size and data density"""
        if not template_data:
            return 0
        
        # Basic quality calculation based on template size and non-zero bytes
        template_size = len(template_data)
        non_zero_bytes = sum(1 for byte in template_data if byte != 0)
        
        # Quality score calculation (0-100)
        if template_size == 0:
            return 0
        
        density_ratio = non_zero_bytes / template_size
        size_factor = min(template_size / 500, 1.0)  # Normalize by expected size
        
        quality_score = int((density_ratio * size_factor) * 100)
        return min(quality_score, 100)  # Cap at 100
    
    def _log_enrollment_summary(self, finger_name, templates, final_template, final_quality):
        """Compact enrollment summary with error codes"""
        if self.ui_logger:
            self.ui_logger.info({
                "type": "enrollment",
                "finger": finger_name,
                "scans": len(templates),
                "quality": final_quality,
                "size": len(final_template),
                "code": 3
            })

        print(f"ENROLLMENT COMPLETE: {finger_name} Q:{final_quality}% S:{len(final_template)}")
        logger.info(f"E:{finger_name}:{final_quality}:{len(final_template)}:3")
        

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
                dll_path = None
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
                        # Running as exe - get exe directory
                        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
                        exe_dir_path = os.path.join(exe_dir, "libzkfp.dll")
                    else:
                        # Running as script - get script directory  
                        exe_dir = os.path.dirname(os.path.abspath(__file__))
                        exe_dir_path = os.path.join(exe_dir, "libzkfp.dll")
                    
                    searched_paths.append(f"2. Executable dir: {exe_dir_path}")
                    if os.path.exists(exe_dir_path):
                        try:
                            # Use absolute path and CDLL for better compatibility with frozen exe
                            abs_exe_dir_path = os.path.abspath(exe_dir_path)
                            self.zkfp = ctypes.CDLL(abs_exe_dir_path)
                            logger.info(f"DLL:ExeDir:{abs_exe_dir_path}")
                            dll_loaded = True
                        except Exception as e:
                            logger.warning(f"Failed to load from executable directory: {e}")
                
                # Priority 3: Current working directory
                if not dll_loaded:
                    current_dir_path = os.path.join(os.getcwd(), "libzkfp.dll")
                    searched_paths.append(f"3. Current dir: {current_dir_path}")
                    if os.path.exists(current_dir_path):
                        try:
                            abs_current_path = os.path.abspath(current_dir_path)
                            self.zkfp = ctypes.CDLL(abs_current_path)
                            logger.info(f"DLL:CurDir:{abs_current_path}")
                            dll_loaded = True
                        except Exception as e:
                            logger.warning(f"Failed to load from current directory: {e}")
                
                # Priority 4: Use SCANNER_CONFIG['dll_path'] (fallback)
                if not dll_loaded:
                    dll_path = SCANNER_CONFIG.get("dll_path", "libzkfp.dll")
                    searched_paths.append(f"4. Config path: {dll_path}")
                    try:
                        # Try windll first (original method)
                        self.zkfp = ctypes.windll.LoadLibrary(dll_path)
                        logger.info(f"DLL:Config:windll:{dll_path}")
                        dll_loaded = True
                    except Exception as e1:
                        try:
                            # Try CDLL as fallback
                            self.zkfp = ctypes.CDLL(dll_path)
                            logger.info(f"DLL:Config:CDLL:{dll_path}")
                            dll_loaded = True
                        except Exception as e2:
                            logger.warning(f"Failed to load using SCANNER_CONFIG (windll): {e1}")
                            logger.warning(f"Failed to load using SCANNER_CONFIG (CDLL): {e2}")
                
                if not dll_loaded:
                    logger.error("❌ Could not load libzkfp.dll from any location")
                    logger.error("📁 Searched locations:")
                    for path in searched_paths:
                        logger.error(f"   {path}")
                    logger.error(f"🔍 Debug info:")
                    logger.error(f"   - sys.frozen: {getattr(sys, 'frozen', False)}")
                    logger.error(f"   - sys.executable: {sys.executable}")
                    logger.error(f"   - __file__: {__file__}")
                    logger.error(f"   - os.getcwd(): {os.getcwd()}")
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
                    else:
                        logger.warning(f"SDK Init attempt {attempt + 1} failed with code: {init_result}")
                        if attempt < init_attempts - 1:
                            time.sleep(0.5)  # Wait before retry
                            # Try terminate and re-init
                            try:
                                self.zkfp.ZKFPM_Terminate()
                            except:
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
            
            # Khởi tạo DB Cache cho merge
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
        # Hàm cơ bản
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
        
        # Hàm merge
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
        
        # Reset all state
        self.is_connected = False
        self.hDBCache = None
        self.handle = None
    
    def capture_fingerprint(self, finger_index: int, scan_number: int = 1) -> Optional[bytes]:
        """Capture fingerprint once with optimized performance"""
        if not self.is_connected or not self.zkfp or not self.handle:
            logger.error("SCAN:NO_CONN:1006")
            return None
            
        # Verify scanner is still responsive before capture
        try:
            device_count = self.zkfp.ZKFPM_GetDeviceCount()
            if device_count == 0:
                logger.warning("Scanner disconnected during operation, attempting reconnection...")
                self.is_connected = False
                if not self.connect():
                    logger.error("RECONN:FAIL:1006")
                    return None
        except Exception as e:
            logger.warning(f"Scanner health check failed: {e}, attempting reconnection...")
            self.is_connected = False
            if not self.connect():
                logger.error("RECONN:FAIL:1006")
                return None
            
        try:
            # Pre-allocate buffers for better performance
            image_buf = (ctypes.c_ubyte * (self.img_width * self.img_height))()
            template_buf = (ctypes.c_ubyte * self.template_buf_size)()
            template_len = ctypes.c_uint(self.template_buf_size)
            
            start_time = time.time()
            timeout = SCANNER_CONFIG.get('timeout', 30)  # Use config timeout
            
            # Show WAITING status BEFORE user places finger (for all scans)
            self._log_scan_attempt(scan_number, self.merge_count, "waiting")

            # Ensure waiting message is always visible for all scans
            if scan_number == 1:
                time.sleep(0.2)  # Normal delay for first scan
            elif scan_number == 2:
                time.sleep(0.5)  # Longer delay for second scan to ensure visibility
            else:  # scan_number == 3
                time.sleep(0.5)  # Longer delay for final scan
            
            # Optimized polling interval for faster response
            poll_interval = 0.03  # Further reduced for better performance
            
            while time.time() - start_time < timeout:
                ret = self.zkfp.ZKFPM_AcquireFingerprint(
                    self.handle,
                    image_buf,
                    self.img_width * self.img_height,
                    template_buf,
                    ctypes.byref(template_len)
                )
                
                if ret == 0:
                    template_data = bytes(template_buf[:template_len.value])
                    quality_score = self._calculate_quality_score(template_data)

                    # Log successful scan with quality data - make it more visible
                    self._log_scan_attempt(scan_number, self.merge_count, "success",
                                         2, {"quality": quality_score, "size": len(template_data)})

                    # Add a clear success message
                    self._log(f"✅ LẦN {scan_number} QUÉT THÀNH CÔNG! (Quality: {quality_score}%)")

                    # Extra delay for scan 3 to ensure success message is processed
                    if scan_number == 3:
                        time.sleep(0.3)

                    return template_data
                    
                time.sleep(poll_interval)
            
            # Log timeout failure
            self._log_scan_attempt(scan_number, self.merge_count, "failure", 2001)
            return None
            
        except Exception as e:
            # Log exception failure
            self._log_scan_attempt(scan_number, self.merge_count, "failure", 2002)
            logger.error(f"CF:{str(e)}")
            return None
    
    def enroll_fingerprint(self, finger_index: int) -> Optional[bytes]:
        """Enroll fingerprint with optimized 3-scan process"""
        if not self.is_connected or not self.zkfp or not self.handle:
            logger.error("ENROLL:NO_CONN:1006")
            return None
            
        if not self.hDBCache:
            logger.error("ENROLL:NO_CACHE:1005")
            return None
            
        collected_templates = []
        finger_name = get_finger_name(finger_index)
        
        self._log(f"🔄 Starting fingerprint enrollment process...")
        self._log(f"ENROLL:{finger_name}:{finger_index}")

        # Let capture_fingerprint handle all waiting messages

        # Minimal delay for UI synchronization
        time.sleep(0.1)
        
        # Collect 3 fingerprint samples with optimized timing
        for i in range(self.merge_count):
            
            template = self.capture_fingerprint(finger_index, i+1)
            if not template:
                return None
            
            collected_templates.append(template)

            if i < self.merge_count - 1:
                # Small delay to let success message display first
                time.sleep(0.3)
                self._log(f"✅ Sẵn sàng cho lần quét {i+2}/3")
                self._log("📋 Vui lòng nhấc tay ra, sau đó đặt lại khi thấy thông báo ĐANG ĐỢI QUÉT")
                time.sleep(1.5)  # Longer wait time to ensure user sees the waiting message
        
        # Merge templates with error handling
        try:
            self._log("MERGE:START")
            
            # Pre-allocate merge buffer
            merged_template_buf = (ctypes.c_ubyte * self.template_buf_size)()
            merged_template_len = ctypes.c_uint(self.template_buf_size)
            
            # Convert templates to ctypes arrays efficiently
            templates_c = []
            for template in collected_templates:
                template_c = (ctypes.c_ubyte * len(template))(*template)
                templates_c.append(template_c)
            
            # Perform merge operation
            ret_merge = self.zkfp.ZKFPM_DBMerge(
                self.hDBCache,
                templates_c[0],
                templates_c[1], 
                templates_c[2],
                merged_template_buf,
                ctypes.byref(merged_template_len)
            )
            
            if ret_merge == 0:
                final_template_data = bytes(merged_template_buf[:merged_template_len.value])
                final_quality = self._calculate_quality_score(final_template_data)
                
                # Show enrollment success summary
                self._log_enrollment_summary(finger_name, collected_templates, final_template_data, final_quality)
                return final_template_data
            else:
                self._log(f"Merge failed: {ret_merge}", "error")
                return None
                
        except Exception as e:
            logger.error(f"M:{str(e)}")
            self._log(f"Merge error: {str(e)}", "error")
            return None

def get_finger_name(finger_index):
    """Get finger name from index (standardized English names)"""
    finger_names = {
        0: "Left Thumb",
        1: "Left Index", 
        2: "Left Middle",
        3: "Left Ring",
        4: "Left Little",
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
        'Left Thumb': 0, 'Left Index': 1, 'Left Middle': 2, 'Left Ring': 3, 'Left Little': 4,
        'Right Thumb': 5, 'Right Index': 6, 'Right Middle': 7, 'Right Ring': 8, 'Right Little': 9
    }
    return finger_map.get(finger_name, -1)

# Test mode
if __name__ == "__main__":
    import sys
    
    print("🔍 Fingerprint Scanner Standalone Test")
    print("=" * 40)
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    scanner = FingerprintScanner()
    
    if scanner.connect():
        print(f"✅ Scanner connected: {scanner.img_width}x{scanner.img_height}")
        
        if len(sys.argv) > 1 and sys.argv[1] == "test":
            # Test capture with colored indicators
            print("\n🔍 Test mode - Enhanced enrollment for finger index 1 (Left Index)...")
            print("This will demonstrate the new colored scan attempt indicators")
            
            template = scanner.enroll_fingerprint(1)
            
            if template:
                quality = scanner._calculate_quality_score(template)
                print(f"\n🎉 Template captured successfully!")
                print(f"📊 Final Quality Score: {quality}%")
                print(f"📏 Template Size: {len(template)} bytes")
                
                template_b64 = base64.b64encode(template).decode('utf-8')
                print(f"📋 Base64 (first 50 chars): {template_b64[:50]}...")
                
                # Save to file
                with open('fingerprint_template.txt', 'w') as f:
                    f.write(template_b64)
                print("💾 Template saved to fingerprint_template.txt")
            else:
                print("❌ Failed to capture fingerprint")
        else:
            print("\nUsage: python functions_fingerprint_scanner.py test")
            print("This will run the enhanced enrollment process with colored indicators")
        
        scanner.disconnect()
    else:
        print("❌ Could not connect to scanner")
        print("\nChecklist:")
        print("- Scanner is connected via USB")
        print("- libzkfp.dll is available in system PATH or current directory")
        print("- No other application is using the scanner")
        print("- Driver is properly installed")
        print("\nDemo Mode:")
        print("- Run: python functions_fingerprint_scanner.py test")
        print("- This will show the new colored scan attempt indicators (LẦN 1, 2, 3)")