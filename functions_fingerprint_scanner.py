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
    
    def _log_scan_attempt(self, attempt_number, total_attempts, status="waiting", message=""):
        """Log scan attempt with colored indicators"""
        # Color codes for console output
        colors = {
            "green": "\033[92m",  # Bright green
            "red": "\033[91m",    # Bright red  
            "yellow": "\033[93m", # Bright yellow
            "blue": "\033[94m",   # Bright blue
            "cyan": "\033[96m",   # Bright cyan
            "reset": "\033[0m"    # Reset color
        }
        
        # Choose color based on status
        if status == "success":
            color = colors["green"]
            icon = "✅"
            status_text = "OK"
        elif status == "failure":
            color = colors["red"]
            icon = "❌"
            status_text = "FAIL"
        elif status == "waiting":
            color = colors["cyan"]
            icon = "⏳"
            status_text = "WAITING"
        elif status == "in_progress":
            color = colors["yellow"]
            icon = "🔄"
            status_text = "SCANNING"
        else:
            color = colors["blue"]
            icon = "🔵"
            status_text = "INFO"
        
        # Large attempt number display
        attempt_display = f"{color}{'='*50}{colors['reset']}\n"
        attempt_display += f"{color}{'':>15}LẦN {attempt_number}/{total_attempts} - {status_text}{colors['reset']}\n"
        attempt_display += f"{color}{'='*50}{colors['reset']}"
        
        if self.ui_logger:
            # For UI logger, send structured data
            self.ui_logger.info({
                "type": "scan_attempt",
                "attempt": attempt_number,
                "total": total_attempts,
                "status": status,
                "message": message,
                "display": f"{icon} LẦN {attempt_number} {status_text}"
            })
        else:
            print(attempt_display)
            if message:
                print(f"{color}{icon} {message}{colors['reset']}")
        
        # Always log to standard logger as well
        logger.info(f"Scan attempt {attempt_number}/{total_attempts} - {status}: {message}")
        
        # Small delay to ensure logs are processed in order
        time.sleep(0.1)
    
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
        """Display enrollment summary with all scan results"""
        colors = {
            "green": "\033[92m",
            "cyan": "\033[96m", 
            "yellow": "\033[93m",
            "reset": "\033[0m"
        }
        
        summary = f"\n{colors['cyan']}{'='*60}{colors['reset']}\n"
        summary += f"{colors['cyan']}🎉 ENROLLMENT COMPLETED: {finger_name}{colors['reset']}\n"
        summary += f"{colors['cyan']}{'='*60}{colors['reset']}\n"
        
        # Show results for each scan
        for i, template in enumerate(templates, 1):
            quality = self._calculate_quality_score(template)
            status_color = colors["green"] if quality >= 70 else colors["yellow"]
            summary += f"{status_color}✅ LẦN {i}: Quality {quality}% ({len(template)} bytes){colors['reset']}\n"
        
        summary += f"{colors['cyan']}-{colors['reset']}" * 60 + "\n"
        summary += f"{colors['green']}🏆 FINAL: Quality {final_quality}% ({len(final_template)} bytes){colors['reset']}\n"
        summary += f"{colors['cyan']}{'='*60}{colors['reset']}"
        
        if self.ui_logger:
            self.ui_logger.info({
                "type": "enrollment_complete",
                "finger_name": finger_name,
                "scans": [{"attempt": i+1, "quality": self._calculate_quality_score(t), "size": len(t)} 
                         for i, t in enumerate(templates)],
                "final_quality": final_quality,
                "final_size": len(final_template)
            })
        else:
            print(summary)
        
        logger.info(f"Enrollment completed for {finger_name}: {len(templates)} scans, final quality {final_quality}%")
        
    def _check_dll_architecture(self, dll_path):
        """Check if DLL architecture matches Python architecture"""
        try:
            import platform
            import struct
            
            python_is_64bit = platform.architecture()[0] == '64bit'
            
            # Check DLL architecture by reading PE header
            with open(dll_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return True  # Not a PE file, assume compatible
                
                # Get PE header offset
                pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # Read PE signature and file header
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return True  # Not a valid PE file
                
                machine_type = struct.unpack('<H', f.read(2))[0]
                
                # 0x014c = i386 (32-bit), 0x8664 = x64 (64-bit)
                dll_is_64bit = machine_type == 0x8664
                
                if python_is_64bit != dll_is_64bit:
                    arch_python = "64-bit" if python_is_64bit else "32-bit"
                    arch_dll = "64-bit" if dll_is_64bit else "32-bit"
                    logger.error(f"Architecture mismatch: Python is {arch_python}, DLL is {arch_dll}")
                    return False
                
                return True
                
        except Exception as e:
            logger.warning(f"Could not verify DLL architecture: {e}")
            return True  # Assume compatible if we can't check

    def connect(self) -> bool:
        """Kết nối với thiết bị scanner vân tay"""
        if self.is_connected:
            return True

        try:
            # Load DLL with priority order
            try:
                dll_loaded = False
                dll_path = None
                
                # Priority 1: Application root directory (current working directory)
                dll_path = os.path.join(os.getcwd(), "libzkfp.dll")
                if os.path.exists(dll_path):
                    try:
                        self.zkfp = ctypes.windll.LoadLibrary(dll_path)
                        logger.info(f"✅ Loaded DLL from application root: {dll_path}")
                        dll_loaded = True
                    except Exception as e:
                        logger.warning(f"Failed to load from application root: {e}")
                
                # Priority 2: Use SCANNER_CONFIG['dll_path'] (working code)
                if not dll_loaded:
                    dll_path = SCANNER_CONFIG.get("dll_path", "libzkfp.dll")
                    try:
                        self.zkfp = ctypes.windll.LoadLibrary(SCANNER_CONFIG['dll_path'])
                        logger.info(f"✅ Loaded DLL using SCANNER_CONFIG: {dll_path}")
                        dll_loaded = True
                    except Exception as e:
                        logger.warning(f"Failed to load using SCANNER_CONFIG: {e}")
                
                if not dll_loaded:
                    raise Exception("Could not load libzkfp.dll from any location")

            except Exception as e:
                error_msg = str(e)
                if "193" in error_msg or "not a valid Win32 application" in error_msg or "architecture mismatch" in error_msg.lower():
                    import platform
                    python_arch = platform.architecture()[0]
                    logger.error("=" * 60)
                    logger.error("❌ DLL ARCHITECTURE MISMATCH DETECTED!")
                    logger.error("=" * 60)
                    logger.error(f"Current Python: {python_arch}")
                    logger.error(f"Current DLL: 32-bit (libzkfp.dll)")
                    logger.error("")
                    logger.error("🔧 SOLUTIONS:")
                    logger.error("1. Get 64-bit libzkfp.dll from ZKTeco SDK")
                    logger.error("2. Install 32-bit Python to match the 32-bit DLL")
                    logger.error("3. Contact ZKTeco for 64-bit SDK support")
                    logger.error("=" * 60)
                    if self.ui_logger:
                        self.ui_logger.error("❌ DLL Architecture Mismatch - Need 64-bit libzkfp.dll")
                else:
                    logger.error(f"Không thể load DLL: {e}")
                return False

            
            # Khai báo hàm
            self._declare_functions()
            
            # Khởi tạo SDK
            if self.zkfp.ZKFPM_Init() != 0:
                logger.error("Không thể khởi tạo SDK máy quét vân tay")
                return False
            
            # Kiểm tra số thiết bị
            device_count = self.zkfp.ZKFPM_GetDeviceCount()
            if device_count == 0:
                logger.error("Không tìm thấy thiết bị quét vân tay nào")
                self.zkfp.ZKFPM_Terminate()
                return False
            
            # Mở thiết bị đầu tiên
            self.handle = self.zkfp.ZKFPM_OpenDevice(0)
            if not self.handle:
                logger.error("Không thể mở thiết bị quét")
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
                logger.error("Không thể khởi tạo bộ đệm DB để merge vân tay")
                self.zkfp.ZKFPM_CloseDevice(self.handle)
                self.zkfp.ZKFPM_Terminate()
                return False
            
            self.is_connected = True
            logger.info(f"✅ Scanner connected: {self.img_width}x{self.img_height}")
            return True
            
        except Exception as e:
            logger.error(f"Lỗi khi khởi tạo hoặc kết nối scanner: {e}")
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
                logger.info("✅ Scanner disconnected")
                return True
            except Exception as e:
                logger.error(f"Lỗi khi ngắt kết nối scanner: {e}")
                return False
        return True
    
    def _cleanup(self):
        """Dọn dẹp tài nguyên"""
        if self.hDBCache:
            self.zkfp.ZKFPM_DBFree(self.hDBCache)
            self.hDBCache = None
            
        if self.handle:
            self.zkfp.ZKFPM_CloseDevice(self.handle)
            self.handle = None
            
        if self.zkfp:
            self.zkfp.ZKFPM_Terminate()
    
    def capture_fingerprint(self, finger_index: int, scan_number: int = 1) -> Optional[bytes]:
        """Capture fingerprint once with optimized performance"""
        if not self.is_connected or not self.zkfp or not self.handle:
            logger.error("Scanner not connected")
            return None
            
        try:
            # Pre-allocate buffers for better performance
            image_buf = (ctypes.c_ubyte * (self.img_width * self.img_height))()
            template_buf = (ctypes.c_ubyte * self.template_buf_size)()
            template_len = ctypes.c_uint(self.template_buf_size)
            
            start_time = time.time()
            timeout = SCANNER_CONFIG.get('timeout', 20)  # Reduced timeout for faster response
            
            # Show WAITING status BEFORE user places finger
            self._log_scan_attempt(scan_number, self.merge_count, "waiting", 
                                 f"Ready for scan {scan_number} - Please place finger on scanner now")
            
            # Small delay to ensure log is captured by frontend polling
            time.sleep(0.3)
            
            # Optimized polling interval
            poll_interval = 0.05  # Reduced from 0.1 to 0.05 for faster response
            
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
                    
                    # Log successful scan with green color and quality score
                    self._log_scan_attempt(scan_number, self.merge_count, "success", 
                                         f"OK - Quality: {quality_score}% ({len(template_data)} bytes)")
                    return template_data
                    
                time.sleep(poll_interval)
            
            # Log timeout failure with red color
            self._log_scan_attempt(scan_number, self.merge_count, "failure", 
                                 f"FAIL - Timeout after {timeout}s")
            return None
            
        except Exception as e:
            # Log exception failure with red color
            self._log_scan_attempt(scan_number, self.merge_count, "failure", 
                                 f"FAIL - Error: {str(e)}")
            logger.error(f"Error capturing fingerprint: {str(e)}")
            return None
    
    def enroll_fingerprint(self, finger_index: int) -> Optional[bytes]:
        """Enroll fingerprint with optimized 3-scan process"""
        if not self.is_connected or not self.zkfp or not self.handle:
            logger.error("Scanner not connected")
            return None
            
        if not self.hDBCache:
            logger.error("DB Cache not initialized")
            return None
            
        collected_templates = []
        finger_name = get_finger_name(finger_index)
        
        self._log(f"👆 Starting enrollment for {finger_name} (Index: {finger_index})")
        self._log(f"📋 This process requires 3 fingerprint scans for optimal quality")
        
        # Show LẦN 1 WAITING immediately so user knows what to expect
        self._log_scan_attempt(1, self.merge_count, "waiting", 
                             "Get ready for first scan - Please prepare finger")
        
        # Small delay to ensure frontend log polling is active
        time.sleep(0.5)
        
        # Collect 3 fingerprint samples with optimized timing
        for i in range(self.merge_count):
            self._log(f"\n📷 Now collecting scan {i+1}/{self.merge_count} for {finger_name}")
            
            template = self.capture_fingerprint(finger_index, i+1)
            if not template:
                return None
            
            collected_templates.append(template)
            
            if i < self.merge_count - 1:
                self._log("👆 Lift finger and prepare for next scan in 2 seconds...")
                time.sleep(2)  # Give user time to lift and reposition finger
        
        # Merge templates with error handling
        try:
            self._log("🔄 Processing and merging templates...")
            
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
                self._log(f"❌ Template merge failed (Error: {ret_merge})", "error")
                return None
                
        except Exception as e:
            logger.error(f"Error merging fingerprint templates: {str(e)}")
            self._log(f"❌ Merge process failed: {str(e)}", "error")
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