# -*- coding: utf-8 -*-
"""
Chứa logic quét vân tay
"""

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
        
    def connect(self) -> bool:
        """Kết nối với thiết bị scanner vân tay"""
        if self.is_connected:
            return True

        try:
            # Load DLL
            try:
                self.zkfp = ctypes.windll.LoadLibrary(SCANNER_CONFIG['dll_path'])
            except Exception as e:
                logger.error(f"Không thể load {SCANNER_CONFIG['dll_path']}: {e}")
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
        """Quét vân tay một lần"""
        if not self.is_connected or not self.zkfp or not self.handle:
            logger.error("Scanner chưa được kết nối")
            return None
            
        try:
            # Tạo buffer
            image_buf = (ctypes.c_ubyte * (self.img_width * self.img_height))()
            template_buf = (ctypes.c_ubyte * self.template_buf_size)()
            template_len = ctypes.c_uint(self.template_buf_size)
            
            start_time = time.time()
            timeout = SCANNER_CONFIG.get('timeout', 30)
            
            self._log(f"🔍 Waiting for fingerprint scan {scan_number}/{self.merge_count}...")
            
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
                    self._log(f"✅ Scan {scan_number} completed", "success")
                    return template_data
                    
                time.sleep(0.1)
                
            self._log(f"❌ Scan {scan_number} timeout", "error")
            return None
            
        except Exception as e:
            logger.error(f"Lỗi khi quét vân tay: {str(e)}")
            return None
    
    def enroll_fingerprint(self, finger_index: int) -> Optional[bytes]:
        """Đăng ký vân tay mới (quét 3 lần và merge)"""
        if not self.is_connected or not self.zkfp or not self.handle:
            logger.error("Scanner chưa được kết nối")
            return None
            
        if not self.hDBCache:
            logger.error("DB Cache chưa được khởi tạo")
            return None
            
        collected_templates = []
        
        self._log(f"👆 Starting fingerprint enrollment for finger {finger_index}")
        
        # Thu thập 3 mẫu vân tay
        for i in range(self.merge_count):
            self._log(f"\n📷 Please place finger on scanner (scan {i+1}/{self.merge_count})")
            
            template = self.capture_fingerprint(finger_index, i+1)
            if not template:
                self._log(f"❌ Scan {i+1} failed", "error")
                return None
            
            collected_templates.append(template)
            
            if i < self.merge_count - 1:
                self._log("👆 Please lift finger and place again")
                time.sleep(2)
        
        # Merge 3 template
        try:
            self._log("🔄 Merging fingerprint templates...")
            
            # Tạo buffer cho kết quả merge
            merged_template_buf = (ctypes.c_ubyte * self.template_buf_size)()
            merged_template_len = ctypes.c_uint(self.template_buf_size)
            
            # Chuyển đổi template thành ctypes array
            t1_c = (ctypes.c_ubyte * len(collected_templates[0]))(*collected_templates[0])
            t2_c = (ctypes.c_ubyte * len(collected_templates[1]))(*collected_templates[1])
            t3_c = (ctypes.c_ubyte * len(collected_templates[2]))(*collected_templates[2])
            
            # Thực hiện merge
            ret_merge = self.zkfp.ZKFPM_DBMerge(
                self.hDBCache,
                t1_c,
                t2_c,
                t3_c,
                merged_template_buf,
                ctypes.byref(merged_template_len)
            )
            
            if ret_merge == 0:
                final_template_data = bytes(merged_template_buf[:merged_template_len.value])
                self._log(f"✅ Fingerprint merged successfully! Template size: {len(final_template_data)} bytes", "success")
                return final_template_data
            else:
                self._log(f"❌ Merge failed with error code: {ret_merge}", "error")
                return None
                
        except Exception as e:
            logger.error(f"Lỗi khi merge vân tay: {str(e)}")
            return None

def get_finger_name(finger_index):
    """Lấy tên ngón tay từ chỉ số"""
    finger_names = {
        0: "Ngón cái trái",
        1: "Ngón trỏ trái", 
        2: "Ngón giữa trái",
        3: "Ngón áp út trái",
        4: "Ngón út trái",
        5: "Ngón cái phải",
        6: "Ngón trỏ phải",
        7: "Ngón giữa phải", 
        8: "Ngón áp út phải",
        9: "Ngón út phải"
    }
    return finger_names.get(finger_index, f"Ngón {finger_index}")

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
            # Test capture
            print("\n🔍 Test mode - Capturing fingerprint for finger index 1...")
            template = scanner.enroll_fingerprint(1)
            
            if template:
                print(f"✅ Template captured: {len(template)} bytes")
                template_b64 = base64.b64encode(template).decode('utf-8')
                print(f"📋 Base64 (first 50 chars): {template_b64[:50]}...")
                
                # Save to file
                with open('fingerprint_template.txt', 'w') as f:
                    f.write(template_b64)
                print("💾 Template saved to fingerprint_template.txt")
            else:
                print("❌ Failed to capture fingerprint")
        
        scanner.disconnect()
    else:
        print("❌ Could not connect to scanner")
        print("\nChecklist:")
        print("- Scanner is connected via USB")
        print("- libzkfp.dll is available in system PATH or current directory")
        print("- No other application is using the scanner")
        print("- Driver is properly installed")