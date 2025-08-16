# Fingerprint Scanner Bridge Application

## Mô tả
Ứng dụng cầu nối (Bridge Application) chạy trên máy tính user để kết nối giữa ERPNext Web UI và máy quét vân tay ZKTeco. Ứng dụng hoạt động như một HTTP Server cục bộ, cho phép ERPNext Web giao tiếp với thiết bị quét vân tay thông qua API REST.

## Tính năng chính
- ✅ **Kết nối máy quét vân tay ZKTeco** qua USB
- ✅ **API REST** để quét và lưu trữ vân tay 
- ✅ **Giao diện console thân thiện** với hiển thị màu sắc
- ✅ **Quét 3 lần và ghép template** để tăng độ chính xác
- ✅ **Log real-time** hiển thị tiến trình LẦN 1, 2, 3
- ✅ **Tính toán điểm chất lượng** cho mỗi template vân tay
- ✅ **CORS support** để ERPNext Web có thể gọi API
- ✅ **Auto-reconnect** khi mất kết nối với scanner

## Cấu trúc project
```
06.fingerprint_scanner_bridge/
├── main.py                              # Entry point chính
├── http_server_fingerprint_scanner.py   # HTTP Server và API endpoints
├── functions_fingerprint_scanner.py     # Logic quét vân tay ZKTeco
├── requirements.txt                     # Dependencies Python
├── libzkfp.dll                         # ZKTeco SDK library (32-bit)
├── build_exe.py                        # Script build executable
└── README.md                           # Documentation
```

## Yêu cầu hệ thống
- **Windows 10/11** (64-bit khuyến nghị)
- **Python 3.8+** (32-bit hoặc 64-bit)
- **ZKTeco Fingerprint Scanner** kết nối USB
- **libzkfp.dll** (ZKTeco SDK) - đã bao gồm trong project

## Cài đặt và chạy

### 1. Cài đặt Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Chạy ứng dụng (Development mode)
```bash
python main.py
```

### 3. Build file EXE (Production)
```bash
python build_exe.py
```
Sau khi build thành công, file EXE sẽ được tạo trong thư mục `dist/`

### 4. Chạy file EXE
- Double-click file `main.exe` trong thư mục `dist/`
- Hoặc chạy từ command line: `dist/main.exe`

## API Endpoints

### Base URL: `http://127.0.0.1:8080/api`

#### 1. Test connection
```
GET /test
Response: {"success": true, "message": "Bridge is running"}
```

#### 2. Initialize scanner
```
POST /scanner/initialize
Response: {"success": true/false, "message": "..."}
```

#### 3. Capture fingerprint (3-scan enrollment)
```
POST /fingerprint/capture
Body: {
    "employee_id": "TIQN-0001", 
    "finger_index": 1
}
Response: {
    "success": true/false,
    "template_data": "base64_encoded_template",
    "template_size": 1048,
    "quality_score": 85,
    "message": "..."
}
```

#### 4. Get real-time logs
```
GET /logs/since?since=14:30:15
Response: {
    "success": true,
    "logs": [
        {
            "timestamp": "14:30:16",
            "level": "info",
            "message": "⏳ LẦN 1 WAITING"
        }
    ]
}
```

#### 5. Disconnect scanner
```
POST /scanner/disconnect
Response: {"success": true/false, "message": "..."}
```

## Thuật toán quét vân tay

### 1. Quy trình quét 3 lần (3-Scan Enrollment)
```
1. LẦN 1: User đặt ngón tay → Capture template 1 → Tính quality score
2. LẦN 2: User đặt ngón tay → Capture template 2 → Tính quality score  
3. LẦN 3: User đặt ngón tay → Capture template 3 → Tính quality score
4. MERGE: Ghép 3 templates thành 1 template cuối cùng
5. SAVE: Lưu template vào database với quality score tổng hợp
```

### 2. Tính toán Quality Score
```python
def _calculate_quality_score(template_data: bytes) -> int:
    """
    Tính điểm chất lượng dựa trên:
    - Kích thước template (bytes)
    - Mật độ dữ liệu (non-zero bytes)
    - Công thức: (density_ratio * size_factor) * 100
    """
    template_size = len(template_data)
    non_zero_bytes = sum(1 for byte in template_data if byte != 0)
    
    density_ratio = non_zero_bytes / template_size
    size_factor = min(template_size / 500, 1.0)
    
    quality_score = int((density_ratio * size_factor) * 100)
    return min(quality_score, 100)  # Tối đa 100%
```

### 3. Hiển thị tiến trình real-time
- **⏳ LẦN X WAITING**: Đang chờ user đặt tay
- **🔄 LẦN X SCANNING**: Đang quét
- **✅ LẦN X OK**: Quét thành công với quality score
- **❌ LẦN X FAIL**: Quét thất bại (timeout/lỗi)

### 4. Template Merging Algorithm
Sử dụng ZKTeco SDK function `ZKFPM_DBMerge()` để ghép 3 templates:
```python
ret_merge = self.zkfp.ZKFPM_DBMerge(
    self.hDBCache,      # DB Cache handle
    templates_c[0],     # Template từ LẦN 1
    templates_c[1],     # Template từ LẦN 2  
    templates_c[2],     # Template từ LẦN 3
    merged_template_buf, # Buffer output
    merged_template_len  # Kích thước output
)
```

## Troubleshooting

### 1. Lỗi "Could not load libzkfp.dll"
**Nguyên nhân**: Architecture mismatch (32-bit vs 64-bit)
**Giải pháp**: 
- Sử dụng Python 32-bit với libzkfp.dll 32-bit (đã include)
- Hoặc tìm libzkfp.dll 64-bit từ ZKTeco SDK

### 2. Lỗi "No fingerprint device found"
**Nguyên nhân**: Scanner chưa kết nối hoặc driver chưa cài
**Giải pháp**:
- Kiểm tra kết nối USB
- Cài đặt driver ZKTeco
- Đảm bảo không có ứng dụng khác đang sử dụng scanner

### 3. Lỗi "Port 8080 already in use"
**Nguyên nhân**: Có process khác đang sử dụng port 8080
**Giải pháp**:
- Đóng ứng dụng cũ
- Hoặc thay đổi port trong code

### 4. ERPNext không kết nối được với Bridge
**Nguyên nhân**: CORS hoặc firewall
**Giải pháp**:
- Kiểm tra Windows Firewall
- Đảm bảo ERPNext truy cập đúng URL: `http://127.0.0.1:8080/api`

## Logs và Debug

### Console Logs
Ứng dụng hiển thị logs với màu sắc:
- 🟢 **Xanh lá**: Thành công
- 🔴 **Đỏ**: Lỗi  
- 🟡 **Vàng**: Cảnh báo
- 🔵 **Xanh dương**: Thông tin

### Log Files
- Logs được lưu trong memory và có thể truy xuất qua API `/logs/since`
- ERPNext Web sử dụng log polling để hiển thị real-time progress

## Tích hợp với ERPNext

### Frontend JavaScript
```javascript
// Kiểm tra kết nối Bridge
fetch('http://127.0.0.1:8080/api/test')

// Quét vân tay
fetch('http://127.0.0.1:8080/api/fingerprint/capture', {
    method: 'POST',
    body: JSON.stringify({
        employee_id: 'TIQN-0001',
        finger_index: 1
    })
})

// Polling logs real-time
setInterval(() => {
    fetch(`http://127.0.0.1:8080/api/logs/since?since=${lastTimestamp}`)
}, 500)
```

### Backend Python (ERPNext)
```python
# Lưu fingerprint data vào database
@frappe.whitelist()
def save_fingerprint_data(employee_id, finger_index, template_data, quality_score):
    # Logic lưu vào Fingerprint Enrollment doctype
    pass
```

## Phát triển và Maintenance

### Thêm tính năng mới
1. Thêm endpoint mới trong `http_server_fingerprint_scanner.py`
2. Implement logic trong `functions_fingerprint_scanner.py`
3. Update frontend JavaScript trong ERPNext
4. Test và build EXE mới

### Performance Optimization
- Giảm polling interval từ 500ms xuống 200ms nếu cần responsive hơn
- Tăng buffer size cho template nếu scanner hỗ trợ
- Implement connection pooling cho multiple concurrent requests

---

**Phiên bản**: 1.0  
**Tác giả**: Development Team  
**Ngày cập nhật**: 2024
