# 🔍 Fingerprint Scanner Bridge

Ứng dụng desktop bridge kết nối máy quét vân tay ZKTeco với các ứng dụng web thông qua REST API.

## 📋 Tổng quan

**Fingerprint Scanner Bridge** là một HTTP server chạy local để:
- Kết nối và điều khiển máy quét vân tay ZKTeco
- Cung cấp REST API cho các ứng dụng web
- Thực hiện quét và đăng ký vân tay với chất lượng cao
- Hỗ trợ 3-scan enrollment process để tối ưu hóa độ chính xác

## 🚀 Khởi chạy nhanh

### Cách 1: Chạy từ Executable
```bash
# Copy exe và dll vào cùng một thư mục
Fingerprint Scanner/
├── Fingerprint Scanner.exe
└── libzkfp.dll

# Chạy ứng dụng
./Fingerprint Scanner.exe
```

### Cách 2: Chạy từ Source Code
```bash
# Kích hoạt virtual environment
venv\Scripts\activate

# Chạy ứng dụng
python http_server_fingerprint_scanner.py
```

## 🔧 Yêu cầu hệ thống

### Hardware
- ✅ Máy quét vân tay ZKTeco (USB)
- ✅ Windows 64-bit OS

### Software Dependencies
- ✅ ZKTeco driver đã cài đặt
- ✅ libzkfp.dll (64-bit version)
- ✅ Python 3.8+ (nếu chạy từ source)

## 📁 Cấu trúc DLL Loading

Ứng dụng sẽ tìm `libzkfp.dll` theo thứ tự ưu tiên:

1. **C:\Windows\SysWOW64\libzkfp.dll** - Folder mặc định khi cài driver
2. **[Executable Directory]\libzkfp.dll** - Cùng thư mục với exe
3. **[Current Directory]\libzkfp.dll** - Thư mục làm việc hiện tại
4. **System PATH** - Fallback tìm trong PATH environment

## 🌐 API Documentation

### Server Information
- **Base URL**: `http://127.0.0.1:8080/api`
- **Content-Type**: `application/json`
- **CORS**: Enabled cho development

### Core Endpoints

#### 1. Test Connection
```http
GET /api/test
```
**Response:**
```json
{
    "status": "success",
    "message": "API is working",
    "timestamp": "2025-08-22T16:27:40"
}
```

#### 2. Initialize Scanner
```http
POST /api/scanner/initialize
```
**Response:**
```json
{
    "success": true,
    "message": "Scanner connected: 288x375",
    "resolution": {
        "width": 288,
        "height": 375
    }
}
```

#### 3. Capture Fingerprint
```http
POST /api/fingerprint/capture
```
**Request Body:**
```json
{
    "employeeId": "TIQN-0148",
    "fingerIndex": 6,
    "fingerName": "Right Index"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Fingerprint captured successfully: 660 bytes, Quality: 91%",
    "data": {
        "fingerprint_template": "base64_encoded_template_data",
        "quality_score": 91,
        "template_size": 660,
        "finger_name": "Right Index",
        "enrollment_details": {
            "scan_1": {"quality": 90, "size": 844},
            "scan_2": {"quality": 91, "size": 660},
            "scan_3": {"quality": 90, "size": 488}
        }
    }
}
```

#### 4. Disconnect Scanner
```http
POST /api/scanner/disconnect
```

#### 5. Get Real-time Logs
```http
GET /api/logs/since?since=16:27:41
```

### Finger Index Mapping
| Index | Finger Name |
|-------|-------------|
| 0 | Left Thumb |
| 1 | Left Index |
| 2 | Left Middle |
| 3 | Left Ring |
| 4 | Left Little |
| 5 | Right Thumb |
| 6 | Right Index |
| 7 | Right Middle |
| 8 | Right Ring |
| 9 | Right Little |

## 🔄 3-Scan Enrollment Process

Để đảm bảo chất lượng cao, ứng dụng sử dụng quy trình 3 lần quét:

1. **Scan 1**: Thu thập template đầu tiên
2. **Scan 2**: Thu thập template thứ hai (sau 2s delay)
3. **Scan 3**: Thu thập template thứ ba (sau 2s delay)
4. **Merge**: Kết hợp 3 template thành final template tối ưu

### Real-time Status Tracking
```
⏳ LẦN 1 WAITING → ✅ LẦN 1 OK (Quality: 90%)
⏳ LẦN 2 WAITING → ✅ LẦN 2 OK (Quality: 91%)
⏳ LẦN 3 WAITING → ✅ LẦN 3 OK (Quality: 90%)
🔄 Processing and merging...
🎉 ENROLLMENT COMPLETED - Final Quality: 91%
```

## 🛠️ Build và Deploy

### Build Executable
```bash
# Chạy build script
build_exe.bat

# Output sẽ được tạo trong folder:
Fingerprint Scanner/
├── Fingerprint Scanner.exe
└── libzkfp.dll
```

### Deploy Requirements
1. Copy toàn bộ folder `Fingerprint Scanner/` 
2. Đảm bảo máy đích đã cài ZKTeco driver
3. Kết nối máy quét vân tay qua USB
4. Chạy `Fingerprint Scanner.exe`

## 🔍 Troubleshooting

### Common Issues

#### 1. DLL Load Failed
```
❌ Could not load libzkfp.dll from any location
```
**Solution:**
- Cài đặt ZKTeco driver
- Copy libzkfp.dll vào cùng thư mục exe
- Kiểm tra DLL architecture (phải là 64-bit)

#### 2. Scanner Not Found
```
❌ Không tìm thấy thiết bị quét vân tay nào
```
**Solution:**
- Kiểm tra kết nối USB
- Restart scanner device
- Kiểm tra Device Manager

#### 3. SDK Init Failed
```
❌ Không thể khởi tạo SDK máy quét vân tay
```
**Solution:**
- Đóng các ứng dụng khác đang sử dụng scanner
- Restart ứng dụng
- Restart scanner device

#### 4. Port Already in Use
```
❌ Address already in use: 127.0.0.1:8080
```
**Solution:**
- Đóng instance khác của ứng dụng
- Đổi port trong code nếu cần

### Debug Information

Ứng dụng cung cấp debug info chi tiết:
```
🔍 Debug info:
   - sys.frozen: True/False
   - sys.executable: D:\Fingerprint Scanner.exe
   - __file__: D:\functions_fingerprint_scanner.py
   - os.getcwd(): D:\
```

### Log Levels
- **INFO**: Thông tin hoạt động bình thường
- **WARNING**: Cảnh báo không ảnh hưởng chức năng
- **ERROR**: Lỗi nghiêm trọng cần xử lý

## 📞 Support

### Technical Specifications
- **Scanner Resolution**: 288x375 pixels
- **Template Size**: ~500-900 bytes
- **Quality Threshold**: ≥50%
- **Timeout**: 30 seconds per scan
- **API Response Time**: <3 seconds

### Contact
- **Developer**: Development Team
- **Version**: 1.0.0
- **Last Updated**: August 2025

---

*Fingerprint Scanner Bridge - Connecting hardware to web applications seamlessly* 🔗