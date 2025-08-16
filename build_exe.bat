@echo off
call venv\Scripts\activate

REM Xóa thư mục build/dist cũ
rmdir /s /q dist
rmdir /s /q build

REM Build bằng file spec, sử dụng icon fingerprint-scan.ico
python -m PyInstaller "Fingerprint Scanner Bridge.spec"

REM Copy libzkfp.dll vào thư mục dist (cùng thư mục với exe)
copy "libzkfp.dll" "dist\libzkfp.dll"

REM Tạo thư mục Fingerprint Scanner nếu chưa tồn tại
if not exist "Fingerprint Scanner" mkdir "Fingerprint Scanner"

REM Copy file exe và dll vào thư mục Fingerprint Scanner
copy "dist\Fingerprint Scanner Bridge.exe" "Fingerprint Scanner\Fingerprint Scanner.exe"
copy "dist\libzkfp.dll" "Fingerprint Scanner\libzkfp.dll"

REM Verify build results
echo.
echo ✅ Build completed! Files in Fingerprint Scanner folder:
dir "Fingerprint Scanner" /b
echo.
echo ✅ libzkfp.dll configuration:
echo   - NOT included in exe bundle
echo   - External file in exe directory only

pause
