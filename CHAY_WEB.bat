@echo off
chcp 65001 >nul
title Website Trường THPT Chuyên Phan Bội Châu - Nghệ An
cd /d "%~dp0"

echo ====================================================================
echo       WEBSITE TRƯỜNG THPT CHUYÊN PHAN BỘI CHÂU - NGHỆ AN
echo ====================================================================
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] LỖI: Không tìm thấy Python trên máy tính của bạn!
    echo Vui lòng cài đặt Python (tích chọn 'Add Python to PATH') để chạy web.
    echo.
    pause
    exit /b 1
)

echo [*] Đang khởi động máy chủ Web Server...
echo [*] Địa chỉ truy cập: http://localhost:8080
echo [*] Đang tự động mở trình duyệt web...
echo.
echo [MẸO] Nhấn Ctrl + C để dừng máy chủ khi hoàn tất.
echo ====================================================================
echo.

:: Tự động kích hoạt mở trình duyệt sau 1 giây
start "" cmd /c "timeout /t 1 /nobreak >nul & start http://localhost:8080"

:: Khởi động máy chủ web
if exist dev_server.py (
    python dev_server.py
) else (
    python -m http.server 8080
)

pause
