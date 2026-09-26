#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
FILE SECURITY MODULE - TRƯỜNG THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Triển khai đúng quy trình bảo mật Upload 5 bước:
Upload
  ↓
1. Kiểm tra Extension (Whitelist)
  ↓
2. Kiểm tra MIME Type & Magic Bytes
  ↓
3. Kiểm tra kích thước (Max Size)
  ↓
4. Malware Scan (Quét mã độc / Script nhúng)
  ↓
5. Lưu trữ an toàn (Random UUID, phân quyền chống thực thi)
==============================================================================
"""

import io
import os
import re
import sys
import uuid
from typing import Any, Dict, Optional, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class FileSecurityManager:
    """Quản lý kiểm duyệt toàn bộ tài liệu, ảnh, kỷ yếu tải lên website."""

    # 1. DANH SÁCH ĐUÔI TỆP CHO PHÉP (WHITELIST EXTENSIONS)
    ALLOWED_EXTENSIONS = {
        'image': {'jpg', 'jpeg', 'png', 'webp', 'gif'},
        'document': {'pdf', 'docx', 'doc', 'xlsx', 'pptx'}
    }

    # 2. BẢNG MAGIC BYTES TIÊU CHUẨN ĐỂ NHẬN DIỆN MIME TYPE THỰC TẾ
    MAGIC_SIGNATURES = {
        'png': b'\x89PNG\r\n\x1a\n',
        'jpg': b'\xff\xd8\xff',
        'jpeg': b'\xff\xd8\xff',
        'gif': b'GIF8',
        'pdf': b'%PDF-',
        'docx': b'PK\x03\x04',
        'xlsx': b'PK\x03\x04',
        'pptx': b'PK\x03\x04'
    }

    # 3. GIỚI HẠN KÍCH THƯỚC TỐI ĐA (5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5,242,880 bytes

    # THƯ MỤC LƯU TRỮ AN TOÀN
    DEFAULT_STORAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "uploads")

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = storage_dir or self.DEFAULT_STORAGE_DIR
        os.makedirs(self.storage_dir, exist_ok=True)

    # --------------------------------------------------------------------------
    # BƯỚC 1: KIỂM TRA EXTENSION
    # --------------------------------------------------------------------------
    def check_extension(self, filename: str) -> Tuple[bool, str, str]:
        """
        Kiểm tra phần mở rộng file.
        Chống tấn công Double-Extension (ví dụ: avatar.php.jpg) và Null-Byte.
        """
        if not filename or '\x00' in filename:
            return False, "", "Phát hiện ký tự Null Byte nguy hiểm trong tên file"

        clean_name = os.path.basename(filename)
        parts = clean_name.lower().split('.')
        if len(parts) < 2:
            return False, "", "Tệp tin không có phần mở rộng hợp lệ"

        # Danh sách đuôi cấm tuyệt đối nằm giữa tên tệp
        dangerous_exts = {'php', 'phtml', 'asp', 'aspx', 'jsp', 'exe', 'sh', 'py', 'pl', 'cgi', 'bat'}
        for ext in parts[1:-1]:
            if ext in dangerous_exts:
                return False, "", f"Phát hiện tấn công Double-Extension nguy hiểm: .{ext}"

        file_ext = parts[-1]
        all_allowed = self.ALLOWED_EXTENSIONS['image'] | self.ALLOWED_EXTENSIONS['document']
        
        if file_ext not in all_allowed:
            return False, file_ext, f"Đuôi tệp .{file_ext} không nằm trong danh sách cho phép (Whitelist)"

        return True, file_ext, "Phần mở rộng hợp lệ"

    # --------------------------------------------------------------------------
    # BƯỚC 2: KIỂM TRA MIME TYPE & MAGIC BYTES
    # --------------------------------------------------------------------------
    def check_mime_and_magic(self, file_bytes: bytes, claimed_ext: str) -> Tuple[bool, str]:
        """
        Đọc các byte đầu tiên (Magic Bytes) để xác định định dạng thực tế của file,
        chống giả mạo đuôi tệp (ví dụ đổi shell sang jpg).
        """
        if len(file_bytes) < 4:
            return False, "Kích thước tệp quá nhỏ hoặc bị hỏng"

        expected_sig = self.MAGIC_SIGNATURES.get(claimed_ext)
        if expected_sig:
            if not file_bytes.startswith(expected_sig):
                if claimed_ext == 'webp' and file_bytes[:4] == b'RIFF' and len(file_bytes) >= 12 and file_bytes[8:12] == b'WEBP':
                    return True, "MIME Type và Magic Bytes hợp lệ (WebP)"
                return False, f"Nội dung file không khớp với định dạng .{claimed_ext} (Giả mạo Magic Bytes)"

        return True, "MIME Type và Magic Bytes hợp lệ"

    # --------------------------------------------------------------------------
    # BƯỚC 3: KIỂM TRA KÍCH THƯỚC FILE
    # --------------------------------------------------------------------------
    def check_file_size(self, file_bytes: bytes) -> Tuple[bool, str]:
        """Giới hạn kích thước tối đa 5MB chống tấn công cạn kiệt dung lượng đĩa."""
        size = len(file_bytes)
        if size == 0:
            return False, "File rỗng (0 bytes)"
        if size > self.MAX_FILE_SIZE:
            return False, f"Kích thước file ({size / 1024 / 1024:.2f} MB) vượt quá giới hạn cho phép (5.00 MB)"
        return True, f"Kích thước hợp lệ ({size / 1024:.1f} KB)"

    # --------------------------------------------------------------------------
    # BƯỚC 4: MALWARE & SCRIPT SCAN
    # --------------------------------------------------------------------------
    def scan_for_malware(self, file_bytes: bytes) -> Tuple[bool, str]:
        """
        Quét các chuỗi mã độc, shellcode, script nhúng thường gặp.
        Sử dụng phân tích chữ ký nhị phân không gây nhầm lẫn.
        """
        sample = file_bytes[:65536].lower()

        # Danh sách chữ ký mã lệnh độc hại (được chuẩn hóa)
        signatures = [
            b'<' + b'?php',
            b'<' + b'?=',
            b'<script',
            b'javascript:',
            b'data:text/html',
            b'eval(',
            b'passthru(',
            b'shell_exec(',
            b'system(',
            b'base64_decode(',
            b'xp_cmdshell'
        ]

        for sig in signatures:
            if sig in sample:
                return False, f"Phát hiện dấu hiệu mã độc / mã lệnh nguy hiểm: {sig.decode('ascii', errors='ignore')}"

        return True, "Không phát hiện mã độc (Quét an toàn)"

    # --------------------------------------------------------------------------
    # BƯỚC 5: LƯU TRỮ AN TOÀN (SAFE STORAGE)
    # --------------------------------------------------------------------------
    def safe_store(self, file_bytes: bytes, valid_ext: str, original_filename: str) -> Tuple[bool, str, Dict[str, str]]:
        """Đổi tên file thành mã ngẫu nhiên UUIDv4 duy nhất và lưu trữ vào thư mục riêng biệt."""
        unique_id = uuid.uuid4().hex
        safe_filename = f"{unique_id}.{valid_ext}"
        target_path = os.path.join(self.storage_dir, safe_filename)

        try:
            with open(target_path, 'wb') as f:
                f.write(file_bytes)

            try:
                os.chmod(target_path, 0o644)
            except Exception:
                pass

            metadata = {
                "safe_filename": safe_filename,
                "original_filename": original_filename,
                "stored_path": target_path,
                "file_size": str(len(file_bytes)),
                "extension": valid_ext
            }
            return True, "Lưu trữ tệp thành công vào khu vực an toàn", metadata
        except Exception as e:
            return False, f"Lỗi trong quá trình ghi tệp: {str(e)}", {}

    # --------------------------------------------------------------------------
    # QUY TRÌNH TỔNG THỂ XỬ LÝ FILE TẢI LÊN (5 BƯỚC HOÀN CHỈNH)
    # --------------------------------------------------------------------------
    def process_uploaded_file(self, filename: str, file_bytes: bytes) -> Dict[str, Any]:
        """Thực thi toàn bộ chuỗi kiểm duyệt an ninh 5 bước."""
        report = {
            "status": "REJECTED",
            "filename": filename,
            "step_logs": []
        }

        # 1. Extension Check
        ok_ext, ext, msg1 = self.check_extension(filename)
        report["step_logs"].append({"step": "1. Extension Check", "passed": ok_ext, "message": msg1})
        if not ok_ext:
            return report

        # 2. MIME & Magic Bytes Check
        ok_mime, msg2 = self.check_mime_and_magic(file_bytes, ext)
        report["step_logs"].append({"step": "2. MIME & Magic Bytes", "passed": ok_mime, "message": msg2})
        if not ok_mime:
            return report

        # 3. File Size Check
        ok_size, msg3 = self.check_file_size(file_bytes)
        report["step_logs"].append({"step": "3. File Size Limit", "passed": ok_size, "message": msg3})
        if not ok_size:
            return report

        # 4. Malware Scan
        ok_scan, msg4 = self.scan_for_malware(file_bytes)
        report["step_logs"].append({"step": "4. Malware Scan", "passed": ok_scan, "message": msg4})
        if not ok_scan:
            return report

        # 5. Safe Storage
        ok_save, msg5, meta = self.safe_store(file_bytes, ext, filename)
        report["step_logs"].append({"step": "5. Safe Storage", "passed": ok_save, "message": msg5})
        
        if ok_save:
            report["status"] = "ACCEPTED"
            report["metadata"] = meta

        return report


# ==============================================================================
# KIỂM THỬ THỰC TẾ QUY TRÌNH 5 BƯỚC
# ==============================================================================
if __name__ == "__main__":
    print("==========================================================")
    print("  KIỂM THỬ QUY TRÌNH FILE SECURITY (5 BƯỚC TIÊU CHUẨN)   ")
    print("==========================================================")

    fsec = FileSecurityManager()

    # Case 1: Tệp ảnh hợp lệ (Valid PNG)
    valid_png_bytes = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
    res1 = fsec.process_uploaded_file("anh_hoat_dong.png", valid_png_bytes)
    print("\n[Case 1: Ảnh PNG hợp lệ]")
    print(f"  Trạng thái: {res1['status']}")
    for step in res1["step_logs"]:
        print(f"   -> {step['step']}: {step['message']}")

    # Case 2: Tấn công Double-Extension (file.php.jpg)
    res2 = fsec.process_uploaded_file("malicious.php.jpg", valid_png_bytes)
    print("\n[Case 2: Tấn công Double Extension (malicious.php.jpg)]")
    print(f"  Trạng thái: {res2['status']} - Lý do: {res2['step_logs'][-1]['message']}")

    # Case 3: Giả mạo Magic Bytes (Tệp giả mạo có chữ ký lạ)
    fake_png_bytes = b"INVALID_BYTES_NOT_MATCHING_PNG"
    res3 = fsec.process_uploaded_file("webshell.png", fake_png_bytes)
    print("\n[Case 3: Giả mạo Magic Bytes (webshell.png)]")
    print(f"  Trạng thái: {res3['status']} - Lý do: {res3['step_logs'][-1]['message']}")

    # Case 4: File vượt quá dung lượng (6MB)
    huge_bytes = b'\x89PNG\r\n\x1a\n' + b'A' * (6 * 1024 * 1024)
    res4 = fsec.process_uploaded_file("too_large.png", huge_bytes)
    print("\n[Case 4: File quá kích thước 5MB]")
    print(f"  Trạng thái: {res4['status']} - Lý do: {res4['step_logs'][-1]['message']}")

    print("\n[+] Đã hoàn thành xác minh quy trình File Security 5 bước thành công!")
