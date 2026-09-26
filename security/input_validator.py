#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
INPUT VALIDATION MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Xác thực và làm sạch dữ liệu người dùng gửi lên theo nguyên tắc Whitelist.
- Cắt bỏ ký tự điều khiển nguy hiểm (Null-Byte, non-printable ASCII).
- Kiểm tra định dạng chuẩn: Email RFC 5322, SĐT Việt Nam, Tên tài khoản.
==============================================================================
"""

import re
import sys
from typing import Optional

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class InputValidator:
    """Xác thực và làm sạch dữ liệu đầu vào theo nguyên tắc Whitelist."""

    @staticmethod
    def sanitize_text(value: str, max_length: int = 500) -> str:
        """Loại bỏ ký tự điều khiển ẩn và cắt bớt độ dài tối đa."""
        if not isinstance(value, str):
            return ""
        # Cắt bớt khoảng trắng dư thừa
        cleaned = value.strip()
        # Loại bỏ các ký tự điều khiển ASCII null byte
        cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', cleaned)
        return cleaned[:max_length]

    @staticmethod
    def validate_email(email: str) -> bool:
        """Kiểm tra định dạng email tiêu chuẩn RFC 5322 đơn giản hóa."""
        if not email or not isinstance(email, str):
            return False
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return bool(re.match(pattern, email.strip()))

    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Kiểm tra số điện thoại Việt Nam hợp lệ (10 số, bắt đầu bằng số 0 hoặc +84)."""
        if not phone or not isinstance(phone, str):
            return False
        cleaned_phone = phone.strip().replace(' ', '').replace('.', '').replace('-', '')
        pattern = r'^(0|\+84)(3|5|7|8|9)[0-9]{8}$'
        return bool(re.match(pattern, cleaned_phone))

    @staticmethod
    def validate_username(username: str) -> bool:
        """Chỉ cho phép chữ cái, chữ số, gạch dưới, độ dài 3-30 ký tự."""
        if not username or not isinstance(username, str):
            return False
        pattern = r'^[a-zA-Z0-9_]{3,30}$'
        return bool(re.match(pattern, username.strip()))


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module InputValidator:")
    valid_email = InputValidator.validate_email("c3chuyenpbc@nghean.edu.vn")
    invalid_email = InputValidator.validate_email("bad_user<script>@evil.com")
    valid_phone = InputValidator.validate_phone("0912345678")
    invalid_phone = InputValidator.validate_phone("12345")
    sanitized = InputValidator.sanitize_text("   Xin chào THPT Chuyên Phan Bội Châu!\x00   ")

    print(f"  - Email hợp lệ       : {valid_email} (Kỳ vọng: True)")
    print(f"  - Email độc hại      : {invalid_email} (Kỳ vọng: False)")
    print(f"  - Số điện thoại đúng : {valid_phone} (Kỳ vọng: True)")
    print(f"  - Số điện thoại sai  : {invalid_phone} (Kỳ vọng: False)")
    print(f"  - Làm sạch văn bản   : '{sanitized}'")
    print("[+] Hoàn thành kiểm thử InputValidator.")
