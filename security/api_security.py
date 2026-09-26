#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
API SECURITY MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Bảo vệ các giao diện lập trình ứng dụng (API Endpoints).
- Xác thực Bearer Token / API Key bằng so sánh mật mã thời gian cố định.
- Ràng buộc Content-Type nghiêm ngặt (`application/json`).
- Giới hạn dung lượng Payload chống DoS / Tràn bộ nhớ máy chủ.
==============================================================================
"""

import secrets
import sys
from typing import List, Optional, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class APISecurity:
    """Bảo vệ và kiểm soát an ninh cho các giao diện lập trình API."""

    @staticmethod
    def validate_bearer_token(auth_header: Optional[str], valid_tokens: List[str]) -> Tuple[bool, str]:
        """Xác thực Bearer Token chuẩn mã hóa thời gian cố định chống Timing Attack."""
        if not auth_header or not auth_header.startswith("Bearer "):
            return False, "Thiếu hoặc sai định dạng Authorization Header (cần 'Bearer <token>')"
        token = auth_header.split(" ", 1)[1].strip()
        for expected in valid_tokens:
            if secrets.compare_digest(token, expected):
                return True, "Token hợp lệ"
        return False, "Bearer Token không hợp lệ hoặc đã hết hạn"

    @staticmethod
    def validate_content_type(content_type_header: Optional[str], expected: str = "application/json") -> bool:
        """Bắt buộc Content-Type phù hợp để ngăn chặn các kiểu request dị dạng."""
        if not content_type_header:
            return False
        return expected in content_type_header.lower()

    @staticmethod
    def validate_payload_size(content_length: Optional[int], max_bytes: int = 1048576) -> bool:
        """Giới hạn dung lượng tải trọng (mặc định 1MB = 1048576 bytes) chống DoS."""
        if content_length is None:
            return True
        return content_length <= max_bytes


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module APISecurity:")
    valid_key = "pbc_secure_api_key_2026"
    test_auth_good, msg_good = APISecurity.validate_bearer_token(f"Bearer {valid_key}", [valid_key])
    test_auth_bad, msg_bad = APISecurity.validate_bearer_token("Bearer invalid_key", [valid_key])
    test_ct = APISecurity.validate_content_type("application/json; charset=UTF-8")
    test_size_ok = APISecurity.validate_payload_size(1024)
    test_size_fail = APISecurity.validate_payload_size(5 * 1024 * 1024)

    print(f"  - Bearer Token đúng  : {test_auth_good} ({msg_good})")
    print(f"  - Bearer Token sai   : {test_auth_bad} ({msg_bad})")
    print(f"  - Content-Type JSON  : {test_ct}")
    print(f"  - Kích thước 1KB     : {test_size_ok} (Kỳ vọng: True)")
    print(f"  - Kích thước 5MB     : {test_size_fail} (Kỳ vọng: False - Bị từ chối)")
    print("[+] Hoàn thành kiểm thử APISecurity.")
