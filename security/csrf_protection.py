#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
CSRF (CROSS-SITE REQUEST FORGERY) PROTECTION MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Sinh Anti-CSRF Token ngẫu nhiên chuẩn mật mã (Cryptographically Secure).
- Quản lý phiên làm việc và gắn Token với từng Session ID.
- Thẩm thực Token bằng thuật toán so sánh thời gian cố định (Constant-time comparison)
  để ngăn chặn Timing Attack.
==============================================================================
"""

import secrets
import sys
import time
from typing import Any, Dict

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class CSRFProtection:
    """Sinh và kiểm tra Anti-CSRF Token gắn liền với phiên làm việc."""

    def __init__(self):
        # Lưu token theo session_id trong bộ nhớ đệm (thực tế dùng Redis hoặc Session DB)
        self._tokens: Dict[str, Dict[str, Any]] = {}

    def generate_token(self, session_id: str, lifetime_seconds: int = 3600) -> str:
        """Tạo CSRF Token an toàn bằng chuỗi ngẫu nhiên chuẩn mật mã."""
        token = secrets.token_urlsafe(32)
        self._tokens[session_id] = {
            "token": token,
            "expires_at": time.time() + lifetime_seconds
        }
        return token

    def validate_token(self, session_id: str, user_token: str) -> bool:
        """Xác thực token người dùng gửi lên với token hợp lệ của phiên."""
        if not session_id or not user_token:
            return False

        stored = self._tokens.get(session_id)
        if not stored:
            return False

        # Kiểm tra thời hạn hiệu lực
        if time.time() > stored["expires_at"]:
            del self._tokens[session_id]
            return False

        # So sánh an toàn chống tấn công đo lường thời gian (Timing Attack)
        return secrets.compare_digest(stored["token"], user_token)


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module CSRFProtection:")
    csrf = CSRFProtection()
    sess_id = "user_session_abc123"
    token = csrf.generate_token(sess_id, lifetime_seconds=10)
    print(f"  - Sinh mã CSRF Token : {token}")
    print(f"  - Thẩm thực mã đúng  : {csrf.validate_token(sess_id, token)} (Kỳ vọng: True)")
    print(f"  - Thẩm thực mã giả   : {csrf.validate_token(sess_id, 'fake_token')} (Kỳ vọng: False)")
    print("[+] Hoàn thành kiểm thử CSRFProtection.")
