#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
ANTI-PHISHING & DOMAIN INTEGRITY MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Chống tấn công giả mạo (Phishing) và chiếm quyền hiển thị (Clickjacking).
- Ngăn chặn lỗ hổng Open Redirect (Chuyển hướng người dùng tới trang web lừa đảo).
- Cung cấp tiêu chuẩn Security Headers bắt buộc: CSP frame-ancestors, HSTS, X-Frame-Options.
==============================================================================
"""

import sys
from typing import Dict, List

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class AntiPhishingProtection:
    """Cung cấp các tiêu chuẩn và kiểm tra an ninh ngăn chặn Phishing & Clickjacking."""

    @staticmethod
    def get_recommended_security_headers() -> Dict[str, str]:
        """Tập hợp các header bắt buộc phải có để chống giả mạo và bảo vệ danh tính website."""
        return {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": (
                "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; "
                "img-src 'self' data: https:; media-src 'self'; frame-ancestors 'self'; object-src 'none';"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
        }

    @staticmethod
    def is_safe_redirect(redirect_url: str, allowed_hosts: List[str]) -> bool:
        """
        Chống Open Redirect:
        - Cho phép đường dẫn tương đối nội bộ (ví dụ: `/pages/tin-tuc.html`).
        - Cấm đường dẫn giả lập giao thức kép (ví dụ: `//attacker.com`).
        - Chỉ cho phép chuyển hướng ra ngoài nếu tên miền nằm trong Whitelist chính thức.
        """
        if not redirect_url or not isinstance(redirect_url, str):
            return False

        stripped = redirect_url.strip()

        # Đường dẫn tương đối hợp lệ
        if stripped.startswith("/") and not stripped.startswith("//") and not stripped.startswith("/\\"):
            return True

        # Đường dẫn tuyệt đối phải nằm trong Whitelist
        for host in allowed_hosts:
            if stripped.startswith(f"https://{host}") or stripped.startswith(f"http://{host}"):
                return True

        return False


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module AntiPhishingProtection:")
    trusted_domains = ["chuyenphanboichau.edu.vn", "localhost:8080"]

    urls_to_test = [
        ("/pages/thanh-tich.html", True),
        ("//evil-phishing-site.com/login", False),
        ("https://chuyenphanboichau.edu.vn/portal", True),
        ("https://pbc-fake-login.attacker.com", False)
    ]

    for u, expected in urls_to_test:
        safe = AntiPhishingProtection.is_safe_redirect(u, trusted_domains)
        print(f"  - URL: '{u}' -> An toàn?: {safe} (Kỳ vọng: {expected})")

    headers = AntiPhishingProtection.get_recommended_security_headers()
    print(f"  - Số lượng Security Headers chuẩn: {len(headers)}")
    print("[+] Hoàn thành kiểm thử AntiPhishingProtection.")
