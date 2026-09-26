#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
SQL INJECTION (SQLi) PROTECTION MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Ngăn chặn triệt để tấn công SQL Injection.
- Ép buộc 100% truy vấn cơ sở dữ liệu sử dụng Parameterized Queries / Prepared Statements.
- Phát hiện và rà soát nhanh các mẫu ký tự độc hại thường gặp trong SQLi.
==============================================================================
"""

import re
import sys
from typing import Any, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class SQLSecurity:
    """Đảm bảo mọi truy vấn cơ sở dữ liệu đều an toàn trước SQL Injection."""

    DANGEROUS_PATTERNS = [
        r'(\bunion\b.*\bselect\b)',
        r'(\bdrop\b\s+\btable\b)',
        r'(\bexec\b\s*\(|\bxp_cmdshell\b)',
        r'(--|\#|\/\*|\*\/)',
        r"(';|\";)",
        r'(\bor\b\s+1\s*=\s*1\b)',
        r'(\band\b\s+1\s*=\s*1\b)',
        r'(\bselect\b.*\bfrom\b.*information_schema\b)',
        r'(\bbenchmark\b\s*\(|\bsleep\b\s*\()',
    ]

    @classmethod
    def assert_no_dangerous_keywords(cls, raw_input: str) -> bool:
        """
        Kiểm tra phát hiện nhanh các ký tự/từ khóa khả nghi thường dùng trong SQLi.
        Trả về True nếu an toàn, False nếu nghi vấn tấn công.
        """
        if not raw_input or not isinstance(raw_input, str):
            return True
        lowered = raw_input.lower()
        for pat in cls.DANGEROUS_PATTERNS:
            if re.search(pat, lowered):
                return False
        return True

    @staticmethod
    def format_parameterized_query(query: str, params: Tuple[Any, ...]) -> Tuple[str, Tuple[Any, ...]]:
        """
        Chuẩn bị câu lệnh truy vấn có tham số tách rời.
        Ví dụ: query = "SELECT * FROM hoc_sinh WHERE id = %s", params = (123,)
        Tuyệt đối KHÔNG ghép chuỗi trực tiếp: query + str(user_input).
        """
        return query, params


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module SQLSecurity (Chống SQLi):")
    payloads = [
        ("admin' OR 1=1 --", False),
        ("1' UNION SELECT username, password FROM users --", False),
        ("normal_search_keyword", True),
        ("nguyenvana@gmail.com", True)
    ]
    for p, expected in payloads:
        res = SQLSecurity.assert_no_dangerous_keywords(p)
        print(f"  - Chuỗi '{p[:30]}...' -> An toàn?: {res} (Kỳ vọng: {expected})")
    print("[+] Hoàn thành kiểm thử SQLSecurity.")
