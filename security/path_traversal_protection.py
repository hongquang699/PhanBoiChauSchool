#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
PATH TRAVERSAL & SENSITIVE FILE PROTECTION MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Ngăn chặn tấn công Path Traversal / Directory Traversal (chặn ../, ..\\\\, null-byte).
- Ngăn chặn tấn công File Inclusion (LFI/RFI).
- Bảo vệ các tệp tin cấu hình và dữ liệu nhạy cảm (.env, .git, .sql, .sh, logs, backups).
- Chuẩn hóa đường dẫn (Path Canonicalization) trước khi truy cập hệ thống file.
==============================================================================
"""

import os
import sys
import urllib.parse
from typing import List, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class PathTraversalProtection:
    """Kiểm tra và ngăn chặn các thao tác leo thang thư mục và truy cập file nhạy cảm."""

    BLOCKED_EXTENSIONS = (
        '.sql', '.sh', '.env', '.git', '.py', '.conf', '.htaccess',
        '.log', '.jsonl', '.bak', '.swp', '.ini'
    )

    BLOCKED_DIRECTORIES = (
        '/security/', '/logs/', '/backups/', '/.git/', '/__pycache__/',
        '/.vscode/', '/etc/', '/windows/'
    )

    @classmethod
    def is_safe_path(cls, requested_path: str, base_dir: str) -> Tuple[bool, str]:
        """
        Kiểm tra tính an toàn của đường dẫn tệp được yêu cầu.
        Trả về (an_toàn_hay_không, lý_do_từ_chối).
        """
        if not requested_path:
            return False, "Đường dẫn rỗng."

        decoded = urllib.parse.unquote(requested_path)

        # 1. Phát hiện ký tự điều hướng hoặc null-byte
        if '..' in decoded or '\\' in decoded or '\x00' in decoded or '%2e%2e' in requested_path.lower():
            return False, "Phát hiện ký tự leo thang thư mục (Path Traversal: ../, ..\\, null-byte)."

        # 2. Kiểm tra phần mở rộng bị cấm
        clean_path = decoded.split('?')[0].lower()
        for ext in cls.BLOCKED_EXTENSIONS:
            if clean_path.endswith(ext):
                return False, f"Truy cập bị từ chối: Tệp tin có phần mở rộng nhạy cảm ({ext})."

        # 3. Kiểm tra thư mục nội bộ bị khóa
        for b_dir in cls.BLOCKED_DIRECTORIES:
            if b_dir in clean_path:
                return False, f"Truy cập bị từ chối: Thư mục hệ thống nội bộ ({b_dir})."

        # 4. Canonicalization: Đường dẫn chuẩn hóa phải nằm bên trong base_dir
        try:
            rel_path = clean_path.lstrip('/')
            full_path = os.path.abspath(os.path.join(base_dir, rel_path))
            base_full = os.path.abspath(base_dir)
            if not full_path.startswith(base_full):
                return False, "Phát hiện đường dẫn trỏ ra ngoài thư mục gốc hệ thống."
        except Exception:
            return False, "Lỗi kiểm tra tính hợp lệ của đường dẫn."

        return True, "Hợp lệ"


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module PathTraversalProtection:")
    base = "c:/Users/admin/gioithieuPBC"
    test_cases = [
        ("../../Windows/win.ini", False),
        ("pages/../security/database_security.sql", False),
        ("pages/gioi-thieu.html", True),
        (".env", False),
        ("css/style.css", True),
        ("backups/db_backup.zip", False)
    ]

    for p, expected in test_cases:
        safe, reason = PathTraversalProtection.is_safe_path(p, base)
        print(f"  - Đường dẫn '{p}' -> An toàn: {safe} | Lý do: {reason}")
    print("[+] Hoàn thành kiểm thử PathTraversalProtection.")
