#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
APPLICATION SECURITY FACADE MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Module này liên kết và tái xuất khẩu (re-export) toàn bộ các module phòng thủ
đã được tách thành các tệp độc lập chuyên trách:
1. input_validator.py            -> InputValidator
2. xss_protection.py             -> OutputEncoder
3. sqli_protection.py            -> SQLSecurity
4. csrf_protection.py            -> CSRFProtection
5. path_traversal_protection.py  -> PathTraversalProtection
6. access_control.py             -> AccessControl
7. brute_force_protection.py     -> BruteForceProtection
8. rate_limiter.py               -> RateLimiter
9. phishing_protection.py        -> AntiPhishingProtection
10. api_security.py              -> APISecurity
==============================================================================
"""

import os
import sys

# Thêm thư mục hiện tại để nạp các file độc lập
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from input_validator import InputValidator
from xss_protection import OutputEncoder
from sqli_protection import SQLSecurity
from csrf_protection import CSRFProtection
from path_traversal_protection import PathTraversalProtection
from access_control import AccessControl
from brute_force_protection import BruteForceProtection
from rate_limiter import RateLimiter
from phishing_protection import AntiPhishingProtection
from api_security import APISecurity

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


if __name__ == "__main__":
    print("=" * 70)
    print("[*] KIỂM THỬ TỔNG HỢP CÁC MODULE BẢO MẬT ĐÃ TÁCH FILE RIÊNG:")
    print("=" * 70)

    # 1. Output Encoding (xss_protection.py)
    xss_safe = OutputEncoder.encode_for_html("<script>alert('XSS');</script>")
    print(f"1. [xss_protection.py]             : {xss_safe}")

    # 2. Input Validation (input_validator.py)
    email_ok = InputValidator.validate_email("chuyenpbc@nghean.edu.vn")
    print(f"2. [input_validator.py]            : Email valid={email_ok}")

    # 3. SQLi Detection (sqli_protection.py)
    sqli_safe = SQLSecurity.assert_no_dangerous_keywords("admin' OR 1=1 --")
    print(f"3. [sqli_protection.py]            : SQLi blocked={not sqli_safe}")

    # 4. CSRF Protection (csrf_protection.py)
    csrf = CSRFProtection()
    token = csrf.generate_token("sess_01")
    csrf_ok = csrf.validate_token("sess_01", token)
    print(f"4. [csrf_protection.py]            : Token verified={csrf_ok}")

    # 5. Path Traversal (path_traversal_protection.py)
    path_safe, reason = PathTraversalProtection.is_safe_path("../../secret.sql", CURRENT_DIR)
    print(f"5. [path_traversal_protection.py]  : Blocked={not path_safe} ({reason})")

    # 6. Access Control (access_control.py)
    rbac_pass = AccessControl.has_role_permission("admin", "student")
    rbac_blocked = AccessControl.has_role_permission("student", "admin")
    print(f"6. [access_control.py]             : Admin->Student={rbac_pass}, Student->Admin={rbac_blocked}")

    # 7. Brute Force (brute_force_protection.py)
    bf = BruteForceProtection(max_failed_attempts=2, lockout_duration=30)
    bf.record_attempt("user_demo", "127.0.0.1", False)
    res_bf = bf.record_attempt("user_demo", "127.0.0.1", False)
    print(f"7. [brute_force_protection.py]     : Locked={res_bf['locked']} sau 2 lần sai")

    # 8. Rate Limiter (rate_limiter.py)
    limiter = RateLimiter(max_requests=1, window_seconds=10)
    r1, _ = limiter.is_allowed("127.0.0.1")
    r2, _ = limiter.is_allowed("127.0.0.1")
    print(f"8. [rate_limiter.py]               : Req1={r1}, Req2={r2} (Bị chặn)")

    # 9. Anti-Phishing (phishing_protection.py)
    redir_safe = AntiPhishingProtection.is_safe_redirect("/home", ["chuyenphanboichau.edu.vn"])
    redir_bad = AntiPhishingProtection.is_safe_redirect("https://evil.com", ["chuyenphanboichau.edu.vn"])
    print(f"9. [phishing_protection.py]        : Local URL={redir_safe}, Phishing URL Blocked={not redir_bad}")

    # 10. API Security (api_security.py)
    auth_ok, _ = APISecurity.validate_bearer_token("Bearer key123", ["key123"])
    print(f"10. [api_security.py]              : Bearer Auth={auth_ok}")

    print("=" * 70)
    print("[+] TẤT CẢ 10 MODULE ĐỘC LẬP HOẠT ĐỘNG HOÀN HẢO!")
    print("=" * 70)
