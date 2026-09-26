#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
SECURITY PACKAGE - TRƯỜNG THPT CHUYÊN PHAN BỘI CHÂU - NGHỆ AN
==============================================================================
Tổ chức phân tầng độc lập theo từng hình thức tấn công & phòng ngự:

1. Web Attacks:
   - SQL Injection          -> sqli_protection.py (SQLSecurity)
   - Cross-Site Scripting   -> xss_protection.py (OutputEncoder)
   - CSRF                   -> csrf_protection.py (CSRFProtection)
   - Path Traversal / LFI   -> path_traversal_protection.py (PathTraversalProtection)
   - Broken Access Control  -> access_control.py (AccessControl)

2. Authentication Attacks:
   - Brute Force            -> brute_force_protection.py (BruteForceProtection)
   - Password Spraying      -> brute_force_protection.py
   - Credential Stuffing    -> brute_force_protection.py
   - Phishing & Clickjack   -> phishing_protection.py (AntiPhishingProtection)

3. Network & Infrastructure:
   - DoS / DDoS Mitigation  -> rate_limiter.py (RateLimiter)
   - Server Hardening       -> nginx.conf, firewall.sh, waf_rules.conf

4. API Security:
   - Token & Payload Guard  -> api_security.py (APISecurity)

5. Input Validation:
   - Whitelist & Sanitize   -> input_validator.py (InputValidator)

6. Data & Database:
   - DB Security & Policy   -> database_security.py (PasswordSecurity, PasswordPolicy, DataEncryption)
   - Backup & Recovery      -> backup.py (SystemBackup)

7. Logging & Monitoring:
   - Security Audit Logs    -> logger.py (SecurityLogger)

8. File & Malware:
   - 5-Step Upload Pipeline -> upload_security.py (FileUploadSecurity)
==============================================================================
"""

from security.input_validator import InputValidator
from security.xss_protection import OutputEncoder
from security.sqli_protection import SQLSecurity
from security.csrf_protection import CSRFProtection
from security.path_traversal_protection import PathTraversalProtection
from security.access_control import AccessControl
from security.brute_force_protection import BruteForceProtection
from security.rate_limiter import RateLimiter
from security.phishing_protection import AntiPhishingProtection
from security.api_security import APISecurity
from security.logger import SecurityLogger
from security.database_security import PasswordSecurity, PasswordPolicy, DataEncryption, SafeDatabaseClient
from security.upload_security import FileSecurityManager
from security.backup import BackupRecoveryManager

__all__ = [
    "InputValidator",
    "OutputEncoder",
    "SQLSecurity",
    "CSRFProtection",
    "PathTraversalProtection",
    "AccessControl",
    "BruteForceProtection",
    "RateLimiter",
    "AntiPhishingProtection",
    "APISecurity",
    "SecurityLogger",
    "PasswordSecurity",
    "PasswordPolicy",
    "DataEncryption",
    "SafeDatabaseClient",
    "FileSecurityManager",
    "BackupRecoveryManager",
]

