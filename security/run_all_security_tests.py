#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
TỔNG HỢP KIỂM THỬ BẢO MẬT TOÀN DIỆN (COMPREHENSIVE SECURITY TEST SUITE)
TRƯỜNG THPT CHUYÊN PHAN BỘI CHÂU - NGHỆ AN
==============================================================================
"""

import sys
import os
import time
import subprocess
import io

# Đảm bảo in Tiếng Việt UTF-8 mượt mà trên Windows console
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# Đảm bảo đường dẫn import thư viện
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

TESTS = [
    {
        "id": 1,
        "name": "Web Application Security (10 Modules)",
        "script": "security/app_security.py",
        "description": "XSS, SQLi, CSRF, Path Traversal, Access Control, Brute Force, Rate Limit, Anti-Phishing, API Security, Input Validator"
    },
    {
        "id": 2,
        "name": "Database Security & Password Policy",
        "script": "security/database_security.py",
        "description": "Bam PBKDF2 (600.000 vong), Salt 32-byte, Prepared Statements, Ma hoa du lieu hoc sinh, Kiem tra do phuc tap mat khau"
    },
    {
        "id": 3,
        "name": "File Upload Security (5-Step Pipeline)",
        "script": "security/upload_security.py",
        "description": "Kiem tra Extension, MIME/Magic Bytes, Gioi han dung luong 5MB, Quet ma doc, Luu tru an toan UUID"
    },
    {
        "id": 4,
        "name": "Security Logging & Audit Trail",
        "script": "security/logger.py",
        "description": "Ghi nhan su kien tan cong WAF, ra quet doc hai, vi pham tan suat, xuat dinh dang text & jsonl"
    },
    {
        "id": 5,
        "name": "Backup & Disaster Recovery Integrity",
        "script": "security/backup.py",
        "description": "Sao luu 3 nhanh (Database, Files/Media, Configs), nen du lieu, tinh ma bam SHA-256 toan ven"
    }
]

def run_single_test(test_info):
    print("\n" + "=" * 76)
    print(f"[*] CHAY KIEM THU [{test_info['id']}/5]: {test_info['name']}")
    print(f"[*] Mo ta: {test_info['description']}")
    print(f"[*] Script: {test_info['script']}")
    print("-" * 76)
    
    script_path = os.path.join(PROJECT_DIR, test_info["script"])
    start_time = time.time()
    
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    
    try:
        proc = subprocess.run(
            [sys.executable, script_path],
            cwd=PROJECT_DIR,
            capture_output=False,
            text=True,
            env=env
        )
        duration = round(time.time() - start_time, 2)
        success = (proc.returncode == 0)
        return {
            "id": test_info["id"],
            "name": test_info["name"],
            "status": "PASS" if success else "FAIL",
            "code": proc.returncode,
            "duration": f"{duration}s"
        }
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        print(f"[!] Loi khi thuc thi {test_info['script']}: {e}")
        return {
            "id": test_info["id"],
            "name": test_info["name"],
            "status": "ERROR",
            "code": -1,
            "duration": f"{duration}s"
        }

def main():
    print("=" * 76)
    print("      HE THONG KIEM THU AN TOAN BAO MAT (SECURITY AUDIT SUITE)")
    print("      TRUONG THPT CHUYEN PHAN BOI CHAU - NGHE AN")
    print("=" * 76)
    print(f"[*] Thoi gian bat dau : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Phien ban Python  : {sys.version.split()[0]}")
    print(f"[*] Thu muc du an     : {PROJECT_DIR}")
    print(f"[*] Tong so bai test  : {len(TESTS)}")

    target_id = None
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        target_id = int(sys.argv[1])

    results = []
    tests_to_run = [t for t in TESTS if target_id is None or t["id"] == target_id]

    if not tests_to_run:
        print(f"[!] Khong tim thay bai kiem thu voi ID: {target_id}")
        return 1

    total_start = time.time()
    for test in tests_to_run:
        res = run_single_test(test)
        results.append(res)

    total_duration = round(time.time() - total_start, 2)

    # In bang tong ket
    print("\n" + "=" * 76)
    print("                   BANG TONG KET KIEM THU BAO MAT")
    print("=" * 76)
    print(f"{'ID':<4} | {'Ten bai kiem thu':<42} | {'Thoi gian':<9} | {'Ket qua':<8}")
    print("-" * 76)
    
    all_passed = True
    for r in results:
        status_str = f"[OK] {r['status']}" if r["status"] == "PASS" else f"[X]  {r['status']}"
        print(f"{r['id']:<4} | {r['name']:<42} | {r['duration']:<9} | {status_str:<8}")
        if r["status"] != "PASS":
            all_passed = False

    print("=" * 76)
    print(f"[*] Tong thoi gian thuc thi: {total_duration}s")
    
    if all_passed:
        print("[+] DANH GIA: 100% CAC BAI KIEM THU BAO MAT DEU DAT CHUAN AN TOAN (PASSED)!")
        print("[+] He thong website Truong THPT Chuyen Phan Boi Chau san sang bao ve toan dien.")
        return 0
    else:
        print("[!] DANH GIA: Co bai kiem thu khong dat hoac phat hien loi an ninh can xu ly!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
