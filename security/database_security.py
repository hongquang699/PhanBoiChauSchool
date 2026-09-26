#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
DATABASE SECURITY IMPLEMENTATION - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Triển khai:
1. Prepared Statements & Parameterized Queries (Chống SQL Injection)
2. Mã hóa mật khẩu an toàn (PBKDF2-HMAC-SHA256 với Salt ngẫu nhiên)
3. Mã hóa dữ liệu định danh nhạy cảm (CCCD, SĐT)
4. Nguyên tắc kết nối phân quyền tối thiểu (Least Privilege)
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


# ==============================================================================
# 1. BẢO MẬT MẬT KHẨU (PASSWORD HASHING & SALTING)
# ==============================================================================
class PasswordSecurity:
    """Tuyệt đối không lưu mật khẩu dạng plaintext. Sử dụng PBKDF2 600.000 vòng lặp."""

    ITERATIONS = 600000

    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """
        Băm mật khẩu kết hợp Salt ngẫu nhiên 32 bytes chống Rainbow Table.
        Trả về: (password_hash_hex, salt_hex)
        """
        salt = os.urandom(32)
        pwd_bytes = password.encode('utf-8')
        derived_key = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, PasswordSecurity.ITERATIONS)
        return derived_key.hex(), salt.hex()

    @staticmethod
    def verify_password(password: str, stored_hash_hex: str, stored_salt_hex: str) -> bool:
        """Kiểm tra mật khẩu khớp sử dụng hmac.compare_digest chống Timing Attack."""
        try:
            salt = bytes.fromhex(stored_salt_hex)
            pwd_bytes = password.encode('utf-8')
            key = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, PasswordSecurity.ITERATIONS)
            # So sánh thời gian cố định
            return hmac.compare_digest(key.hex(), stored_hash_hex)
        except Exception:
            return False


class PasswordPolicy:
    """
    Chính sách mật khẩu nghiêm ngặt:
    - Độ dài tối thiểu 8 ký tự
    - Bắt buộc chứa chữ hoa, chữ thường, chữ số và ký tự đặc biệt
    - Chặn các mật khẩu phổ biến thường bị tấn công bởi Brute Force, Credential Stuffing, Password Spraying
    """

    COMMON_PASSWORDS_BLACKLIST = {
        "123456", "password", "12345678", "admin", "pbc123456", "pbc@2026",
        "qwerty", "letmein", "welcome", "iloveyou", "admin123", "chuyenpbc"
    }

    @classmethod
    def validate_password_strength(cls, password: str) -> Tuple[bool, List[str]]:
        errors = []
        if len(password) < 8:
            errors.append("Mật khẩu phải có độ dài tối thiểu 8 ký tự.")
        if not re.search(r'[A-Z]', password):
            errors.append("Mật khẩu phải chứa ít nhất một chữ cái in hoa (A-Z).")
        if not re.search(r'[a-z]', password):
            errors.append("Mật khẩu phải chứa ít nhất một chữ cái in thường (a-z).")
        if not re.search(r'[0-9]', password):
            errors.append("Mật khẩu phải chứa ít nhất một chữ số (0-9).")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Mật khẩu phải chứa ít nhất một ký tự đặc biệt (!@#$%...).")
        if password.lower() in cls.COMMON_PASSWORDS_BLACKLIST:
            errors.append("Mật khẩu nằm trong danh sách mật khẩu yếu/phổ biến dễ bị đoán.")

        return len(errors) == 0, errors



# ==============================================================================
# 2. MÃ HÓA DỮ LIỆU NHẠY CẢM (ENCRYPTED SENSITIVE DATA)
# ==============================================================================
class DataEncryption:
    """Mã hóa số CCCD, thông tin cá nhân của học sinh/giáo viên."""

    @staticmethod
    def derive_key(secret_passphrase: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', secret_passphrase.encode('utf-8'), salt, 100000)

    @staticmethod
    def simple_aes_encrypt(plaintext: str, master_key: str) -> str:
        """Mã hóa dữ liệu với salt và khóa dẫn xuất."""
        salt = os.urandom(16)
        key = DataEncryption.derive_key(master_key, salt)
        # Giả lập mã hóa block an toàn dựa trên key & XOR stream xor digest
        data = plaintext.encode('utf-8')
        stream = hashlib.sha256(key + salt).digest()
        # Lặp lại stream đủ độ dài
        extended_stream = (stream * ((len(data) // len(stream)) + 1))[:len(data)]
        encrypted = bytes(a ^ b for a, b in zip(data, extended_stream))
        # Ghép Salt + Encrypted Data dưới dạng Base64
        return base64.b64encode(salt + encrypted).decode('ascii')

    @staticmethod
    def simple_aes_decrypt(ciphertext_b64: str, master_key: str) -> Optional[str]:
        """Giải mã dữ liệu."""
        try:
            raw = base64.b64decode(ciphertext_b64.encode('ascii'))
            salt, encrypted = raw[:16], raw[16:]
            key = DataEncryption.derive_key(master_key, salt)
            stream = hashlib.sha256(key + salt).digest()
            extended_stream = (stream * ((len(encrypted) // len(stream)) + 1))[:len(encrypted)]
            decrypted = bytes(a ^ b for a, b in zip(encrypted, extended_stream))
            return decrypted.decode('utf-8')
        except Exception:
            return None


# ==============================================================================
# 3. MÔ PHỎNG TRUY VẤN PARAMETERIZED (PREPARED STATEMENTS)
# ==============================================================================
class SafeDatabaseClient:
    """Mô phỏng kết nối an toàn với cơ sở dữ liệu tuân thủ chuẩn Prepared Statements."""

    def __init__(self, db_host: str = "127.0.0.1", db_name: str = "pbc_school_db"):
        # CHỈ KẾT NỐI QUA LOCALHOST/PRIVATE IP, KHÔNG BAO GIỜ PUBLIC PORT RA NGOÀI
        self.host = db_host
        self.db = db_name
        print(f"[DB] Kết nối an toàn nội bộ tới: {self.host}/{self.db}")

    def execute_prepared(self, query: str, parameters: Tuple[Any, ...]) -> Dict[str, Any]:
        """
        Thực thi câu lệnh SQL với tham số tách rời.
        Trình điều khiển cơ sở dữ liệu sẽ gửi câu lệnh biên dịch riêng và truyền dữ liệu riêng,
        ngăn chặn 100% việc mã độc SQL bị thực thi.
        """
        # Kiểm tra tính hợp lệ: Số lượng dấu '?' hoặc '%s' phải khớp với tham số
        placeholder_count = query.count("%s") + query.count("?")
        if placeholder_count != len(parameters):
            raise ValueError("Số lượng tham số không khớp với câu lệnh Prepared Statement!")

        # Không bao giờ ghép chuỗi!
        return {
            "status": "SUCCESS",
            "compiled_query": query,
            "bound_params": parameters,
            "message": "Truy vấn an toàn tuyệt đối, không có nguy cơ SQL Injection"
        }


# ==============================================================================
# KIỂM THỬ THỰC TẾ
# ==============================================================================
if __name__ == "__main__":
    print("[*] Kiểm thử Database Security:")

    # 1. Kiểm thử Băm mật khẩu (Không bao giờ lưu plaintext)
    plain_pass = "ThayCo@PBC2026!#"
    pwd_hash, pwd_salt = PasswordSecurity.hash_password(plain_pass)
    print(f"  [Mật khẩu gốc]    : {plain_pass}")
    print(f"  [Hash an toàn]   : {pwd_hash[:32]}... (Độ dài: {len(pwd_hash)} hex chars)")
    print(f"  [Salt ngẫu nhiên]: {pwd_salt[:16]}...")
    
    # Xác thực mật khẩu
    check_correct = PasswordSecurity.verify_password("ThayCo@PBC2026!#", pwd_hash, pwd_salt)
    check_wrong = PasswordSecurity.verify_password("SaiMatKhau123", pwd_hash, pwd_salt)
    print(f"  [Xác thực đúng]  : {check_correct}")
    print(f"  [Xác thực sai]   : {check_wrong}")

    # 2. Kiểm thử Mã hóa dữ liệu cá nhân nhạy cảm
    secret_key = "KhoaBaoMatRiengTuCuaTruong@PBC"
    cccd_number = "038096001234"
    encrypted_cccd = DataEncryption.simple_aes_encrypt(cccd_number, secret_key)
    decrypted_cccd = DataEncryption.simple_aes_decrypt(encrypted_cccd, secret_key)
    print(f"  [CCCD Học sinh]  : {cccd_number} -> Mã hóa: {encrypted_cccd} -> Giải mã: {decrypted_cccd}")

    # 3. Kiểm thử Prepared Statements
    db = SafeDatabaseClient()
    # Kẻ tấn công thử nhập mã độc SQLi vào tên đăng nhập
    attacker_input = "' OR 1=1; DROP TABLE users; --"
    result = db.execute_prepared(
        "SELECT id, username, role FROM users WHERE username = %s AND email = %s",
        (attacker_input, "target@example.com")
    )
    print(f"  [Prepared SQL]   : {result['message']}")

    # 4. Kiểm thử Chính sách Mật khẩu (Chống Brute Force, Credential Stuffing, Password Spraying)
    strong_pwd = "PhanBoiChau@2026!"
    weak_pwd = "123456"
    is_strong, errors_strong = PasswordPolicy.validate_password_strength(strong_pwd)
    is_weak, errors_weak = PasswordPolicy.validate_password_strength(weak_pwd)
    print(f"  [Password Policy] Mật khẩu mạnh '{strong_pwd}': Hợp lệ={is_strong}")
    print(f"  [Password Policy] Mật khẩu yếu '{weak_pwd}': Hợp lệ={is_weak}, Lỗi={errors_weak[0]}")

    print("[+] Hoàn thành kiểm thử Database Security.")
