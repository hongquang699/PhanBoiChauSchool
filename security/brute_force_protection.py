#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
AUTHENTICATION ATTACKS DEFENSE MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Chống tấn công Brute Force (Vét cạn mật khẩu).
- Chống tấn công Credential Stuffing (Dùng tài khoản/mật khẩu rò rỉ từ dịch vụ khác).
- Chống tấn công Password Spraying (Thử một mật khẩu phổ biến trên nhiều tài khoản).
- Triển khai cơ chế Khóa tài khoản tạm thời (Account Lockout).
- Triển khai cơ chế Độ trễ lũy tiến (Progressive Delay).
==============================================================================
"""

import sys
import time
from typing import Any, Dict, List, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class BruteForceProtection:
    """Phòng vệ tấn công dò đoán mật khẩu tự động và vét cạn tài khoản."""

    def __init__(self, max_failed_attempts: int = 5, lockout_duration: int = 900):
        self.max_failed_attempts = max_failed_attempts
        self.lockout_duration = lockout_duration  # 15 phút = 900s
        # Lưu vết theo username/id: {identifier: {"failed_count": int, "locked_until": float, "last_attempt": float}}
        self._accounts: Dict[str, Dict[str, Any]] = {}
        # Lưu vết theo IP chống Password Spraying: {ip: [attempt_timestamps]}
        self._ip_attempts: Dict[str, List[float]] = {}

    def is_locked(self, identifier: str) -> Tuple[bool, int]:
        """Kiểm tra tài khoản có đang bị khóa hay không. Trả về (bị_khóa, số_giây_còn_lại)."""
        record = self._accounts.get(identifier)
        if not record:
            return False, 0

        locked_until = record.get("locked_until", 0)
        now = time.time()
        if now < locked_until:
            return True, int(locked_until - now)
        return False, 0

    def get_progressive_delay(self, identifier: str) -> float:
        """Tính toán độ trễ lũy tiến (giây) nhằm làm chậm tốc độ của bot vét cạn (1s, 2s, 4s, 8s...)."""
        record = self._accounts.get(identifier)
        if not record:
            return 0.0
        failed = record.get("failed_count", 0)
        if failed <= 1:
            return 0.0
        return min(2.0 ** (failed - 2), 16.0)

    def record_attempt(self, identifier: str, ip_address: str, success: bool) -> Dict[str, Any]:
        """
        Ghi nhận kết quả đăng nhập và xử lý khóa hoặc cảnh báo:
        - Thành công: Xóa đếm thất bại.
        - Thất bại: Tăng đếm, kích hoạt Lockout nếu vượt ngưỡng, kiểm tra rủi ro Password Spraying từ IP.
        """
        now = time.time()

        # Cập nhật lịch sử theo IP (theo dõi trong 5 phút = 300s)
        ip_list = [t for t in self._ip_attempts.get(ip_address, []) if now - t < 300]
        ip_list.append(now)
        self._ip_attempts[ip_address] = ip_list
        ip_spray_risk = len(ip_list) > 20

        if identifier not in self._accounts:
            self._accounts[identifier] = {"failed_count": 0, "locked_until": 0, "last_attempt": now}

        record = self._accounts[identifier]
        record["last_attempt"] = now

        if success:
            record["failed_count"] = 0
            record["locked_until"] = 0
            return {
                "status": "SUCCESS",
                "locked": False,
                "remaining_attempts": self.max_failed_attempts
            }

        record["failed_count"] += 1
        failed = record["failed_count"]

        if failed >= self.max_failed_attempts:
            record["locked_until"] = now + self.lockout_duration
            return {
                "status": "LOCKED",
                "locked": True,
                "lockout_seconds": self.lockout_duration,
                "reason": f"Khóa tạm thời do nhập sai {failed} lần liên tiếp."
            }

        delay = self.get_progressive_delay(identifier)
        return {
            "status": "FAILED",
            "locked": False,
            "failed_attempts": failed,
            "remaining_attempts": self.max_failed_attempts - failed,
            "progressive_delay_seconds": delay,
            "password_spray_risk": ip_spray_risk
        }


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module BruteForceProtection:")
    shield = BruteForceProtection(max_failed_attempts=3, lockout_duration=60)
    user = "teacher_demo"
    ip = "192.168.1.15"

    for i in range(1, 4):
        res = shield.record_attempt(user, ip, success=False)
        print(f"  - Lần thử sai {i}: Status={res['status']}, Locked={res['locked']}")

    is_lck, rem = shield.is_locked(user)
    print(f"  -> Kiểm tra tài khoản {user}: Bị khóa={is_lck}, Mở lại sau={rem}s")
    print("[+] Hoàn thành kiểm thử BruteForceProtection.")
