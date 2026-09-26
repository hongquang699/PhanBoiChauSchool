#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
RATE LIMITING & ANTI-DOS/DDOS MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Giới hạn tần suất truy vấn theo địa chỉ IP sử dụng thuật toán Cửa sổ trượt (Sliding Window).
- Ngăn chặn các cuộc tấn công Từ chối dịch vụ (DoS / DDoS) tầng ứng dụng.
- Chống spam form gửi liên hệ và quét dữ liệu tự động (Web Scraping).
==============================================================================
"""

import sys
import time
from typing import Dict, List, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class RateLimiter:
    """Giới hạn số lượt request của một địa chỉ IP trong khoảng thời gian nhất định (Sliding Window)."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Cấu trúc: {ip: [timestamp1, timestamp2, ...]}
        self._history: Dict[str, List[float]] = {}

    def is_allowed(self, ip_address: str) -> Tuple[bool, int]:
        """
        Kiểm tra xem IP có được phép tiếp tục gửi request hay không.
        Trả về (được_phép_hay_không, số_lượt_còn_lại).
        """
        now = time.time()
        timestamps = self._history.get(ip_address, [])

        # Loại bỏ các timestamp đã quá thời hạn cửa sổ trượt
        valid_timestamps = [t for t in timestamps if now - t < self.window_seconds]

        if len(valid_timestamps) >= self.max_requests:
            self._history[ip_address] = valid_timestamps
            return False, 0

        valid_timestamps.append(now)
        self._history[ip_address] = valid_timestamps
        remaining = self.max_requests - len(valid_timestamps)
        return True, remaining


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module RateLimiter:")
    limiter = RateLimiter(max_requests=3, window_seconds=5)
    test_ip = "192.168.1.99"

    for i in range(1, 5):
        allowed, rem = limiter.is_allowed(test_ip)
        print(f"  - Request {i} từ {test_ip}: Được phép={allowed}, Còn lại={rem}")
    print("[+] Hoàn thành kiểm thử RateLimiter.")
