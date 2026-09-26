#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
SECURITY LOGGING & MONITORING MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Ghi nhận và giám sát an ninh tập trung:
- Request bất thường (Abnormal requests)
- Lỗi máy chủ (5xx Server Errors)
- Các lần truy cập đáng ngờ (Suspicious accesses / Brute force)
- Tấn công bị WAF chặn (SQLi, XSS, Path Traversal)
- Lưu Security Log có xoay vòng file (Log Rotation)
==============================================================================
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class SecurityLogger:
    """Hệ thống ghi nhật ký an ninh chuyên dụng cho Website Trường THPT Chuyên PBC."""

    # Phân loại mức độ nghiêm trọng
    LEVEL_INFO = "INFO"           # Đăng nhập thành công, thao tác thông thường
    LEVEL_WARNING = "WARNING"     # Thử truy cập sai mật khẩu 1-2 lần, request thiếu header
    LEVEL_ALERT = "ALERT"         # Vi phạm Rate Limit, quét thư mục ẩn
    LEVEL_CRITICAL = "CRITICAL"   # Tấn công SQLi, XSS, leo thang đặc quyền, upload shell

    DEFAULT_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")

    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = log_dir or self.DEFAULT_LOG_DIR
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, "security_events.log")
        self.json_log_file = os.path.join(self.log_dir, "security_events.jsonl")

        # Khởi tạo Python Logger chuẩn
        self.logger = logging.getLogger("PBC_SecurityAudit")
        self.logger.setLevel(logging.INFO)

        # Tránh gán trùng handler
        if not self.logger.handlers:
            # Ghi log text có xoay vòng (tối đa 10MB mỗi file, lưu tối đa 10 file backup)
            file_handler = RotatingFileHandler(
                self.log_file, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
            )
            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def log_event(
        self,
        event_type: str,
        severity: str,
        ip_address: str,
        user_agent: str,
        endpoint: str,
        details: Dict[str, Any],
        action_taken: str = "BLOCKED"
    ) -> Dict[str, Any]:
        """Ghi nhận một sự kiện an ninh vào hệ thống."""
        timestamp_iso = datetime.now(timezone.utc).isoformat()

        
        event_record = {
            "timestamp": timestamp_iso,
            "event_type": event_type,
            "severity": severity,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "endpoint": endpoint,
            "action_taken": action_taken,
            "details": details
        }

        # Ghi dạng Text Format
        log_msg = (
            f"[{severity}] [{event_type}] IP:{ip_address} Path:{endpoint} "
            f"Action:{action_taken} Details:{json.dumps(details, ensure_ascii=False)}"
        )
        if severity == self.LEVEL_CRITICAL:
            self.logger.critical(log_msg)
        elif severity == self.LEVEL_ALERT or severity == self.LEVEL_WARNING:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)

        # Ghi dạng JSON Lines (JSONL) thuận tiện cho hệ thống SIEM (ELK, Splunk, Grafana Loki)
        try:
            with open(self.json_log_file, "a", encoding="utf-8") as jf:
                jf.write(json.dumps(event_record, ensure_ascii=False) + "\n")
        except Exception:
            pass

        return event_record

    # --------------------------------------------------------------------------
    # CÁC HÀM TIỆN ÍCH GHI LOG AN NINH ĐẶC THÙ
    # --------------------------------------------------------------------------
    def log_waf_block(self, ip: str, ua: str, endpoint: str, attack_pattern: str, raw_payload: str):
        """Ghi nhận tấn công bị WAF chặn (SQLi, XSS...)."""
        return self.log_event(
            event_type="WAF_ATTACK_BLOCKED",
            severity=self.LEVEL_CRITICAL,
            ip_address=ip,
            user_agent=ua,
            endpoint=endpoint,
            action_taken="DROPPED_403",
            details={
                "attack_pattern": attack_pattern,
                "sample_payload": raw_payload[:200]
            }
        )

    def log_suspicious_access(self, ip: str, ua: str, endpoint: str, reason: str):
        """Ghi nhận truy cập đáng ngờ (quét file ẩn .git, .env, admin panel)."""
        return self.log_event(
            event_type="SUSPICIOUS_PROBING",
            severity=self.LEVEL_ALERT,
            ip_address=ip,
            user_agent=ua,
            endpoint=endpoint,
            action_taken="REJECTED_404_OR_403",
            details={"reason": reason}
        )

    def log_rate_limit_exceeded(self, ip: str, endpoint: str, request_count: int):
        """Ghi nhận vi phạm tần suất gửi truy vấn."""
        return self.log_event(
            event_type="RATE_LIMIT_EXCEEDED",
            severity=self.LEVEL_WARNING,
            ip_address=ip,
            user_agent="Unknown/Browser",
            endpoint=endpoint,
            action_taken="THROTTLED_429",
            details={"request_count": request_count, "limit": "20r/s"}
        )

    def log_server_error(self, endpoint: str, error_trace: str, status_code: int = 500):
        """Ghi nhận lỗi 500 nội bộ máy chủ để điều tra lỗ hổng."""
        return self.log_event(
            event_type="INTERNAL_SERVER_ERROR",
            severity=self.LEVEL_ALERT,
            ip_address="127.0.0.1",
            user_agent="System",
            endpoint=endpoint,
            action_taken="LOGGED_FOR_AUDIT",
            details={"status_code": status_code, "error_summary": error_trace[:300]}
        )


# ==============================================================================
# KIỂM THỬ GHI NHẬT KÝ AN NINH
# ==============================================================================
if __name__ == "__main__":
    print("[*] Kiểm thử Security Logger & Monitoring:")
    sec_log = SecurityLogger()

    # 1. Ghi nhận tấn công SQLi bị WAF chặn
    e1 = sec_log.log_waf_block(
        ip="203.113.152.12",
        ua="sqlmap/1.7.2#stable",
        endpoint="/pages/tin-tuc.html?id=1",
        attack_pattern="SQL_INJECTION_UNION_SELECT",
        raw_payload="1' UNION SELECT 1,group_concat(username,password) FROM users--"
    )
    print(f"  [Log 1] {e1['event_type']} - Mức độ: {e1['severity']} - IP: {e1['ip_address']}")

    # 2. Ghi nhận rà quét file ẩn
    e2 = sec_log.log_suspicious_access(
        ip="118.70.188.45",
        ua="Mozilla/5.0",
        endpoint="/.env",
        reason="Thử dò quét file chứa thông tin cấu hình nhạy cảm"
    )
    print(f"  [Log 2] {e2['event_type']} - Mức độ: {e2['severity']} - Đường dẫn: {e2['endpoint']}")

    # 3. Ghi nhận vi phạm Rate Limit
    e3 = sec_log.log_rate_limit_exceeded(
        ip="42.112.24.89",
        endpoint="/index.html",
        request_count=85
    )
    print(f"  [Log 3] {e3['event_type']} - Mức độ: {e3['severity']} - Thao tác: {e3['action_taken']}")

    print(f"[+] Nhật ký an ninh đã ghi thành công vào: {sec_log.log_file}")
