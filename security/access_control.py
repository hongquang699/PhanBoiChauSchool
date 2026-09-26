#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
ACCESS CONTROL & RBAC MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Chống tấn công Broken Access Control (Hỏng kiểm soát quyền truy cập).
- Triển khai phân quyền theo vai trò (Role-Based Access Control - RBAC).
- Ngăn chặn lỗ hổng IDOR (Insecure Direct Object Reference) bằng kiểm tra
  thẩm quyền sở hữu tài nguyên thực tế tại Server.
==============================================================================
"""

import sys
from typing import Any, Dict, List

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class AccessControl:
    """
    Phòng thủ chống Broken Access Control & IDOR:
    - Phân cấp vai trò: Admin > Teacher > Student > Guest.
    - Nguyên tắc "Mặc định từ chối" (Default Deny).
    """

    ROLES_HIERARCHY: Dict[str, int] = {
        "admin": 4,      # Quản trị viên hệ thống (toàn quyền quản trị)
        "teacher": 3,    # Giáo viên (quản lý lớp, nhập điểm, duyệt bài)
        "student": 2,    # Học sinh (xem kết quả, nộp bài, đọc tin tức)
        "guest": 1       # Khách vãng lai (chỉ xem thông tin công khai)
    }

    @classmethod
    def has_role_permission(cls, user_role: str, min_required_role: str) -> bool:
        """Kiểm tra cấp độ quyền của người dùng có thỏa mãn quyền tối thiểu yêu cầu."""
        if not user_role:
            return False
        user_level = cls.ROLES_HIERARCHY.get(user_role.lower(), 0)
        req_level = cls.ROLES_HIERARCHY.get(min_required_role.lower(), 999)
        return user_level >= req_level

    @classmethod
    def verify_ownership(cls, current_user_id: Any, resource_owner_id: Any, current_user_role: str) -> bool:
        """
        Chống lỗ hổng IDOR (Insecure Direct Object Reference).
        Admin luôn có quyền truy cập kiểm toán. Người dùng thông thường chỉ được xem/sửa
        tài nguyên do chính mình sở hữu.
        """
        if not current_user_id:
            return False
        if current_user_role.lower() == "admin":
            return True
        return str(current_user_id) == str(resource_owner_id)


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module AccessControl (RBAC & Chống IDOR):")
    can_teacher_read = AccessControl.has_role_permission("teacher", "student")
    can_student_admin = AccessControl.has_role_permission("student", "admin")
    owner_check_pass = AccessControl.verify_ownership("hs101", "hs101", "student")
    owner_check_fail = AccessControl.verify_ownership("hs101", "hs999", "student")

    print(f"  - Giáo viên truy cập quyền học sinh  : {can_teacher_read} (Kỳ vọng: True)")
    print(f"  - Học sinh truy cập trang Admin      : {can_student_admin} (Kỳ vọng: False - Bị chặn)")
    print(f"  - Học sinh xem hồ sơ của mình        : {owner_check_pass} (Kỳ vọng: True)")
    print(f"  - Học sinh xem hồ sơ người khác(IDOR): {owner_check_fail} (Kỳ vọng: False - Bị chặn)")
    print("[+] Hoàn thành kiểm thử AccessControl.")
