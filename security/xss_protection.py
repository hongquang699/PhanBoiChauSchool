#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
CROSS-SITE SCRIPTING (XSS) PROTECTION MODULE - THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Mục đích:
- Chống tấn công Cross-Site Scripting (Reflected XSS, Stored XSS, DOM XSS).
- Triển khai kỹ thuật Output Encoding (Mã hóa thực thể HTML).
- Mã hóa ký tự đặc biệt `<`, `>`, `&`, `"`, `'`, `\\` thành các entities an toàn.
==============================================================================
"""

import html
import sys
from typing import Any

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class OutputEncoder:
    """Mã hóa thực thể HTML để đảm bảo an toàn tuyệt đối khi render dữ liệu ra trình duyệt."""

    @staticmethod
    def encode_for_html(data: Any) -> str:
        """Chuyển đổi <, >, &, ", ' thành các HTML entities tương ứng (&lt;, &gt;, &amp;, &quot;, &#x27;)."""
        if data is None:
            return ""
        return html.escape(str(data), quote=True)

    @staticmethod
    def encode_for_attribute(data: Any) -> str:
        """Mã hóa đặc biệt khi nhúng vào thuộc tính HTML (ví dụ value="...", href="...")."""
        raw = OutputEncoder.encode_for_html(data)
        # Bổ sung mã hóa dấu gạch chéo ngược
        return raw.replace('\\', '&#x5C;')

    @staticmethod
    def encode_for_javascript(data: Any) -> str:
        """Mã hóa an toàn khi nhúng dữ liệu vào ngữ cảnh JavaScript inline."""
        if data is None:
            return ""
        s = str(data)
        # Thay thế các ký tự nguy hiểm thành unicode escape
        return s.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'").replace('<', '\\u003C').replace('>', '\\u003E')


if __name__ == "__main__":
    print("[*] Kiểm thử độc lập module OutputEncoder (Chống XSS):")
    xss_payload = "<script>alert('Chiếm đoạt Cookie!');</script>"
    encoded_html = OutputEncoder.encode_for_html(xss_payload)
    encoded_attr = OutputEncoder.encode_for_attribute('"><img src=x onerror=alert(1)>')

    print(f"  - Payload XSS gốc    : {xss_payload}")
    print(f"  - HTML Encoded       : {encoded_html}")
    print(f"  - Attribute Encoded  : {encoded_attr}")
    print("[+] Hoàn thành kiểm thử XSS OutputEncoder.")
