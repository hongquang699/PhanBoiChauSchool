#!/bin/bash
# ==============================================================================
# KỊCH BẢN THIẾT LẬP TƯỜNG LỬA (FIREWALL) CHO MÁY CHỦ WEBSITE TRƯỜNG THPT CHUYÊN PBC
# Sử dụng: UFW (Uncomplicated Firewall) & iptables Rules
# ==============================================================================

echo "=========================================================="
echo "    KHỞI TẠO CẤU HÌNH TƯỜNG LỬA MÁY CHỦ (FIREWALL SETUP)  "
echo "=========================================================="

# Đảm bảo kịch bản chạy với quyền root
if [ "$EUID" -ne 0 ]; then
  echo "Lỗi: Vui lòng chạy kịch bản này dưới quyền root (sudo ./firewall.sh)"
  exit 1
fi

# 1. THIẾT LẬP CHÍNH SÁCH MẶC ĐỊNH CHO UFW
echo "[+] Thiết lập chính sách mặc định: Chặn toàn bộ kết nối đến (DROP)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# 2. MỞ CÁC CỔNG DỊCH VỤ CẦN THIẾT
echo "[+] Cho phép cổng 80 (HTTP) để điều hướng sang HTTPS"
ufw allow 80/tcp comment "HTTP Port Redirect"

echo "[+] Cho phép cổng 443 (HTTPS) mã hóa an toàn"
ufw allow 443/tcp comment "HTTPS Secure Port"

echo "[+] Cấu hình cổng SSH (Khuyến nghị đổi sang cổng bảo mật, ví dụ 2222)"
# Giới hạn số lần thử kết nối SSH (chống Brute Force)
ufw limit 22/tcp comment "SSH Rate Limited"

# 3. QUY TẮC IPTABLES BẢO VỆ CHỐNG TẤN CÔNG MẠNG PHỔ BIẾN
echo "[+] Kích hoạt quy tắc iptables chống SYN Flood và gói tin dị dạng..."

# Chặn gói tin Null, XMAS, FIN scan (thường do nmap/hacker rà quét)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Chống tấn công SYN Flood
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 40 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Chặn tấn công Ping of Death / ICMP Flood
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# Giới hạn số lượng kết nối đồng thời từ cùng 1 IP
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j REJECT

# 4. KÍCH HOẠT TƯỜNG LỬA
echo "[+] Kích hoạt tường lửa UFW..."
ufw --force enable

echo "=========================================================="
echo "    HOÀN TẤT THIẾT LẬP TƯỜNG LỬA AN TOÀN                  "
echo "=========================================================="
ufw status verbose
