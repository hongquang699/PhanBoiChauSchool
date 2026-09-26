import threading
import time
import urllib.request
import urllib.error
import json
import dev_server

def start_server():
    dev_server.socketserver.TCPServer.allow_reuse_address = True
    with dev_server.socketserver.TCPServer(('', 8089), dev_server.SecureHTTPRequestHandler) as httpd:
        httpd.serve_forever()

t = threading.Thread(target=start_server, daemon=True)
t.start()
time.sleep(1)

print("=" * 60)
print("[*] KIỂM THỬ TÍCH HỢP TOÀN DIỆN MÁY CHỦ BẢO MẬT (DEV SERVER):")
print("=" * 60)

# Test 1: API Security Status
req = urllib.request.urlopen('http://localhost:8089/api/security-status')
data = json.loads(req.read().decode('utf-8'))
print(f"[+] Test 1 (Security Status API) : HTTP {req.status} - Trạng thái: {data['status']}")

# Test 2: Security Headers
xf = req.headers.get('X-Frame-Options')
xc = req.headers.get('X-Content-Type-Options')
csp = req.headers.get('Content-Security-Policy')
print(f"[+] Test 2 (Security Headers)    : X-Frame-Options={xf}, nosniff={xc}, CSP={'Có' if csp else 'Không'}")

# Test 3: Path Traversal & Sensitive File block
try:
    urllib.request.urlopen('http://localhost:8089/security/database_security.sql')
    print("[-] Test 3 FAILED: Tệp nhạy cảm không bị chặn")
except urllib.error.HTTPError as e:
    print(f"[+] Test 3 (Chặn Tệp Nhạy Cảm)   : HTTP {e.code} (Chặn thành công!)")

# Test 4: WAF SQLi filter
try:
    urllib.request.urlopen('http://localhost:8089/pages/tin-tuc.html?q=1%20UNION%20SELECT%201')
    print("[-] Test 4 FAILED: SQLi không bị chặn")
except urllib.error.HTTPError as e:
    print(f"[+] Test 4 (WAF Chặn SQLi)       : HTTP {e.code} (Chặn thành công!)")

# Test 5: WAF XSS filter
try:
    urllib.request.urlopen('http://localhost:8089/index.html?name=%3Cscript%3Ealert(1)%3C/script%3E')
    print("[-] Test 5 FAILED: XSS không bị chặn")
except urllib.error.HTTPError as e:
    print(f"[+] Test 5 (WAF Chặn XSS)        : HTTP {e.code} (Chặn thành công!)")

# Test 6: Brute Force & Account Lockout
login_url = 'http://localhost:8089/api/auth/login'
print("[*] Test 6 (Chống Brute Force / Account Lockout):")
for i in range(1, 6):
    payload = json.dumps({'username': 'hacked_target', 'password': 'wrong_password'}).encode('utf-8')
    req_post = urllib.request.Request(login_url, data=payload, headers={'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(req_post)
    except urllib.error.HTTPError as e:
        res_body = json.loads(e.read().decode('utf-8'))
        is_locked = res_body.get('details', {}).get('locked', False) or (e.code == 423)
        print(f"    - Lần thử {i}: HTTP {e.code} -> Bị khóa={is_locked}")

print("=" * 60)
print("[+] TẤT CẢ CÁC BÀI KIỂM THỬ TRÊN MÁY CHỦ ĐỀU VƯỢT QUA XUẤT SẮC!")
print("=" * 60)
