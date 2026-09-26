import re
import urllib.request

urls = [
    "https://thptchuyenphanboichau.edu.vn/gioi-thieu-ve-cp-the-news-clb-noi-san-truong-thpt-chuyen-phan-boi-chau/",
    "https://thptchuyenphanboichau.edu.vn/gioi-thieu-ve-clb-tranh-bien/",
    "https://thptchuyenphanboichau.edu.vn/bai-gioi-thieu-ve-cau-lac-bo-phan-acoustic-club/",
    "https://thptchuyenphanboichau.edu.vn/cau-lac-bo-co-vua-truong-thpt-chuyen-phan-boi-chau-phan-chess-academy/",
    "https://thptchuyenphanboichau.edu.vn/gioi-thieu-ve-clb-sach-phan-bookaholic-club/",
    "https://thptchuyenphanboichau.edu.vn/gioi-thieu-ve-clb-bullets-basketball-club/",
    "https://thptchuyenphanboichau.edu.vn/doi-thanh-nien-tinh-nguyen-thpt-chuyen-phan-boi-chau/",
    "https://thptchuyenphanboichau.edu.vn/gioi-thieu-ve-clb-duong-len-dinh-olympia-truong-thpt-chuyen-phan-boi-chau/",
    "https://thptchuyenphanboichau.edu.vn/gioi-thieu-ve-phan-boi-chau-model-united-nations-union/",
    "https://thptchuyenphanboichau.edu.vn/phan-design-fashion-club/"
]

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

for u in urls:
    try:
        req = urllib.request.Request(u, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            # find images in post content or uploads
            matches = re.findall(r'https?://[^\s"\'>]+\.(?:jpg|jpeg|png|webp)', html, re.IGNORECASE)
            uploads = [m for m in matches if "uploads" in m and "logo" not in m.lower() and "icon" not in m.lower()]
            print(f"URL: {u.split('/')[-2]}")
            for m in list(set(uploads))[:5]:
                print(f"  Img: {m}")
    except Exception as e:
        print(f"Error {u}: {e}")
