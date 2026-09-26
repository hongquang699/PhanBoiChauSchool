#!/bin/bash
# ==============================================================================
# KỊCH BẢN TỰ ĐỘNG HÓA SAO LƯU HÀNG NGÀY (CRONJOB) - THPT CHUYÊN PHAN BỘI CHÂU
# Chạy định kỳ vào 02:00 sáng mỗi ngày: 0 2 * * * /var/www/gioithieuPBC/security/backup.sh
# ==============================================================================

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="/var/backups/gioithieuPBC"
WEB_DIR="/var/www/gioithieuPBC"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

echo "=== [$(date)] Bắt đầu sao lưu hệ thống Website PBC ==="

# 1. SAO LƯU CƠ SỞ DỮ LIỆU
echo "[+] Đang sao lưu Database..."
mysqldump -u pbc_backup_user -p'PBc_BackupOnly#2026$Safe' --single-transaction --quick pbc_school_db | gzip > "$BACKUP_DIR/db_$TIMESTAMP.sql.gz"

# 2. SAO LƯU TỆP TIN & MEDIA
echo "[+] Đang sao lưu Tệp tin & Media..."
tar -czf "$BACKUP_DIR/files_$TIMESTAMP.tar.gz" -C "$WEB_DIR" images videos pages css js index.html

# 3. SAO LƯU CẤU HÌNH HỆ THỐNG
echo "[+] Đang sao lưu Cấu hình máy chủ..."
tar -czf "$BACKUP_DIR/configs_$TIMESTAMP.tar.gz" -C "$WEB_DIR/security" nginx.conf .htaccess firewall.sh waf_rules.conf

# 4. TÍNH MÃ BĂM TOÀN VẸN SHA-256
cd "$BACKUP_DIR"
sha256sum *"_$TIMESTAMP"* > "$BACKUP_DIR/checksum_$TIMESTAMP.sha256"

# 5. XÓA BẢN SAO LƯU CŨ HƠN 30 NGÀY (LOG ROTATION)
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete

echo "=== [$(date)] Hoàn tất sao lưu an toàn! ==="
