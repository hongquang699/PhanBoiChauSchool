#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
BACKUP & RECOVERY MODULE - TRƯỜNG THPT CHUYÊN PHAN BỘI CHÂU
==============================================================================
Triển khai đúng cấu trúc 3 nhánh:
Website
   │
   ├── 1. Database Backup
   ├── 2. File Backup (Images, Media, Code)
   └── 3. Configuration Backup (Nginx, Apache, Firewall, WAF)
             │
             ▼
       Backup Storage (Kèm mã băm toàn vẹn SHA-256)
==============================================================================
"""

import hashlib
import json
import os
import shutil
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class BackupRecoveryManager:
    """Tự động hóa sao lưu và phục hồi dữ liệu hệ thống website."""

    def __init__(self, root_dir: Optional[str] = None, backup_dir: Optional[str] = None):
        self.root_dir = root_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.backup_dir = backup_dir or os.path.join(self.root_dir, "backups")
        os.makedirs(self.backup_dir, exist_ok=True)

    @staticmethod
    def calculate_sha256(filepath: str) -> str:
        """Tính mã băm SHA-256 để xác thực tính toàn vẹn của bản sao lưu."""
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    # --------------------------------------------------------------------------
    # 1. DATABASE BACKUP (SAO LƯU CƠ SỞ DỮ LIỆU)
    # --------------------------------------------------------------------------
    def backup_database(self, timestamp_str: str) -> str:
        """Sao lưu cấu trúc bảng và dữ liệu cơ sở dữ liệu thành file SQL dump."""
        db_dump_filename = f"db_backup_{timestamp_str}.sql"
        db_dump_path = os.path.join(self.backup_dir, db_dump_filename)

        # Trong môi trường thực tế: Chạy mysqldump hoặc sqlite3 dump
        # Ở đây xuất bản sao lưu schema an toàn và dữ liệu mẫu
        schema_path = os.path.join(self.root_dir, "security", "database_security.sql")
        content = f"-- PBC SCHOOL DATABASE BACKUP AT {datetime.now(timezone.utc).isoformat()}\n"
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as sf:
                content += sf.read()
        
        with open(db_dump_path, "w", encoding="utf-8") as df:
            df.write(content)

        return db_dump_path

    # --------------------------------------------------------------------------
    # 2. FILE & MEDIA BACKUP (SAO LƯU TÀI NGUYÊN & MÃ NGUỒN)
    # --------------------------------------------------------------------------
    def backup_files(self, timestamp_str: str) -> str:
        """Nén toàn bộ mã nguồn web và kho ảnh/video tư liệu kỷ yếu."""
        zip_filename = f"files_backup_{timestamp_str}.zip"
        zip_path = os.path.join(self.backup_dir, zip_filename)

        folders_to_backup = ["css", "js", "pages", "images", "videos"]
        files_to_backup = ["index.html"]

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in files_to_backup:
                full_p = os.path.join(self.root_dir, item)
                if os.path.isfile(full_p):
                    zf.write(full_p, arcname=item)

            for folder in folders_to_backup:
                folder_path = os.path.join(self.root_dir, folder)
                if os.path.exists(folder_path):
                    for root, _, files in os.walk(folder_path):
                        for f in files:
                            full_file = os.path.join(root, f)
                            rel_file = os.path.relpath(full_file, self.root_dir)
                            zf.write(full_file, arcname=rel_file)

        return zip_path

    # --------------------------------------------------------------------------
    # 3. CONFIGURATION BACKUP (SAO LƯU CẤU HÌNH HỆ THỐNG & BẢO MẬT)
    # --------------------------------------------------------------------------
    def backup_configs(self, timestamp_str: str) -> str:
        """Nén toàn bộ file cấu hình máy chủ Nginx, Apache, Firewall, WAF."""
        cfg_filename = f"configs_backup_{timestamp_str}.zip"
        cfg_path = os.path.join(self.backup_dir, cfg_filename)

        sec_dir = os.path.join(self.root_dir, "security")
        config_files = ["nginx.conf", ".htaccess", "firewall.sh", "waf_rules.conf"]

        with zipfile.ZipFile(cfg_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for cf in config_files:
                cf_path = os.path.join(sec_dir, cf)
                if os.path.isfile(cf_path):
                    zf.write(cf_path, arcname=cf)

        return cfg_path

    # --------------------------------------------------------------------------
    # QUY TRÌNH SAO LƯU TỔNG THỂ (MASTER BACKUP)
    # --------------------------------------------------------------------------
    def run_full_backup(self) -> Dict[str, Any]:
        """Thực thi sao lưu đồng thời 3 thành phần và đóng gói vào kho lưu trữ."""
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print(f"[*] Bắt đầu tiến trình sao lưu hệ thống: {timestamp_str}")
        
        # 1. DB Backup
        db_file = self.backup_database(timestamp_str)
        db_hash = self.calculate_sha256(db_file)
        print(f"  [1/3] Database Backup     : {os.path.basename(db_file)} ({os.path.getsize(db_file)} bytes)")

        # 2. File Backup
        files_file = self.backup_files(timestamp_str)
        files_hash = self.calculate_sha256(files_file)
        print(f"  [2/3] File & Media Backup : {os.path.basename(files_file)} ({os.path.getsize(files_file) / 1024 / 1024:.2f} MB)")

        # 3. Config Backup
        cfg_file = self.backup_configs(timestamp_str)
        cfg_hash = self.calculate_sha256(cfg_file)
        print(f"  [3/3] Config Backup       : {os.path.basename(cfg_file)} ({os.path.getsize(cfg_file)} bytes)")

        # Ghi báo cáo kiểm toán tính toàn vẹn (Integrity Manifest)
        manifest = {
            "backup_timestamp": timestamp_str,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "components": {
                "database": {
                    "filename": os.path.basename(db_file),
                    "sha256": db_hash,
                    "size_bytes": os.path.getsize(db_file)
                },
                "files": {
                    "filename": os.path.basename(files_file),
                    "sha256": files_hash,
                    "size_bytes": os.path.getsize(files_file)
                },
                "configurations": {
                    "filename": os.path.basename(cfg_file),
                    "sha256": cfg_hash,
                    "size_bytes": os.path.getsize(cfg_file)
                }
            }
        }

        manifest_path = os.path.join(self.backup_dir, f"manifest_{timestamp_str}.json")
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2, ensure_ascii=False)

        print(f"[+] Báo cáo toàn vẹn sao lưu: {os.path.basename(manifest_path)}")
        return manifest


# ==============================================================================
# KIỂM THỬ THỰC TẾ BACKUP
# ==============================================================================
if __name__ == "__main__":
    print("==========================================================")
    print("    TIẾN HÀNH SAO LƯU DỮ LIỆU ĐỊNH KỲ (BACKUP RUN)       ")
    print("==========================================================")
    mgr = BackupRecoveryManager()
    result = mgr.run_full_backup()
    print("\n[+] Đã hoàn thành sao lưu 3 thành phần: Database, Files, Configs an toàn!")
