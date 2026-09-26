-- ==============================================================================
-- DATABASE SECURITY CONFIGURATION & SCHEMA - THPT CHUYÊN PHAN BỘI CHÂU
-- Tuân thủ: Phân quyền tối thiểu, Không public DB, Bảo vệ dữ liệu nhạy cảm
-- ==============================================================================

-- 1. TẠO CƠ SỞ DỮ LIỆU CHÍNH
CREATE DATABASE IF NOT EXISTS pbc_school_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE pbc_school_db;

-- 2. PHÂN QUYỀN TỐI THIỂU (PRINCIPLE OF LEAST PRIVILEGE)
-- Xóa quyền root từ xa
DROP USER IF EXISTS 'root'@'%';

-- Tạo tài khoản chuyên dụng cho Web Application (Chỉ kết nối cục bộ localhost)
CREATE USER IF NOT EXISTS 'pbc_webapp_user'@'localhost' IDENTIFIED BY 'PBcSecure_AppUser@2026!#';

-- Giới hạn quyền: Web Application CHỈ ĐƯỢC PHÉP ĐỌC, GHI DỮ LIỆU CẦN THIẾT
-- TUYỆT ĐỐI KHÔNG CẤP QUYỀN DROP, ALTER, GRANT, SHUTDOWN, SUPER
GRANT SELECT, INSERT, UPDATE, DELETE ON pbc_school_db.* TO 'pbc_webapp_user'@'localhost';

-- Tạo tài khoản riêng chỉ dành cho tiến trình Backup (Chỉ có quyền SELECT và LOCK TABLES)
CREATE USER IF NOT EXISTS 'pbc_backup_user'@'localhost' IDENTIFIED BY 'PBc_BackupOnly#2026$Safe';
GRANT SELECT, LOCK TABLES, SHOW VIEW ON pbc_school_db.* TO 'pbc_backup_user'@'localhost';

FLUSH PRIVILEGES;

-- 3. BẢNG TÀI KHOẢN HỆ THỐNG (BẢO VỆ MẬT KHẨU)
-- Tuyệt đối không lưu Plaintext. Mật khẩu phải được Hash bằng Bcrypt/Argon2/PBKDF2 kèm Salt.
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL, -- Chuỗi băm an toàn 60+ ký tự
    password_salt VARCHAR(64) NOT NULL, -- Salt ngẫu nhiên chống Rainbow Table
    role ENUM('super_admin', 'giao_vien', 'hoc_sinh') DEFAULT 'hoc_sinh',
    failed_attempts INT DEFAULT 0, -- Chống Brute Force (khóa sau 5 lần sai)
    account_locked_until DATETIME NULL,
    two_factor_secret VARCHAR(64) NULL, -- Hỗ trợ 2FA (TOTP)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_user_email (email)
) ENGINE=InnoDB;

-- 4. BẢNG HỒ SƠ THÔNG TIN CẦN MÃ HÓA (ENCRYPTED SENSITIVE DATA)
-- Số CCCD, Ngày sinh, Địa chỉ riêng tư được mã hóa AES-256
CREATE TABLE IF NOT EXISTS student_profiles (
    student_id INT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    specialized_class VARCHAR(50) NOT NULL, -- Chuyên Toán, Chuyên Tin, Chuyên Anh...
    id_card_encrypted VARBINARY(256) NOT NULL, -- Số CCCD/Định danh đã mã hóa AES-256
    contact_phone_encrypted VARBINARY(256) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. BẢNG SECURITY AUDIT LOG (NHẬT KÝ AN TOÀN TRUY VẤN)
CREATE TABLE IF NOT EXISTS security_audit_logs (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    user_id INT NULL,
    action_type VARCHAR(50) NOT NULL, -- LOGIN_FAIL, UNAUTHORIZED_ACCESS, SQLI_BLOCKED...
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_log_created (created_at),
    INDEX idx_log_ip (ip_address)
) ENGINE=InnoDB;
