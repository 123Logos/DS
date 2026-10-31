-- Numbered migration only: no request-time DDL. Explicit cutover revokes legacy sessions.
-- Change future inserts only. Existing frozen/deleted users retain their state.
ALTER TABLE users ALTER COLUMN status SET DEFAULT 0;
CREATE TABLE IF NOT EXISTS sessions (
 id INT AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,token VARCHAR(256) NOT NULL UNIQUE,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,expired_at DATETIME NOT NULL,
 INDEX idx_user(user_id),INDEX idx_expired(expired_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS auth_sms_limits (
 scope_hash CHAR(64) PRIMARY KEY,window_start DATETIME NOT NULL,
 issuance_count INT NOT NULL DEFAULT 0,attempt_count INT NOT NULL DEFAULT 0,last_issued_at DATETIME NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS auth_sms_challenges (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,session_id CHAR(32) NOT NULL UNIQUE,
 mobile VARCHAR(32) NOT NULL,purpose VARCHAR(32) NOT NULL,subject_hash CHAR(64) NOT NULL,
 code_hash CHAR(64) NOT NULL,user_id INT NULL,send_status VARCHAR(16) NOT NULL,
 provider_message_id VARCHAR(128) NULL,delivery_status VARCHAR(16) NOT NULL DEFAULT 'unconfirmed',expires_at DATETIME NOT NULL,
 consumed_at DATETIME NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 INDEX idx_challenge(mobile,purpose,subject_hash,id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS security_operator_audit (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,operator_id INT NULL,target_id INT NOT NULL,
 action VARCHAR(80) NOT NULL,before_json JSON NOT NULL,after_json JSON NOT NULL,
 reason VARCHAR(200) NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 INDEX idx_target(target_id,created_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS user_unilevel (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,user_id BIGINT UNSIGNED NOT NULL UNIQUE,
 level TINYINT NOT NULL DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='points_log' AND column_name='operator_id')=0,'ALTER TABLE points_log ADD COLUMN operator_id BIGINT NULL','SELECT 1');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='points_log' AND column_name='balance_before')=0,'ALTER TABLE points_log ADD COLUMN balance_before DECIMAL(18,6) NULL','SELECT 1');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='points_log' AND column_name='event_id')=0,'ALTER TABLE points_log ADD COLUMN event_id VARCHAR(128) NULL','SELECT 1');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='points_log' AND column_name='source')=0,'ALTER TABLE points_log ADD COLUMN source VARCHAR(32) NOT NULL DEFAULT ''automatic''','SELECT 1');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
-- Migration runner executes each numbered migration once. DDL above precedes data transaction.
START TRANSACTION;
DELETE FROM sessions;
COMMIT;
