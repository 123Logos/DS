CREATE TABLE IF NOT EXISTS payment_refund_intents (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 order_number VARCHAR(64) NOT NULL,
 logical_key VARCHAR(128) NOT NULL,
 out_refund_no VARCHAR(64) NOT NULL,
 transaction_id VARCHAR(64) NULL,
 sub_mchid VARCHAR(64) NULL,
 total_fee BIGINT NOT NULL,
 refund_fee BIGINT NOT NULL,
 previous_status VARCHAR(32) NOT NULL,
 state VARCHAR(24) NOT NULL DEFAULT 'prepared',
 provider_refund_id VARCHAR(64) NULL,
 attempts INT NOT NULL DEFAULT 0,
 next_attempt_at DATETIME NULL,
 last_error VARCHAR(64) NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 UNIQUE KEY uq_refund_logical (logical_key),
 UNIQUE KEY uq_refund_number (out_refund_no),
 KEY ix_refund_recovery (state,next_attempt_at),
 KEY ix_refund_order (order_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS payment_events (
 event_key VARCHAR(128) NOT NULL PRIMARY KEY,
 order_number VARCHAR(64) NOT NULL,
 transaction_id VARCHAR(64) NOT NULL,
 total_fee BIGINT NOT NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE KEY uq_payment_transaction (transaction_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS payment_merchant_transfers (
 order_number VARCHAR(64) NOT NULL PRIMARY KEY,
 merchant_id BIGINT NOT NULL,
 beneficiary_openid VARCHAR(128) NULL,
 amount BIGINT NOT NULL,
 out_batch_no VARCHAR(32) NOT NULL UNIQUE,
 state VARCHAR(24) NOT NULL DEFAULT 'prepared',
 attempts INT NOT NULL DEFAULT 0,
 next_attempt_at DATETIME NULL,
 updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS payment_reconciliation_cases (
 case_key VARCHAR(128) NOT NULL PRIMARY KEY,
 order_number VARCHAR(64) NOT NULL,
 transaction_id VARCHAR(64) NULL,
 total_fee BIGINT NULL,
 refund_no VARCHAR(64) NULL,
 reason VARCHAR(64) NOT NULL,
 state VARCHAR(24) NOT NULL DEFAULT 'open',
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
ALTER TABLE payment_merchant_transfers ADD COLUMN notification_sent TINYINT NOT NULL DEFAULT 0;
ALTER TABLE offline_order ADD COLUMN security_prepay_frozen TINYINT NOT NULL DEFAULT 0;
ALTER TABLE payment_refund_intents ADD COLUMN reason VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE payment_merchant_transfers ADD COLUMN original_amount BIGINT NULL;
