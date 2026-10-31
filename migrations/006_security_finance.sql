CREATE TABLE IF NOT EXISTS finance_requests (
 actor_id BIGINT NOT NULL,
 request_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 operation VARCHAR(64) NOT NULL,
 payload_hash CHAR(64) CHARACTER SET ascii NOT NULL,
 result_json JSON NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY (actor_id, request_key)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS finance_events (
 event_kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 event_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 order_number VARCHAR(64) NOT NULL,
 payload_hash CHAR(64) CHARACTER SET ascii NOT NULL,
 result_json JSON NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY (event_kind, event_key),
 KEY ix_finance_events_order (order_number, event_kind)
) ENGINE=InnoDB;
