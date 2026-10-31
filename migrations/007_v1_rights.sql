-- ============================================================
-- 007_v1_rights.sql
-- 禹泽小程序 V1.1 会员权益与白酒专区 · 第一阶段底层数据模型
--
-- 执行方式：uv run python scripts/migrate.py
-- 幂等性：全部使用 CREATE TABLE IF NOT EXISTS / INSERT IGNORE，
--         并在文件头固化触发器 DROP IF EXISTS + CREATE。
--
-- 强制约定：
--   1. 金额/数量/比例一律 DECIMAL(20,6)（points_value 系数用 (20,10)），
--      应用层同步使用 decimal.Decimal，禁止 float。
--   2. rights_ledger 只允许 INSERT，禁止 UPDATE / DELETE，
--      由触发器 trg_rights_ledger_no_update / trg_rights_ledger_no_delete 强制，
--      纠正必须使用新增反向流水（reversal_of_id 指向原流水）。
--   3. 咯哒蛋发行总量恒定 1 亿，只在下面 INSERT 一次，
--      触发器 trg_pool_total_supply_immutable 强制其不可被 UPDATE 修改，
--      系统不提供任何增发入口。
--   4. Q12（雨点补贴池 12%/8% 下发）暂缓：subsidy_coupon_balance 本阶段
--      只允许入池（兑换 20% 分流、过期券入池），不允许任何出池扣减。
-- ============================================================

CREATE TABLE IF NOT EXISTS system_pools (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY COMMENT '单例行，固定为 1',
    total_egg_supply DECIMAL(20,6) NOT NULL COMMENT '咯哒蛋发行总量，恒定 100000000，无增发入口',
    pool_coupon_balance DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '底池优惠券余额（咯哒值分子）',
    subsidy_coupon_balance DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '雨点补贴池优惠券余额（本阶段只入不出，Q12 暂缓）',
    platform_egg_balance DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '平台未发放咯哒蛋库存（咯哒值分母）',
    valuation_version BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '估值版本号，池余额每次变动 +1，用于报价失效判定',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT ck_system_pools_non_negative CHECK (
        pool_coupon_balance >= 0
        AND subsidy_coupon_balance >= 0
        AND platform_egg_balance >= 0
    ),
    CONSTRAINT ck_system_pools_total_supply CHECK (total_egg_supply = 100000000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='V1.1 平台级权益池（单例）';

CREATE TABLE IF NOT EXISTS user_assets (
    user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY COMMENT '会员用户ID',
    points DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '积分余额，长期有效不清零（Q1）',
    rain_balance DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '雨点余额，中间过渡值，不可提现不可兑换（Q2）',
    coupon_balance DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '优惠券余额，须等于 rights_coupon_batches 未过期批次剩余之和',
    egg_quantity DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '持有咯哒蛋数量',
    avg_cost_goda_value DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '所持咯哒蛋加权平均成本咯哒值（Q4 判定基准）',
    goda_coupon_balance DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '咯哒券余额，仅可兑换坛装白酒（Q7）',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT ck_user_assets_non_negative CHECK (
        points >= 0
        AND rain_balance >= 0
        AND coupon_balance >= 0
        AND egg_quantity >= 0
        AND avg_cost_goda_value >= 0
        AND goda_coupon_balance >= 0
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='V1.1 会员权益资产表';

CREATE TABLE IF NOT EXISTS rights_ledger (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '会员ID，0 表示平台级流水',
    asset_type ENUM('points','rain','coupon','egg','goda_coupon','pool_coupon','subsidy_coupon','platform_egg') NOT NULL COMMENT '权益类型',
    event_type VARCHAR(48) NOT NULL COMMENT '业务事件，取值见 services/rights_service.py 的 EV_* 常量',
    quantity_delta DECIMAL(20,6) NOT NULL COMMENT '变动量，正为增加，负为减少',
    balance_after DECIMAL(20,6) NOT NULL COMMENT '该权益变动后余额',
    unit_value DECIMAL(20,6) NULL COMMENT '事件发生时刻咯哒值快照，无估值时为 NULL',
    operation_id VARCHAR(40) NULL COMMENT '关联 rights_operations.operation_no',
    related_order_no VARCHAR(64) NULL COMMENT '关联订单号/合同编号等外部单号',
    reversal_of_id BIGINT UNSIGNED NULL COMMENT '冲正流水的原流水ID，原流水本身永不修改',
    rule_version VARCHAR(24) NOT NULL DEFAULT 'v1.1-p1' COMMENT '规则版本快照',
    occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '发生时间',
    INDEX idx_ledger_user_time (user_id, occurred_at),
    INDEX idx_ledger_asset_event (asset_type, event_type),
    INDEX idx_ledger_operation (operation_id),
    INDEX idx_ledger_reversal (reversal_of_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='V1.1 全量权益流水（只增不改不删）';

DROP TRIGGER IF EXISTS trg_rights_ledger_no_update;
CREATE TRIGGER trg_rights_ledger_no_update BEFORE UPDATE ON rights_ledger FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'rights_ledger is append-only, use a reversal entry';
DROP TRIGGER IF EXISTS trg_rights_ledger_no_delete;
CREATE TRIGGER trg_rights_ledger_no_delete BEFORE DELETE ON rights_ledger FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'rights_ledger is append-only, use a reversal entry';
DROP TRIGGER IF EXISTS trg_pool_total_supply_immutable;
CREATE TRIGGER trg_pool_total_supply_immutable BEFORE UPDATE ON system_pools FOR EACH ROW SET NEW.total_egg_supply = OLD.total_egg_supply;

CREATE TABLE IF NOT EXISTS rights_operations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    operation_no VARCHAR(40) NOT NULL COMMENT '业务操作号，例如 EXG20261031000001',
    operation_type ENUM('egg_exchange','egg_auto_conversion','wine_redemption_quote','wine_redemption') NOT NULL COMMENT '操作类型',
    user_id BIGINT UNSIGNED NOT NULL COMMENT '发起会员ID',
    status ENUM('quoted','succeeded','failed') NOT NULL DEFAULT 'succeeded' COMMENT '报价中/成功/失败',
    idempotency_key VARCHAR(96) NULL COMMENT '客户端幂等键，与 user_id + operation_type 唯一',
    request_fingerprint CHAR(64) NULL COMMENT '请求参数指纹，同键不同参返回 409',
    coupon_quantity DECIMAL(20,6) NULL COMMENT '提交优惠券数量',
    pool_in_quantity DECIMAL(20,6) NULL COMMENT '入底池券数量（80%）',
    subsidy_in_quantity DECIMAL(20,6) NULL COMMENT '入补贴池券数量（20%）',
    egg_quantity DECIMAL(20,6) NULL COMMENT '本次发放/清零的咯哒蛋数量',
    goda_coupon_quantity DECIMAL(20,6) NULL COMMENT '本次涉及的咯哒券数量',
    unit_value_before DECIMAL(20,6) NULL COMMENT '操作前咯哒值',
    unit_value_after DECIMAL(20,6) NULL COMMENT '操作后咯哒值',
    valuation_version_before BIGINT UNSIGNED NULL COMMENT '操作前估值版本',
    valuation_version_after BIGINT UNSIGNED NULL COMMENT '操作后估值版本',
    target_type VARCHAR(20) NULL COMMENT '业务对象类型，例如 wine_listing',
    target_id BIGINT UNSIGNED NULL COMMENT '业务对象ID',
    payload JSON NULL COMMENT '请求快照',
    result JSON NULL COMMENT '结果快照，幂等重放时原样返回',
    expires_at DATETIME NULL COMMENT '报价过期时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    committed_at DATETIME NULL COMMENT '事务提交时间',
    UNIQUE KEY uk_operation_no (operation_no),
    UNIQUE KEY uk_idempotency (user_id, operation_type, idempotency_key),
    INDEX idx_operation_user (user_id, created_at),
    INDEX idx_operation_target (target_type, target_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='V1.1 权益写操作与报价、幂等台账';

CREATE TABLE IF NOT EXISTS rights_daily_settlements (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    business_date DATE NOT NULL COMMENT '结算业务日',
    user_id BIGINT UNSIGNED NOT NULL COMMENT '会员ID',
    status ENUM('pending','settled','skipped','failed') NOT NULL DEFAULT 'pending' COMMENT '结算状态',
    points_basis DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '结算时点有效积分基数',
    points_value DECIMAL(20,10) NOT NULL DEFAULT 0 COMMENT '当日每积分折算雨点系数，即页面展示的计算依据',
    rain_generated DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '本次生成雨点',
    rain_converted DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '本次雨点转券数量（1:1）',
    coupons_issued DECIMAL(20,6) NOT NULL DEFAULT 0 COMMENT '本次发放优惠券数量',
    failure_code VARCHAR(48) NULL COMMENT '失败/跳过原因码',
    settled_at DATETIME NULL COMMENT '完成时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_daily_date_user (business_date, user_id),
    INDEX idx_daily_date (business_date, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='V1.1 每日结算记录（替代旧月结）';

CREATE TABLE IF NOT EXISTS rights_coupon_batches (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL COMMENT '会员ID',
    quantity DECIMAL(20,6) NOT NULL COMMENT '批次发放数量',
    remaining DECIMAL(20,6) NOT NULL COMMENT '批次剩余数量',
    valid_from DATE NOT NULL COMMENT '生效日',
    valid_to DATE NOT NULL COMMENT '失效日，次日起判过期（Q2 每批按发放时间计算 30 天）',
    status ENUM('active','expired','consumed') NOT NULL DEFAULT 'active' COMMENT '批次状态',
    source_event VARCHAR(48) NOT NULL COMMENT '来源事件，例如 rain_to_coupon',
    business_date DATE NULL COMMENT '来源业务日',
    operation_no VARCHAR(40) NULL COMMENT '来源操作号',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT ck_coupon_batch_quantity CHECK (quantity >= 0 AND remaining >= 0 AND remaining <= quantity),
    INDEX idx_batch_user_expiry (user_id, status, valid_to),
    INDEX idx_batch_expiry (status, valid_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='V1.1 优惠券批次（支持按批过期与先进先出核销）';

CREATE TABLE IF NOT EXISTS wine_jars (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    contract_no VARCHAR(64) NOT NULL COMMENT '合同编号，一号一坛（FR-301/306）',
    owner_id BIGINT UNSIGNED NOT NULL COMMENT '当前权属人用户ID',
    weight_jin DECIMAL(20,6) NOT NULL DEFAULT 100 COMMENT '规格重量（斤）',
    wine_price_fen INT UNSIGNED NOT NULL DEFAULT 300000 COMMENT '酒价（分），仅含酒价，器皿/包装/物流另计（Q13）',
    status ENUM('owned','listed','locked','delivering','delivered') NOT NULL DEFAULT 'owned' COMMENT '酒坛状态',
    ownership_version BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '权属版本号，权属迁移时 +1',
    acquired_at DATETIME NULL COMMENT '最近一次权属获得时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_wine_jar_contract (contract_no),
    INDEX idx_wine_jar_owner (owner_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='白酒酒坛（权属随合同编号流转）';

CREATE TABLE IF NOT EXISTS wine_listings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    listing_no VARCHAR(40) NOT NULL COMMENT '挂牌单号',
    jar_id BIGINT UNSIGNED NOT NULL COMMENT '酒坛ID，一坛仅一条挂牌记录，禁止重复出售（Q14）',
    contract_no VARCHAR(64) NOT NULL COMMENT '合同编号快照',
    seller_id BIGINT UNSIGNED NOT NULL COMMENT '挂牌店长用户ID',
    buyer_id BIGINT UNSIGNED NULL COMMENT '成交买家用户ID',
    status ENUM('listed','locked','sold','withdrawn') NOT NULL DEFAULT 'listed' COMMENT '挂牌状态',
    wine_price_fen INT UNSIGNED NOT NULL DEFAULT 300000 COMMENT '成交价（分），服务端固定，不接受客户端传价',
    version BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '挂牌版本号，用于并发下单校验',
    listed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '上架时间',
    locked_at DATETIME NULL COMMENT '锁定时间',
    sold_at DATETIME NULL COMMENT '成交时间',
    withdrawn_at DATETIME NULL COMMENT '下架时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_listing_no (listing_no),
    UNIQUE KEY uk_listing_jar (jar_id),
    INDEX idx_listing_status (status, listed_at),
    INDEX idx_listing_seller (seller_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='白酒挂牌交易表';

INSERT IGNORE INTO system_pools (
    id, total_egg_supply, pool_coupon_balance, subsidy_coupon_balance, platform_egg_balance
) VALUES (
    1, 100000000, 1000000, 0, 100000000
);

INSERT IGNORE INTO user_assets (user_id, points)
SELECT u.id, COALESCE(u.member_points, 0) FROM users u WHERE u.id > 0;
