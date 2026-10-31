-- ============================================================
-- 008_legacy_assets_bridge.sql
-- 旧账本（users.member_points / users.true_total_points）
-- 与 V1.1 权益账本（user_assets.points / user_assets.rain_balance）的桥接
--
-- 执行的漏洞修复：漏洞 1 & 2「新旧账本分叉」
--
-- 为什么用触发器而不是逐点改业务代码：
--   services/finance_service.py 中存在动态字段名的写入，例如
--     UPDATE users SET {balance_field} = {balance_field} - :amount ...
--     UPDATE users SET `{balance_field}` = COALESCE(`{balance_field}`, 0) + %s ...
--     UPDATE users SET {quoted_field} = COALESCE({quoted_field}, 0) + :delta ...
--   同一文件另有 18 处直写 member_points / true_total_points（含绝对赋值
--   SET true_total_points = %s 的形式），且未来新增路径无法预知。
--   逐点补丁必然漏写，账本仍会分叉。触发器把「镜像」下沉为不可绕过的约束：
--   任何对 users 积分列的改动，无论来自旧代码、动态 SQL、手工修数还是将来新代码，
--   都在同一事务内按**增量**同步到 user_assets。
--
-- 单向原则（关键，避免双写翻倍）：
--   users.member_points / users.true_total_points 是积分与雨点的**唯一写入点**；
--   user_assets.points / user_assets.rain_balance 只是镜像，任何代码都不得直接写这两列，
--   一律通过 services/legacy_assets_bridge.py 写 users 侧，由本触发器镜像。
--   （V1.1 日结的积分回补、雨点生成/消耗同样遵守此约束。）
--
-- 增量而非覆盖：
--   用 (NEW.x - OLD.x) 做增量，对「+ delta」和「SET 绝对值」两种写法都成立，
--   且与并发写入可交换，不会用旧快照覆盖别人刚写进去的值。
--
-- 负数即 Bug，直接报错：
--   旧账本被扣成负数（NEW.member_points < 0 或 NEW.true_total_points < 0）说明
--   上游业务存在越界扣减，属于严重缺陷。此处**不夹 0、不做任何容错**：
--   SIGNAL SQLSTATE '45000' 让整条 UPDATE 与其所在事务回滚，把问题暴露在上线前，
--   而不是把余额悄悄变成 0 掩盖掉（那会让账面凭空多出资产，且永远查不出来）。
--   已知的合法扣减路径（bridge._apply_legacy_delta）自带 `余额 + delta >= 0`
--   下界保护，正常业务永远不会触发本 SIGNAL。
--
-- 加锁顺序：
--   触发器在 users 行锁之后获取 user_assets 行锁，因此全库统一顺序为
--     system_pools → users → user_assets
--   应用层必须保证「先锁 users、再锁 user_assets」，不得出现
--   「持有 user_assets 再回头更新 users」的反向获取，否则与旧业务互锁。
--
-- 幂等：全部 DROP TRIGGER IF EXISTS + CREATE，可重复执行。
--       触发器体为 BEGIN...END 复合语句，用 DELIMITER $$ 包裹；
--       scripts/migrate.py 通过 core.sql_split 识别该指令，mysql CLI 原生支持。
-- ============================================================

-- ------------------------------------------------------------
-- 1) 新建会员即建镜像行（含历史值），保证后续 UPDATE 的增量有落点
--    负值直接报错：user_assets 侧有 CHECK (points >= 0)，与其抛一个含义模糊的
--    CHECK 违约，不如在这里给出明确的业务原因。
-- ------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_users_assets_mirror_insert;

DELIMITER $$

CREATE TRIGGER trg_users_assets_mirror_insert AFTER INSERT ON users FOR EACH ROW
BEGIN
    IF COALESCE(NEW.member_points, 0) < 0 OR COALESCE(NEW.true_total_points, 0) < 0 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'legacy_asset_negative: users.member_points/true_total_points must be >= 0';
    END IF;

    INSERT IGNORE INTO user_assets (user_id, points, rain_balance)
    VALUES (
        NEW.id,
        COALESCE(NEW.member_points, 0),
        COALESCE(NEW.true_total_points, 0)
    );
END$$

-- ------------------------------------------------------------
-- 2) 旧账本改动 → 增量镜像到 user_assets
--    顺序要点：先判负（可能 SIGNAL 中断整个事务），再判「是否真的变了」。
--    第二步的内层 IF 是写放大控制：users 在登录、改昵称、改等级时频繁 UPDATE，
--    积分/雨点未变化时不做任何写入 —— 不取 user_assets 行锁、也不动 updated_at。
-- ------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_users_assets_mirror_update$$

CREATE TRIGGER trg_users_assets_mirror_update AFTER UPDATE ON users FOR EACH ROW
BEGIN
    IF COALESCE(NEW.member_points, 0) < 0 OR COALESCE(NEW.true_total_points, 0) < 0 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'legacy_asset_negative: users.member_points/true_total_points must be >= 0';
    END IF;

    IF COALESCE(NEW.member_points, 0) <> COALESCE(OLD.member_points, 0)
       OR COALESCE(NEW.true_total_points, 0) <> COALESCE(OLD.true_total_points, 0) THEN
        UPDATE user_assets
           SET points = points + (COALESCE(NEW.member_points, 0) - COALESCE(OLD.member_points, 0)),
               rain_balance = rain_balance + (COALESCE(NEW.true_total_points, 0) - COALESCE(OLD.true_total_points, 0)),
               updated_at = NOW()
         WHERE user_id = NEW.id;
    END IF;
END$$

DELIMITER ;

-- ------------------------------------------------------------
-- 3) 对账视图：一眼看出哪些会员两套账本不一致
--    drift_points / drift_rain 为 0 表示该会员已对齐。
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_legacy_asset_parity AS
SELECT
    u.id AS user_id,
    COALESCE(u.member_points, 0) AS legacy_points,
    COALESCE(a.points, 0) AS v1_points,
    COALESCE(u.member_points, 0) - COALESCE(a.points, 0) AS drift_points,
    COALESCE(u.true_total_points, 0) AS legacy_rain,
    COALESCE(a.rain_balance, 0) AS v1_rain,
    COALESCE(u.true_total_points, 0) - COALESCE(a.rain_balance, 0) AS drift_rain,
    (a.user_id IS NULL) AS assets_row_missing
FROM users u
LEFT JOIN user_assets a ON a.user_id = u.id;
