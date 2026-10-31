"""V1.1 每日结算服务（重写旧月结，替代 services/finance 的月结与日补贴链路）。

每日 00:00 顺序执行（FQ：Q1/Q2/Q3）：

1. 券过期入池 —— 到期未用券划入雨点补贴池，同时 1:1 回补积分（Q3）。
2. 积分生成雨点 —— 按当日每积分折算系数结算，积分不清零（Q1）。
3. 雨点转优惠券 —— 1 雨点 = 1 券，有效期 30 天，已转雨点从余额扣除（Q2）。

**Q12（雨点补贴池 12%/8% 下发）在本阶段强制暂缓**：

* 本模块对 `system_pools.subsidy_coupon_balance` **只有入池（+），没有任何出池（-）逻辑**；
* `payout_subsidy_pool()` 显式抛 `SubsidyPayoutDisabled`，不写发放明细、不写 12%/8% 分账；
* 待甲方书面确认后单开分支实现。

Q1 的"沿用现有积分产雨点算法"说明：
现有实现（services/finance_service.distribute_daily_subsidy）的每日积分值为
`每日可分配金额 ÷ 平台总积分`，并受 `MAX_POINTS_VALUE` 上限约束。
本模块复用同一计算形态与同一上限常量，只把来源池切换为 V1.1 台账口径，
且**不再扣减会员积分**（Q1 明确"积分长期有效、不清零"，与旧实现的扣分行为相反）。
"每日可分配金额"仍只读旧补贴池资金余额（不修改旧财务代码、不从 V1.1 补贴池出池），
该资金来源口径需甲方在 Q1 书面确认后固化，已登记 docs/待完成事项.md。
"""
from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Optional

from core.config import MAX_POINTS_VALUE
from core.database import get_conn
from core.logging import get_logger
from services import legacy_assets_bridge as bridge
from services.rights_service import (
    ASSET_COUPON,
    ASSET_POINTS,
    ASSET_RAIN,
    ASSET_SUBSIDY_COUPON,
    RULE_VERSION,
    RightsService,
    quantize_amount,
    to_decimal,
)

logger = get_logger(__name__)

#: 优惠券有效期（Q2：30 天，按批次发放时间计算）
COUPON_VALID_DAYS = 30

#: 每积分折算雨点系数的上限，复用现有已核实规则
MAX_DAILY_POINTS_VALUE = to_decimal(MAX_POINTS_VALUE, "MAX_POINTS_VALUE")
#: 系数精度：0.0000000001
POINTS_VALUE_QUANT = Decimal("0.0000000001")
#: 现有日补贴比例默认值（finance_accounts.subsidy_pool.config_params.daily_subsidy_ratio）
DEFAULT_DAILY_SUBSIDY_RATIO = Decimal("0.05")

#: 结算失败/跳过原因码
SKIP_NO_FUNDING = "RAIN_FUNDING_UNAVAILABLE"
SKIP_ZERO_RAIN = "ZERO_RAIN"
FAIL_INVARIANT = "INVARIANT_BROKEN"

#: 流水事件
EV_COUPON_EXPIRED = "coupon_expired_to_pool"
EV_POINTS_BACKFILL = "points_expiry_backfill"
EV_RAIN_GENERATED = "rain_daily_settlement"
EV_RAIN_TO_COUPON = "rain_to_coupon"
EV_COUPON_ISSUED = "coupon_issued"

#: 单批处理上限，避免一次性加载全量用户
BATCH_SIZE = 500

DISCLAIMER = "本权益为会员消费回馈福利，非金融资产，不可提现、不可转让"


class SubsidyPayoutDisabled(RuntimeError):
    """Q12 未确认：雨点补贴池任何下发/出池行为均被禁用。"""


def daily_points_value(daily_available: Decimal, total_points: Decimal) -> Decimal:
    """当日每积分折算雨点系数 = min(每日可分配 ÷ 平台总积分, 0.02)。

    总积分为 0 或可分配为负时返回 0（不产生雨点，也不允许负数）。
    """
    available = to_decimal(daily_available, "daily_available")
    total = to_decimal(total_points, "total_points")
    if total <= 0 or available <= 0:
        return Decimal("0")
    value = available / total
    if value > MAX_DAILY_POINTS_VALUE:
        value = MAX_DAILY_POINTS_VALUE
    return value.quantize(POINTS_VALUE_QUANT, rounding=ROUND_HALF_UP)


def rain_for_points(points_basis: Decimal, points_value: Decimal) -> Decimal:
    """本次雨点 = 有效积分 × 当日系数（6 位小数，ROUND_HALF_UP）。"""
    points = to_decimal(points_basis, "points_basis")
    value = to_decimal(points_value, "points_value")
    if points <= 0 or value <= 0:
        return Decimal("0")
    return quantize_amount(points * value)


def coupon_validity(business_date: date) -> tuple[date, date]:
    """券批次有效期：发放当日起 30 天，valid_to 当日仍可用，次日判过期。"""
    return business_date, business_date + timedelta(days=COUPON_VALID_DAYS)


class SettlementService:
    """每日结算与券到期处理。所有步骤按 (business_date, user_id) 幂等。"""

    # ---------- 资金来源（Q1 待确认口径，集中在此便于替换） ----------

    @staticmethod
    def _legacy_daily_available(cur) -> Decimal:
        """只读旧补贴池资金余额 × 日补贴比例，得到"每日可分配金额"。

        只读，不修改旧财务代码、不写旧流水；表或行缺失时返回 0。
        """
        try:
            cur.execute(
                "SELECT balance, config_params FROM finance_accounts WHERE account_type = 'subsidy_pool'"
            )
            row = cur.fetchone()
        except Exception:
            logger.warning("daily_available_source_unavailable")
            return Decimal("0")
        if not row:
            return Decimal("0")
        balance = to_decimal(row["balance"] or 0)
        ratio = DEFAULT_DAILY_SUBSIDY_RATIO
        raw = row.get("config_params")
        if raw:
            try:
                import json

                config = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
                if config.get("daily_subsidy_ratio") is not None:
                    ratio = to_decimal(str(config["daily_subsidy_ratio"]), "daily_subsidy_ratio")
            except Exception:
                logger.warning("daily_ratio_config_invalid")
        return balance * ratio

    def resolve_points_value(self, points_value: Optional[Any] = None) -> Decimal:
        """确定当日系数：显式注入优先（测试/人工复核），否则按 Q1 现网口径计算。"""
        if points_value is not None:
            return to_decimal(points_value, "points_value").quantize(POINTS_VALUE_QUANT, rounding=ROUND_HALF_UP)
        with get_conn() as conn:
            with conn.cursor() as cur:
                daily_available = self._legacy_daily_available(cur)
                # 积分基数取旧账本（唯一写入点），镜像侧仅用于展示与对账
                cur.execute("SELECT COALESCE(SUM(member_points), 0) AS total FROM users")
                total_points = to_decimal((cur.fetchone() or {}).get("total") or 0)
        return daily_points_value(daily_available, total_points)

    # ---------- 主流程 ----------

    @staticmethod
    def _lock_legacy_or_skip(cur, user_id: int) -> Optional[dict]:
        """锁旧账本会员行；行缺失时返回 None 并记错误，由调用方跳过该会员。

        日结是批量任务，单个会员数据异常（`user_assets` 有孤儿行）不应该让整批
        结算中断——但也不能静默：这里记 error，并让该会员停在未结算状态。
        """
        try:
            return bridge.lock_legacy_user(cur, user_id)
        except bridge.LegacyBridgeError:
            logger.error("legacy_user_missing user=%s, 跳过该会员结算（可能存在孤儿 user_assets 行）", user_id)
            return None

    def run_daily_settlement(
        self,
        business_date: Optional[date] = None,
        points_value: Optional[Any] = None,
    ) -> dict:
        """每日 00:00 总入口：券过期入池 → 积分产雨点 → 雨点转券。

        business_date 默认取"刚刚结束的自然日"（凌晨执行时结算前一天）。
        """
        target_date = business_date or (date.today() - timedelta(days=1))
        if isinstance(target_date, datetime):
            target_date = target_date.date()

        expired = self.expire_due_coupons(target_date)

        value = self.resolve_points_value(points_value)
        if value <= 0:
            logger.warning("daily_settlement_skipped reason=%s", SKIP_NO_FUNDING)
            return {
                "business_date": str(target_date),
                "status": "skipped",
                "failure_code": SKIP_NO_FUNDING,
                "points_value": "0",
                "expired": expired,
                "rain": {"users": 0, "rain_generated": "0.000000"},
                "coupons": {"users": 0, "coupons_issued": "0.000000"},
                "rule_version": RULE_VERSION,
            }

        rain = self.generate_rain(target_date, value)
        coupons = self.convert_rain_to_coupons(target_date)
        summary = {
            "business_date": str(target_date),
            "status": "settled",
            "failure_code": None,
            "points_value": str(value),
            "expired": expired,
            "rain": rain,
            "coupons": coupons,
            "rule_version": RULE_VERSION,
            "disclaimer": DISCLAIMER,
        }
        logger.info("daily_settlement_done %s", summary)
        return summary

    # ---------- 步骤 1：券过期入池 + 1:1 回补积分（Q3） ----------

    def expire_due_coupons(self, business_date: date) -> dict:
        """到期未用券：券入雨点补贴池，同时 1:1 回补会员积分（Q3）。

        每笔过期余额只处理一次：批次状态 active → expired 的条件 UPDATE 保证幂等。
        本步骤只把券写入补贴池，不发生任何补贴池出池。
        """
        processed_users = 0
        total_expired = Decimal("0")
        rounds = 0
        while rounds < 200:
            rounds += 1
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """SELECT DISTINCT user_id FROM rights_coupon_batches
                           WHERE status = 'active' AND valid_to < %s ORDER BY user_id LIMIT %s""",
                        (business_date, BATCH_SIZE),
                    )
                    user_ids = [int(row["user_id"]) for row in cur.fetchall() or []]
            if not user_ids:
                break
            for user_id in user_ids:
                amount = self._expire_user_coupons(user_id, business_date)
                if amount > 0:
                    processed_users += 1
                    total_expired += amount
            if len(user_ids) < BATCH_SIZE:
                break
        if total_expired > 0:
            logger.info("coupon_expiry_done users=%s quantity=%s", processed_users, total_expired)
        return {
            "users": processed_users,
            "coupons_to_subsidy_pool": str(quantize_amount(total_expired)),
            "points_backfilled": str(quantize_amount(total_expired)),
        }

    def _expire_user_coupons(self, user_id: int, business_date: date) -> Decimal:
        """单会员过期处理，独立事务。

        加锁顺序：system_pools → 券批次 → **users** → user_assets。
        `users` 必须先于 `user_assets` 取得：镜像触发器是「锁 users 后锁 user_assets」，
        旧业务路径（下单扣积分等）也是这个方向；一旦本方法反着来，就会与旧业务
        形成「你等我我等你」的死锁。

        积分回补不再直写 `user_assets.points`，而是写 `users.member_points`，
        由触发器在同一事务内镜像——保证小程序「我的积分」（读 users）与
        V1.1 结算口径（读 user_assets）永远是同一个数。
        """
        service = RightsService()
        with get_conn() as conn:
            with conn.cursor() as cur:
                pools = service.lock_pools(cur)

                # 1. 先锁定并核销到期批次：active → expired 的条件 UPDATE 是幂等闸门
                cur.execute(
                    """SELECT id, remaining FROM rights_coupon_batches
                       WHERE user_id = %s AND status = 'active' AND valid_to < %s
                       ORDER BY valid_to, id FOR UPDATE""",
                    (user_id, business_date),
                )
                batches = cur.fetchall() or []
                total = Decimal("0")
                for batch in batches:
                    remaining = to_decimal(batch["remaining"])
                    if remaining <= 0:
                        cur.execute(
                            "UPDATE rights_coupon_batches SET status = 'expired', updated_at = NOW() WHERE id = %s AND status = 'active'",
                            (batch["id"],),
                        )
                        continue
                    cur.execute(
                        """UPDATE rights_coupon_batches
                           SET status = 'expired', remaining = 0, updated_at = NOW()
                           WHERE id = %s AND status = 'active'""",
                        (batch["id"],),
                    )
                    if cur.rowcount == 1:
                        total += remaining
                if total <= 0:
                    conn.rollback()
                    return Decimal("0")

                # 2. 锁旧账本会员行（必须先于 user_assets）
                if self._lock_legacy_or_skip(cur, user_id) is None:
                    conn.rollback()
                    return Decimal("0")

                # 3. 再锁 user_assets 并校验券余额
                assets = service.lock_user_assets(cur, user_id)
                coupon_balance = to_decimal(assets["coupon_balance"])
                if coupon_balance < total:
                    # 券余额与批次不一致：先按实际余额入池，避免出现负余额，并记录告警
                    logger.error("coupon_balance_invariant_broken user=%s balance=%s batches=%s", user_id, coupon_balance, total)
                    total = coupon_balance
                    if total <= 0:
                        conn.rollback()
                        return Decimal("0")

                cur.execute(
                    """UPDATE system_pools
                       SET subsidy_coupon_balance = subsidy_coupon_balance + %s,
                           valuation_version = valuation_version + 1,
                           updated_at = NOW()
                       WHERE id = 1""",
                    (total,),
                )
                cur.execute(
                    """UPDATE user_assets
                       SET coupon_balance = coupon_balance - %s,
                           updated_at = NOW()
                       WHERE user_id = %s AND coupon_balance >= %s""",
                    (total, user_id, total),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("券到期回补时资产状态冲突")

                # 4. Q3 的 1:1 积分回补走旧账本（唯一写入点），镜像由触发器完成
                points_after = bridge.add_points(cur, user_id, total)

                pool_after = to_decimal(pools["subsidy_coupon_balance"]) + total
                coupon_after = coupon_balance - total
                service._write_ledger(cur, user_id, ASSET_COUPON, EV_COUPON_EXPIRED, -total, coupon_after)
                service._write_ledger(cur, 0, ASSET_SUBSIDY_COUPON, EV_COUPON_EXPIRED, total, pool_after)
                service._write_ledger(cur, user_id, ASSET_POINTS, EV_POINTS_BACKFILL, total, points_after)
                conn.commit()
        return total

    # ---------- 步骤 2：积分生成雨点（Q1） ----------

    def generate_rain(self, business_date: date, points_value: Decimal) -> dict:
        """按有效积分生成当日雨点，积分不清零（Q1）。

        只触碰 user_assets（不读写 system_pools），因此不存在与池锁的反向获取。
        """
        users = 0
        total_rain = Decimal("0")
        last_user_id = 0
        while True:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """SELECT id AS user_id FROM users
                           WHERE member_points > 0 AND id > %s ORDER BY id LIMIT %s""",
                        (last_user_id, BATCH_SIZE),
                    )
                    rows = cur.fetchall() or []
            if not rows:
                break
            last_user_id = int(rows[-1]["user_id"])
            for row in rows:
                rain = self._settle_user_rain(int(row["user_id"]), business_date, points_value)
                if rain > 0:
                    users += 1
                    total_rain += rain
        return {
            "users": users,
            "rain_generated": str(quantize_amount(total_rain)),
            "points_value": str(points_value),
        }

    def _settle_user_rain(self, user_id: int, business_date: date, points_value: Decimal) -> Decimal:
        """单会员雨点生成，独立事务；加锁顺序 users → user_assets（与旧业务同向）。"""
        service = RightsService()
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 先锁旧账本会员行；积分以 users.member_points 为准（唯一写入点）
                legacy = self._lock_legacy_or_skip(cur, user_id)
                if legacy is None:
                    conn.rollback()
                    return Decimal("0")
                service.lock_user_assets(cur, user_id)
                points = to_decimal(legacy["member_points"] or 0)
                cur.execute(
                    """INSERT IGNORE INTO rights_daily_settlements
                           (business_date, user_id, status, points_basis, points_value)
                       VALUES (%s, %s, 'pending', %s, %s)""",
                    (business_date, user_id, points, points_value),
                )
                if cur.rowcount != 1:
                    conn.rollback()
                    return Decimal("0")

                rain = rain_for_points(points, points_value)
                if rain <= 0:
                    cur.execute(
                        """UPDATE rights_daily_settlements
                           SET status = 'skipped', failure_code = %s, settled_at = NOW()
                           WHERE business_date = %s AND user_id = %s""",
                        (SKIP_ZERO_RAIN, business_date, user_id),
                    )
                    conn.commit()
                    return Decimal("0")

                # 雨点增长写入 true_total_points，由触发器镜像到 user_assets.rain_balance
                rain_after = bridge.add_rain(cur, user_id, rain)
                cur.execute(
                    """UPDATE rights_daily_settlements SET rain_generated = %s
                       WHERE business_date = %s AND user_id = %s""",
                    (rain, business_date, user_id),
                )
                service._write_ledger(cur, user_id, ASSET_RAIN, EV_RAIN_GENERATED, rain, rain_after)
                conn.commit()
        return rain

    # ---------- 步骤 3：雨点转优惠券（Q2） ----------

    def convert_rain_to_coupons(self, business_date: date) -> dict:
        """1 雨点 = 1 券，生成 30 天有效批次，已转雨点从余额扣除（Q2）。"""
        users = 0
        total_issued = Decimal("0")
        last_user_id = 0
        while True:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """SELECT id AS user_id FROM users
                           WHERE true_total_points > 0 AND id > %s ORDER BY id LIMIT %s""",
                        (last_user_id, BATCH_SIZE),
                    )
                    rows = cur.fetchall() or []
            if not rows:
                break
            last_user_id = int(rows[-1]["user_id"])
            for row in rows:
                issued = self._convert_user_rain(int(row["user_id"]), business_date)
                if issued > 0:
                    users += 1
                    total_issued += issued
        return {"users": users, "coupons_issued": str(quantize_amount(total_issued))}

    def _convert_user_rain(self, user_id: int, business_date: date) -> Decimal:
        """单会员雨点转券，独立事务；加锁顺序 users → user_assets（与旧业务同向）。"""
        service = RightsService()
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 雨点余额以 users.true_total_points 为准，user_assets.rain_balance 只是镜像
                legacy = self._lock_legacy_or_skip(cur, user_id)
                if legacy is None:
                    conn.rollback()
                    return Decimal("0")
                assets = service.lock_user_assets(cur, user_id)
                rain = to_decimal(legacy["true_total_points"] or 0)
                if rain <= 0:
                    conn.rollback()
                    return Decimal("0")
                valid_from, valid_to = coupon_validity(business_date)
                cur.execute(
                    """INSERT INTO rights_coupon_batches
                           (user_id, quantity, remaining, valid_from, valid_to, status, source_event, business_date)
                       VALUES (%s, %s, %s, %s, %s, 'active', %s, %s)""",
                    (user_id, rain, rain, valid_from, valid_to, EV_RAIN_TO_COUPON, business_date),
                )
                # 雨点清零写旧账本，触发器把镜像的 rain_balance 一起归零
                bridge.add_rain(cur, user_id, -rain)
                cur.execute(
                    """UPDATE user_assets
                       SET coupon_balance = coupon_balance + %s,
                           updated_at = NOW()
                       WHERE user_id = %s""",
                    (rain, user_id),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("雨点转券时资产状态冲突")
                cur.execute(
                    """UPDATE rights_daily_settlements
                       SET rain_converted = rain_generated, coupons_issued = rain_generated,
                           status = 'settled', settled_at = NOW()
                       WHERE business_date = %s AND user_id = %s""",
                    (business_date, user_id),
                )
                coupon_after = to_decimal(assets["coupon_balance"]) + rain
                service._write_ledger(cur, user_id, ASSET_RAIN, EV_RAIN_TO_COUPON, -rain, Decimal("0"))
                service._write_ledger(cur, user_id, ASSET_COUPON, EV_COUPON_ISSUED, rain, coupon_after)
                conn.commit()
        return rain

    # ---------- Q12 强制暂缓 ----------

    def payout_subsidy_pool(self, *args, **kwargs):
        """Q12：雨点补贴池下发机制未确认，禁止实现 12%/8% 发放与发放明细流水。

        该方法保持显式失败，避免任何调用方"以为"补贴发放可用。
        """
        raise SubsidyPayoutDisabled(
            "Q12 雨点补贴池下发机制未经甲方书面确认：补贴池本阶段只入池、不出池，不实现 12%/8% 发放"
        )
