"""V1.1 会员权益核心服务（第一阶段）。

业务基线：《docs/问题清单.md》Q1-Q17 为最高优先级，与需求文档冲突时以问题清单为准。

本模块实现的规则映射：

* Q6  实时咯哒值 = 底池优惠券余额 ÷ 平台未发放咯哒蛋余额。
      （底池 1,000,000 ÷ 平台 100,000,000 = 0.01，与需求 3.4 "100 券 = 8,000 枚" 完全吻合。
       任务描述中的 `(底池券余额 + 平台未发蛋余额) / 平台总蛋余额` 量纲不一致，
       按"冲突以问题清单为准"的约定采用 Q6 口径，见 `compute_unit_value`。）
* Q6  兑换数量 =（提交券 × 80%）÷ 入池前实时咯哒值，提交券的 20% 入雨点补贴池。
* Q4  多次兑换按加权平均成本判定：`(旧成本×旧数量 + 新成本×新数量) / 总数量`。
* Q4/Q5 实时咯哒值 >= 成本 × 2 时，蛋全部清零、按 `蛋数量 × 实时咯哒值` 发咯哒券；
      清零的蛋回补平台库存（Q5 "库存变化后重新计算咯哒值"），底池按发券数量扣减（Q5 "转券扣底池"）。
* Q7  咯哒券兑白酒：扣买家 3,000 咯哒券/坛，**不扣底池券**（对 Q5 的针对性修正），权属转移。
* Q12 雨点补贴池下发机制暂缓：本模块对补贴池**只有入池**（兑换 20% 分流），
      不存在任何出池/下发逻辑，相关发放见 `services/settlement_service.py` 的显式禁用。

工程约束：
* 所有金额/数量/咯哒值运算使用 `decimal.Decimal`，禁止 float；除法统一 ROUND_HALF_UP 保留 6 位。
* 事务内加锁顺序固定为：先 `system_pools`，再 `user_assets`，最后业务表（酒坛/挂牌/券批次）。
* 券余额、蛋数量等关键字段使用条件 UPDATE（`WHERE balance >= ?`）二次兜底，防止并发超发。
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Optional

from core.database import get_conn
from core.logging import get_logger

logger = get_logger(__name__)

# ==================== 规则常量 ====================

RULE_VERSION = "v1.1-p1"

#: 咯哒蛋发行总量（恒定，禁止增发）
TOTAL_EGG_SUPPLY = Decimal("100000000")
#: 初始底池优惠券（仅在 migrations/007_v1_rights.sql 初始化一次）
INITIAL_POOL_COUPONS = Decimal("1000000")

#: 兑换分流比例（Q6 / R3）
POOL_IN_RATIO = Decimal("0.8")
SUBSIDY_IN_RATIO = Decimal("0.2")

#: 自动转券触发线：权益增值 100%，即实时咯哒值达到成本的 2 倍（Q4 / R5）
CONVERSION_TRIGGER_MULTIPLE = Decimal("2")

#: 白酒兑换（Q7）：3,000 咯哒券 / 坛，100 斤/坛，仅酒价
GODA_COUPONS_PER_JAR = Decimal("3000")
WINE_PRICE_FEN = 300000
WINE_WEIGHT_JIN = Decimal("100")
#: 单次最多兑换坛数（Q8 一人限购 6 坛的保守上限）
MAX_WINE_JARS_PER_OPERATION = 6

#: 报价有效期
QUOTE_TTL_MINUTES = 15

#: 权益类型（与 rights_ledger.asset_type 枚举一致）
ASSET_POINTS = "points"
ASSET_RAIN = "rain"
ASSET_COUPON = "coupon"
ASSET_EGG = "egg"
ASSET_GODA_COUPON = "goda_coupon"
ASSET_POOL_COUPON = "pool_coupon"
ASSET_SUBSIDY_COUPON = "subsidy_coupon"
ASSET_PLATFORM_EGG = "platform_egg"

#: 业务事件（与 rights_ledger.event_type 取值一致）
EV_COUPON_TO_EGG = "coupon_to_egg"
EV_EGG_ISSUED = "egg_issued"
EV_EGG_AUTO_CONVERSION = "egg_auto_conversion"
EV_EGG_RETURN_TO_PLATFORM = "egg_return_to_platform"
EV_GODA_COUPON_ISSUED = "goda_coupon_issued"
EV_WINE_REDEMPTION = "wine_redemption"
EV_WINE_OWNERSHIP_TRANSFER = "wine_ownership_transfer"
EV_REVERSAL = "reversal"

#: 操作类型（与 rights_operations.operation_type 枚举一致）
OP_EGG_EXCHANGE = "egg_exchange"
OP_EGG_AUTO_CONVERSION = "egg_auto_conversion"
OP_WINE_QUOTE = "wine_redemption_quote"
OP_WINE_REDEMPTION = "wine_redemption"

#: 业务错误码（接口文档第 10 章拟定码，非历史错误码）
ERR_INVALID_ARGUMENT = "INVALID_ARGUMENT"
ERR_NOT_OWNER = "NOT_OWNER"
ERR_INSUFFICIENT_BALANCE = "INSUFFICIENT_BALANCE"
ERR_POOL_INSUFFICIENT = "POOL_INSUFFICIENT"
ERR_QUOTE_STALE = "QUOTE_STALE"
ERR_LISTING_UNAVAILABLE = "LISTING_UNAVAILABLE"
ERR_STATE_CONFLICT = "STATE_CONFLICT"
ERR_IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
ERR_SELF_TRADE_FORBIDDEN = "SELF_TRADE_FORBIDDEN"
ERR_RULE_UNCONFIRMED = "RULE_UNCONFIRMED"

DISCLAIMER = "本权益为会员消费回馈福利，非金融资产，不可提现、不可转让"
#: 白酒专区仍未确认的问题（Q13 器皿/包装/物流费用，Q15 应付金额口径，Q16 收款码载体）
WINE_BLOCKED_QUESTIONS = ("Q13",)

#: 统一精度：金额/数量/咯哒值 6 位小数
AMOUNT_QUANT = Decimal("0.000001")


class RightsError(Exception):
    """权益域业务异常：由 api/v1 统一映射为 {code, message, data, request_id}。"""

    def __init__(self, code: str, http_status: int, message: str):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.message = message


# ==================== Decimal 工具 ====================

def to_decimal(value: Any, field: str = "value") -> Decimal:
    """把 str/int/Decimal 转成 Decimal。

    显式拒绝 float 与 bool：float 已丢失精度，进入账务即不可逆。
    """
    if isinstance(value, Decimal):
        result = value
    elif isinstance(value, bool):
        raise RightsError(ERR_INVALID_ARGUMENT, 422, f"{field} 不能为布尔值")
    elif isinstance(value, int):
        result = Decimal(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise RightsError(ERR_INVALID_ARGUMENT, 422, f"{field} 不能为空")
        try:
            result = Decimal(text)
        except InvalidOperation as exc:
            raise RightsError(ERR_INVALID_ARGUMENT, 422, f"{field} 不是合法数值") from exc
    elif isinstance(value, float):
        raise RightsError(ERR_INVALID_ARGUMENT, 422, f"{field} 禁止使用浮点数，请传十进制字符串")
    else:
        raise RightsError(ERR_INVALID_ARGUMENT, 422, f"{field} 类型不支持")
    if not result.is_finite():
        raise RightsError(ERR_INVALID_ARGUMENT, 422, f"{field} 不能为 NaN/Infinity")
    return result


def quantize_amount(value: Decimal) -> Decimal:
    """统一保留 6 位小数，ROUND_HALF_UP。"""
    return value.quantize(AMOUNT_QUANT, rounding=ROUND_HALF_UP)


def format_amount(value: Optional[Decimal]) -> Optional[str]:
    """接口输出：十进制字符串（6 位小数），None 保持 None。"""
    if value is None:
        return None
    return str(quantize_amount(value))


# ==================== 纯计算（可单元测试，无数据库依赖） ====================

def compute_unit_value(pool_coupon_balance: Decimal, platform_egg_balance: Decimal) -> Optional[Decimal]:
    """实时咯哒值（Q6）= 底池优惠券余额 ÷ 平台未发放咯哒蛋余额。

    分母为 0（平台蛋库存耗尽）时返回 None，接口层输出 null，
    不得用 0 冒充"已计算"，也不得按 0 发放咯哒蛋。
    """
    pool = to_decimal(pool_coupon_balance, "pool_coupon_balance")
    eggs = to_decimal(platform_egg_balance, "platform_egg_balance")
    if eggs <= 0:
        return None
    if pool < 0:
        raise RightsError(ERR_STATE_CONFLICT, 409, "底池余额异常")
    return quantize_amount(pool / eggs)


def split_submission(coupon_quantity: Decimal) -> tuple[Decimal, Decimal]:
    """按 R3 拆分提交的优惠券：80% 入底池、20% 入雨点补贴池。

    补偿尾差：底池取 6 位舍入结果，补贴池取差额，
    保证 pool_in + subsidy_in 恒等于提交量，不产生第三笔"尾差券"。
    """
    quantity = quantize_amount(to_decimal(coupon_quantity, "coupon_quantity"))
    if quantity <= 0:
        raise RightsError(ERR_INVALID_ARGUMENT, 422, "兑换数量必须大于 0")
    pool_in = quantize_amount(quantity * POOL_IN_RATIO)
    subsidy_in = quantity - pool_in
    return pool_in, subsidy_in


def eggs_for_coupons(pool_in_quantity: Decimal, unit_value: Decimal) -> Decimal:
    """R4：咯哒蛋数量 =（提交券 × 80%）÷ 入池前实时咯哒值。"""
    pool_in = to_decimal(pool_in_quantity, "pool_in_quantity")
    unit = to_decimal(unit_value, "unit_value")
    if unit <= 0:
        raise RightsError(ERR_POOL_INSUFFICIENT, 422, "咯哒值无效，暂不可兑换")
    if pool_in <= 0:
        return Decimal("0")
    return quantize_amount(pool_in / unit)


def weighted_avg_cost(
    old_cost: Decimal,
    old_quantity: Decimal,
    new_cost: Decimal,
    new_quantity: Decimal,
) -> Decimal:
    """Q4 加权平均成本咯哒值 =（旧成本×旧数量 + 新成本×新数量）÷ 总数量。

    总数量为 0 时成本归零（无持仓即无成本基准）。
    """
    old_cost_d = to_decimal(old_cost, "old_cost")
    old_qty_d = to_decimal(old_quantity, "old_quantity")
    new_cost_d = to_decimal(new_cost, "new_cost")
    new_qty_d = to_decimal(new_quantity, "new_quantity")
    if old_qty_d < 0 or new_qty_d < 0:
        raise RightsError(ERR_STATE_CONFLICT, 409, "咯哒蛋数量异常")
    total_quantity = old_qty_d + new_qty_d
    if total_quantity <= 0:
        return Decimal("0")
    total_cost = old_cost_d * old_qty_d + new_cost_d * new_qty_d
    return quantize_amount(total_cost / total_quantity)


def conversion_triggered(unit_value: Optional[Decimal], avg_cost: Decimal) -> bool:
    """Q4 触发判定：实时咯哒值 >= 成本 × 2（增值 100%）。

    成本缺失（0 或无持仓）时不触发，避免 0 成本被任意值触发。
    """
    if unit_value is None:
        return False
    cost = to_decimal(avg_cost, "avg_cost")
    if cost <= 0:
        return False
    return to_decimal(unit_value, "unit_value") >= cost * CONVERSION_TRIGGER_MULTIPLE


def goda_coupons_for_eggs(egg_quantity: Decimal, unit_value: Decimal) -> Decimal:
    """R6：咯哒券 = 咯哒蛋数量 × 触发时刻实时咯哒值。"""
    eggs = to_decimal(egg_quantity, "egg_quantity")
    unit = to_decimal(unit_value, "unit_value")
    if eggs < 0 or unit < 0:
        raise RightsError(ERR_STATE_CONFLICT, 409, "转券参数异常")
    return quantize_amount(eggs * unit)


def goda_coupons_for_jars(jars: int) -> Decimal:
    """Q7：3,000 咯哒券 / 坛（仅酒价，Q13 附加费本阶段不计）。"""
    if isinstance(jars, bool) or not isinstance(jars, int):
        raise RightsError(ERR_INVALID_ARGUMENT, 422, "坛数必须为整数")
    if jars < 1 or jars > MAX_WINE_JARS_PER_OPERATION:
        raise RightsError(ERR_INVALID_ARGUMENT, 422, f"坛数须在 1-{MAX_WINE_JARS_PER_OPERATION} 之间")
    return quantize_amount(GODA_COUPONS_PER_JAR * jars)


# ==================== 内部小工具 ====================

def _new_operation_no(prefix: str) -> str:
    return f"{prefix}{datetime.now().strftime('%Y%m%d%H%M%S')}{secrets.token_hex(2).upper()}"


def _fingerprint(payload: dict) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


class RightsService:
    """V1.1 权益核心服务。所有写方法自管事务，失败一律回滚。"""

    # ---------- 加锁与台账 ----------

    @staticmethod
    def lock_pools(cur) -> dict:
        """加锁顺序第 1 步：锁 platform 池单例行（system_pools）。"""
        cur.execute(
            """SELECT id, total_egg_supply, pool_coupon_balance, subsidy_coupon_balance,
                      platform_egg_balance, valuation_version
               FROM system_pools WHERE id = 1 FOR UPDATE"""
        )
        row = cur.fetchone()
        if not row:
            raise RightsError(ERR_STATE_CONFLICT, 503, "权益池未初始化，请先执行 migrations/007_v1_rights.sql")
        return row

    @staticmethod
    def lock_user_assets(cur, user_id: int) -> dict:
        """加锁顺序第 2 步：锁会员资产行（user_assets），不存在则先建零值行。"""
        cur.execute("INSERT IGNORE INTO user_assets (user_id) VALUES (%s)", (user_id,))
        cur.execute(
            """SELECT user_id, points, rain_balance, coupon_balance, egg_quantity,
                      avg_cost_goda_value, goda_coupon_balance
               FROM user_assets WHERE user_id = %s FOR UPDATE""",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            raise RightsError(ERR_STATE_CONFLICT, 503, "会员资产账户初始化失败")
        return row

    @staticmethod
    def _write_ledger(
        cur,
        user_id: int,
        asset_type: str,
        event_type: str,
        quantity_delta: Decimal,
        balance_after: Decimal,
        unit_value: Optional[Decimal] = None,
        operation_no: Optional[str] = None,
        related_order_no: Optional[str] = None,
        reversal_of_id: Optional[int] = None,
    ) -> int:
        """追加一条权益流水（只 INSERT，绝不更新历史流水）。"""
        cur.execute(
            """INSERT INTO rights_ledger
                   (user_id, asset_type, event_type, quantity_delta, balance_after, unit_value,
                    operation_id, related_order_no, reversal_of_id, rule_version, occurred_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
            (
                user_id,
                asset_type,
                event_type,
                quantize_amount(quantity_delta),
                quantize_amount(balance_after),
                None if unit_value is None else quantize_amount(unit_value),
                operation_no,
                related_order_no,
                reversal_of_id,
                RULE_VERSION,
            ),
        )
        return int(cur.lastrowid)

    @staticmethod
    def _record_operation(cur, **fields) -> None:
        columns = ", ".join(fields.keys())
        placeholders = ", ".join(["%s"] * len(fields))
        cur.execute(
            f"INSERT INTO rights_operations ({columns}) VALUES ({placeholders})",
            tuple(fields.values()),
        )

    @staticmethod
    def _replay_idempotent(cur, user_id: int, operation_type: str, idempotency_key: str, fingerprint: str) -> Optional[dict]:
        """幂等重放：同一 user+类型+幂等键，参数一致则原样返回上次结果。

        使用加锁读（FOR UPDATE）绕过 REPEATABLE READ 快照，确保能看到并发已提交的结果。
        """
        cur.execute(
            """SELECT status, request_fingerprint, result
               FROM rights_operations
               WHERE user_id = %s AND operation_type = %s AND idempotency_key = %s
               FOR UPDATE""",
            (user_id, operation_type, idempotency_key),
        )
        row = cur.fetchone()
        if not row:
            return None
        if row["request_fingerprint"] and row["request_fingerprint"] != fingerprint:
            raise RightsError(ERR_IDEMPOTENCY_CONFLICT, 409, "同一幂等键的请求参数不一致")
        if row["status"] != "succeeded" or not row["result"]:
            raise RightsError(ERR_STATE_CONFLICT, 409, "该幂等键的操作未成功，请换用新键重试")
        result = row["result"]
        if isinstance(result, (str, bytes)):
            result = json.loads(result)
        result = dict(result)
        result["idempotent_replay"] = True
        return result

    # ---------- 查询 ----------

    def get_pool_snapshot(self) -> dict:
        """GET /api/v1/rights/pool —— 池与咯哒值快照（只读，不加锁）。"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT total_egg_supply, pool_coupon_balance, subsidy_coupon_balance,
                              platform_egg_balance, valuation_version, updated_at
                       FROM system_pools WHERE id = 1"""
                )
                row = cur.fetchone()
        if not row:
            raise RightsError(ERR_STATE_CONFLICT, 503, "权益池未初始化，请先执行 migrations/007_v1_rights.sql")
        unit_value = compute_unit_value(row["pool_coupon_balance"], row["platform_egg_balance"])
        return {
            "total_supply": format_amount(row["total_egg_supply"]),
            "pool_coupon_balance": format_amount(row["pool_coupon_balance"]),
            "subsidy_coupon_balance": format_amount(row["subsidy_coupon_balance"]),
            "platform_egg_balance": format_amount(row["platform_egg_balance"]),
            "unit_value": format_amount(unit_value),
            "valuation_version": int(row["valuation_version"]),
            "valued_at": row["updated_at"],
            "rule_version": RULE_VERSION,
            "blocked_questions": [],
            "disclaimer": DISCLAIMER,
        }

    def get_my_rights(self, user_id: int) -> dict:
        """GET /api/v1/rights/me —— 会员权益总览（只读取，不写库）。"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT user_id, points, rain_balance, coupon_balance, egg_quantity,
                              avg_cost_goda_value, goda_coupon_balance
                       FROM user_assets WHERE user_id = %s""",
                    (user_id,),
                )
                assets = cur.fetchone()
                cur.execute("SELECT member_level FROM users WHERE id = %s", (user_id,))
                user_row = cur.fetchone()
                cur.execute(
                    """SELECT total_egg_supply, pool_coupon_balance, platform_egg_balance, valuation_version
                       FROM system_pools WHERE id = 1"""
                )
                pools = cur.fetchone()

        member_level = int((user_row or {}).get("member_level") or 0)
        zero = Decimal("0")
        assets = assets or {
            "points": zero,
            "rain_balance": zero,
            "coupon_balance": zero,
            "egg_quantity": zero,
            "avg_cost_goda_value": zero,
            "goda_coupon_balance": zero,
        }
        unit_value = None
        if pools:
            unit_value = compute_unit_value(pools["pool_coupon_balance"], pools["platform_egg_balance"])

        egg_quantity = to_decimal(assets["egg_quantity"])
        avg_cost = to_decimal(assets["avg_cost_goda_value"])
        current_value = None
        growth_ratio = None
        if unit_value is not None:
            current_value = quantize_amount(egg_quantity * unit_value)
            if avg_cost > 0:
                growth_ratio = quantize_amount((unit_value - avg_cost) / avg_cost)

        return {
            "member_level": member_level,
            "capabilities": {
                # Q8：六星店长解锁挂牌权限，等级门槛待甲方书面确认（当前按 6 星）
                "can_list_wine": member_level >= 6,
            },
            "points": {"balance": format_amount(to_decimal(assets["points"]))},
            "rain": {"balance": format_amount(to_decimal(assets["rain_balance"]))},
            "coupons": {"balance": format_amount(to_decimal(assets["coupon_balance"])), "expiring_quantity": None},
            "eggs": {
                "quantity": format_amount(egg_quantity),
                "avg_cost_goda_value": format_amount(avg_cost) if avg_cost > 0 else None,
                "current_value": format_amount(current_value),
                "current_unit_value": format_amount(unit_value),
                "growth_ratio": format_amount(growth_ratio),
                "conversion_threshold_ratio": "1.000000",
            },
            "goda_coupons": {"balance": format_amount(to_decimal(assets["goda_coupon_balance"]))},
            "valuation_version": int(pools["valuation_version"]) if pools else None,
            "rule_version": RULE_VERSION,
            "valued_at": datetime.now(),
            "blocked_questions": [],
            "disclaimer": DISCLAIMER,
        }

    # ---------- 兑换咯哒蛋（FR-205 / Q6） ----------

    def quote_egg_exchange(self, user_id: int, coupon_quantity: Any) -> dict:
        """兑换预报价：只读快照，不扣券、不锁价。"""
        quantity = quantize_amount(to_decimal(coupon_quantity, "coupon_quantity"))
        if quantity <= 0:
            raise RightsError(ERR_INVALID_ARGUMENT, 422, "兑换数量必须大于 0")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT pool_coupon_balance, platform_egg_balance, valuation_version
                       FROM system_pools WHERE id = 1"""
                )
                pools = cur.fetchone()
                cur.execute("SELECT coupon_balance FROM user_assets WHERE user_id = %s", (user_id,))
                assets = cur.fetchone()
        if not pools:
            raise RightsError(ERR_STATE_CONFLICT, 503, "权益池未初始化")
        unit_value = compute_unit_value(pools["pool_coupon_balance"], pools["platform_egg_balance"])
        if unit_value is None:
            raise RightsError(ERR_POOL_INSUFFICIENT, 422, "平台咯哒蛋库存为 0，暂不可兑换")
        pool_in, subsidy_in = split_submission(quantity)
        eggs = eggs_for_coupons(pool_in, unit_value)
        available = to_decimal((assets or {}).get("coupon_balance") or 0)
        return {
            "coupon_quantity": format_amount(quantity),
            "coupon_balance": format_amount(available),
            "pool_in_quantity": format_amount(pool_in),
            "subsidy_in_quantity": format_amount(subsidy_in),
            "egg_quantity": format_amount(eggs),
            "unit_value": format_amount(unit_value),
            "valuation_version": int(pools["valuation_version"]),
            "rule_version": RULE_VERSION,
            "disclaimer": DISCLAIMER,
        }

    def exchange_eggs(
        self,
        user_id: int,
        coupon_quantity: Any,
        expected_unit_value: Any = None,
        idempotency_key: Optional[str] = None,
    ) -> dict:
        """POST /api/v1/rights/egg-exchanges —— 优惠券兑换咯哒蛋。

        单事务内完成：扣券 → 80% 入底池 / 20% 入补贴池 → 发放咯哒蛋 → 更新加权平均成本 → 写台账。
        加锁顺序：system_pools → user_assets（全库统一，防死锁）。
        """
        quantity = quantize_amount(to_decimal(coupon_quantity, "coupon_quantity"))
        if quantity <= 0:
            raise RightsError(ERR_INVALID_ARGUMENT, 422, "兑换数量必须大于 0")
        expected = None
        if expected_unit_value is not None:
            expected = quantize_amount(to_decimal(expected_unit_value, "expected_unit_value"))
        fingerprint = _fingerprint({"coupon_quantity": format_amount(quantity), "expected_unit_value": format_amount(expected)})

        with get_conn() as conn:
            with conn.cursor() as cur:
                pools = self.lock_pools(cur)
                assets = self.lock_user_assets(cur, user_id)
                if idempotency_key:
                    replay = self._replay_idempotent(cur, user_id, OP_EGG_EXCHANGE, idempotency_key, fingerprint)
                    if replay is not None:
                        conn.rollback()
                        return replay

                unit_before = compute_unit_value(pools["pool_coupon_balance"], pools["platform_egg_balance"])
                if unit_before is None:
                    raise RightsError(ERR_POOL_INSUFFICIENT, 422, "平台咯哒蛋库存为 0，暂不可兑换")
                if expected is not None and expected != unit_before:
                    raise RightsError(ERR_QUOTE_STALE, 409, "咯哒值已变化，请重新报价后再兑换")
                if to_decimal(assets["coupon_balance"]) < quantity:
                    raise RightsError(ERR_INSUFFICIENT_BALANCE, 422, "优惠券余额不足")

                pool_in, subsidy_in = split_submission(quantity)
                eggs = eggs_for_coupons(pool_in, unit_before)
                if eggs <= 0:
                    raise RightsError(ERR_INVALID_ARGUMENT, 422, "兑换数量过小，无法产生咯哒蛋")
                if to_decimal(pools["platform_egg_balance"]) < eggs:
                    raise RightsError(ERR_POOL_INSUFFICIENT, 422, "平台咯哒蛋库存不足")

                operation_no = _new_operation_no("EXG")
                # 池已加锁，条件 UPDATE 作为超发二次兜底
                cur.execute(
                    """UPDATE system_pools
                       SET pool_coupon_balance = pool_coupon_balance + %s,
                           subsidy_coupon_balance = subsidy_coupon_balance + %s,
                           platform_egg_balance = platform_egg_balance - %s,
                           valuation_version = valuation_version + 1,
                           updated_at = NOW()
                       WHERE id = 1 AND platform_egg_balance >= %s""",
                    (pool_in, subsidy_in, eggs, eggs),
                )
                if cur.rowcount != 1:
                    raise RightsError(ERR_POOL_INSUFFICIENT, 409, "平台咯哒蛋库存不足，请重新报价")

                new_egg_quantity = to_decimal(assets["egg_quantity"]) + eggs
                new_cost = weighted_avg_cost(
                    to_decimal(assets["avg_cost_goda_value"]), to_decimal(assets["egg_quantity"]), unit_before, eggs
                )
                cur.execute(
                    """UPDATE user_assets
                       SET coupon_balance = coupon_balance - %s,
                           egg_quantity = egg_quantity + %s,
                           avg_cost_goda_value = %s,
                           updated_at = NOW()
                       WHERE user_id = %s AND coupon_balance >= %s""",
                    (quantity, eggs, new_cost, user_id, quantity),
                )
                if cur.rowcount != 1:
                    raise RightsError(ERR_INSUFFICIENT_BALANCE, 409, "优惠券余额不足，请刷新后重试")

                coupon_after = to_decimal(assets["coupon_balance"]) - quantity
                pool_after = to_decimal(pools["pool_coupon_balance"]) + pool_in
                egg_inventory_after = to_decimal(pools["platform_egg_balance"]) - eggs
                unit_after = compute_unit_value(pool_after, egg_inventory_after)

                self._write_ledger(cur, user_id, ASSET_COUPON, EV_COUPON_TO_EGG, -quantity, coupon_after, unit_before, operation_no)
                self._write_ledger(cur, user_id, ASSET_EGG, EV_EGG_ISSUED, eggs, new_egg_quantity, unit_before, operation_no)

                result = {
                    "exchange_id": operation_no,
                    "status": "succeeded",
                    "coupon_quantity": format_amount(quantity),
                    "pool_in_quantity": format_amount(pool_in),
                    "subsidy_in_quantity": format_amount(subsidy_in),
                    "egg_quantity": format_amount(eggs),
                    "executed_unit_value": format_amount(unit_before),
                    "unit_value_after": format_amount(unit_after),
                    "avg_cost_goda_value": format_amount(new_cost),
                    "egg_quantity_total": format_amount(new_egg_quantity),
                    "coupon_balance_after": format_amount(coupon_after),
                    "valuation_version_before": int(pools["valuation_version"]),
                    "valuation_version_after": int(pools["valuation_version"]) + 1,
                    "rule_version": RULE_VERSION,
                    "created_at": datetime.now(),
                }
                self._record_operation(
                    cur,
                    operation_no=operation_no,
                    operation_type=OP_EGG_EXCHANGE,
                    user_id=user_id,
                    status="succeeded",
                    idempotency_key=idempotency_key,
                    request_fingerprint=fingerprint,
                    coupon_quantity=quantity,
                    pool_in_quantity=pool_in,
                    subsidy_in_quantity=subsidy_in,
                    egg_quantity=eggs,
                    unit_value_before=unit_before,
                    unit_value_after=unit_after,
                    valuation_version_before=pools["valuation_version"],
                    valuation_version_after=int(pools["valuation_version"]) + 1,
                    payload=_dumps({"coupon_quantity": format_amount(quantity)}),
                    result=_dumps(result),
                    committed_at=datetime.now(),
                )
                conn.commit()

        conversion = self.maybe_auto_convert(user_id)
        if conversion:
            result["auto_conversion"] = conversion
        return result

    # ---------- 自动转咯哒券（FR-206 / Q4 / Q5） ----------

    def maybe_auto_convert(self, user_id: int) -> Optional[dict]:
        """实时监测：实时咯哒值 >= 成本×2 时，蛋清零、按 `蛋数量×实时咯哒值` 发咯哒券。

        Q5：清零的蛋回补平台库存，底池按发券数量扣减（"转券扣底池"）。
        底池不足时不转换（不产生透支），返回 None 由下一次监测重试。
        本方法自带事务，天然幂等：蛋被清零后数量为 0，不会重复转券。
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                pools = self.lock_pools(cur)
                assets = self.lock_user_assets(cur, user_id)

                egg_quantity = to_decimal(assets["egg_quantity"])
                avg_cost = to_decimal(assets["avg_cost_goda_value"])
                if egg_quantity <= 0:
                    return None
                unit_value = compute_unit_value(pools["pool_coupon_balance"], pools["platform_egg_balance"])
                if not conversion_triggered(unit_value, avg_cost):
                    return None

                goda_quantity = goda_coupons_for_eggs(egg_quantity, unit_value)
                if goda_quantity <= 0:
                    return None
                if to_decimal(pools["pool_coupon_balance"]) < goda_quantity:
                    logger.warning(
                        "auto_conversion_deferred pool_insufficient user=%s need=%s pool=%s",
                        user_id, goda_quantity, pools["pool_coupon_balance"],
                    )
                    conn.rollback()
                    return None

                operation_no = _new_operation_no("CVT")
                egg_inventory_after = to_decimal(pools["platform_egg_balance"]) + egg_quantity
                if egg_inventory_after > to_decimal(pools["total_egg_supply"]):
                    raise RightsError(ERR_STATE_CONFLICT, 409, "平台咯哒蛋库存超出总量恒定上限")

                cur.execute(
                    """UPDATE system_pools
                       SET pool_coupon_balance = pool_coupon_balance - %s,
                           platform_egg_balance = platform_egg_balance + %s,
                           valuation_version = valuation_version + 1,
                           updated_at = NOW()
                       WHERE id = 1 AND pool_coupon_balance >= %s
                             AND platform_egg_balance + %s <= total_egg_supply""",
                    (goda_quantity, egg_quantity, goda_quantity, egg_quantity),
                )
                if cur.rowcount != 1:
                    raise RightsError(ERR_STATE_CONFLICT, 409, "转券时底池状态冲突，请稍后重试")

                goda_after = to_decimal(assets["goda_coupon_balance"]) + goda_quantity
                cur.execute(
                    """UPDATE user_assets
                       SET egg_quantity = 0,
                           avg_cost_goda_value = 0,
                           goda_coupon_balance = goda_coupon_balance + %s,
                           updated_at = NOW()
                       WHERE user_id = %s AND egg_quantity = %s""",
                    (goda_quantity, user_id, egg_quantity),
                )
                if cur.rowcount != 1:
                    raise RightsError(ERR_STATE_CONFLICT, 409, "转券时持仓状态冲突，请稍后重试")

                pool_after = to_decimal(pools["pool_coupon_balance"]) - goda_quantity
                unit_after = compute_unit_value(pool_after, egg_inventory_after)

                self._write_ledger(cur, user_id, ASSET_EGG, EV_EGG_AUTO_CONVERSION, -egg_quantity, Decimal("0"), unit_value, operation_no)
                self._write_ledger(cur, 0, ASSET_PLATFORM_EGG, EV_EGG_RETURN_TO_PLATFORM, egg_quantity, egg_inventory_after, unit_value, operation_no)
                self._write_ledger(cur, 0, ASSET_POOL_COUPON, EV_GODA_COUPON_ISSUED, -goda_quantity, pool_after, unit_value, operation_no)
                self._write_ledger(cur, user_id, ASSET_GODA_COUPON, EV_GODA_COUPON_ISSUED, goda_quantity, goda_after, unit_value, operation_no)

                result = {
                    "conversion_id": operation_no,
                    "status": "succeeded",
                    "egg_quantity_converted": format_amount(egg_quantity),
                    "goda_coupon_quantity": format_amount(goda_quantity),
                    "cost_basis": format_amount(avg_cost),
                    "unit_value": format_amount(unit_value),
                    "unit_value_after": format_amount(unit_after),
                    "goda_coupon_balance": format_amount(goda_after),
                    "rule_version": RULE_VERSION,
                    "triggered_at": datetime.now(),
                }
                self._record_operation(
                    cur,
                    operation_no=operation_no,
                    operation_type=OP_EGG_AUTO_CONVERSION,
                    user_id=user_id,
                    status="succeeded",
                    egg_quantity=egg_quantity,
                    goda_coupon_quantity=goda_quantity,
                    unit_value_before=unit_value,
                    unit_value_after=unit_after,
                    valuation_version_before=pools["valuation_version"],
                    valuation_version_after=int(pools["valuation_version"]) + 1,
                    payload=_dumps({"avg_cost_goda_value": format_amount(avg_cost)}),
                    result=_dumps(result),
                    committed_at=datetime.now(),
                )
                conn.commit()
        logger.info("egg_auto_conversion user=%s eggs=%s goda=%s", user_id, egg_quantity, goda_quantity)
        return result

    # ---------- 白酒：报价与咯哒券兑换（FR-207 / Q7） ----------

    @staticmethod
    def _load_listing(cur, listing_id: int) -> dict:
        cur.execute(
            """SELECT l.id AS listing_id, l.listing_no, l.contract_no, l.seller_id,
                      l.status AS listing_status, l.wine_price_fen, l.version AS listing_version,
                      j.id AS jar_id, j.owner_id, j.status AS jar_status, j.weight_jin
               FROM wine_listings l JOIN wine_jars j ON j.id = l.jar_id
               WHERE l.id = %s""",
            (listing_id,),
        )
        row = cur.fetchone()
        if not row:
            raise RightsError(ERR_LISTING_UNAVAILABLE, 404, "酒坛挂牌不存在")
        return row

    def quote_wine_redemption(self, user_id: int, listing_id: int, jars: int = 1) -> dict:
        """POST /api/v1/wine/redemption-quotes —— 咯哒券兑酒报价。

        Q7：3,000 咯哒券/坛，**不扣底池券**；Q13 的包装/器皿/物流费用未确认，
        三个费用字段一律返回 null（null 表示"未确认"，不是"免费"）。
        """
        needed = goda_coupons_for_jars(jars)
        with get_conn() as conn:
            with conn.cursor() as cur:
                row = self._load_listing(cur, listing_id)
                if row["listing_status"] != "listed" or row["jar_status"] not in ("listed", "owned"):
                    raise RightsError(ERR_LISTING_UNAVAILABLE, 409, "酒坛当前不可兑换")
                if int(row["seller_id"]) == int(user_id):
                    raise RightsError(ERR_SELF_TRADE_FORBIDDEN, 422, "不得购买本人挂牌的酒坛")
                if int(row["owner_id"]) != int(row["seller_id"]):
                    raise RightsError(ERR_STATE_CONFLICT, 409, "酒坛权属与挂牌人不一致")
                cur.execute("SELECT goda_coupon_balance FROM user_assets WHERE user_id = %s", (user_id,))
                assets = cur.fetchone() or {"goda_coupon_balance": 0}
                balance = to_decimal(assets["goda_coupon_balance"])
                if balance < needed:
                    raise RightsError(ERR_INSUFFICIENT_BALANCE, 422, "咯哒券余额不足")

                operation_no = _new_operation_no("WQ")
                expires_at = datetime.now() + timedelta(minutes=QUOTE_TTL_MINUTES)
                result = {
                    "quote_id": operation_no,
                    "listing_id": str(row["listing_id"]),
                    "contract_no": row["contract_no"],
                    "jars": jars,
                    "weight_jin": format_amount(to_decimal(row["weight_jin"])),
                    "goda_coupon_quantity": format_amount(needed),
                    "goda_coupon_balance": format_amount(balance),
                    # Q7：兑酒不扣底池，故底池扣减量恒为 0
                    "pool_coupon_debit": format_amount(Decimal("0")),
                    "wine_price_fen": int(row["wine_price_fen"]),
                    "fees": {"packaging_fen": None, "container_fen": None, "shipping_fen": None},
                    "rule_version": RULE_VERSION,
                    "expires_at": expires_at,
                    "blocked_questions": list(WINE_BLOCKED_QUESTIONS),
                    "disclaimer": DISCLAIMER,
                }
                self._record_operation(
                    cur,
                    operation_no=operation_no,
                    operation_type=OP_WINE_QUOTE,
                    user_id=user_id,
                    status="quoted",
                    goda_coupon_quantity=needed,
                    target_type="wine_listing",
                    target_id=row["listing_id"],
                    payload=_dumps({"listing_id": row["listing_id"], "jars": jars}),
                    result=_dumps(result),
                    expires_at=expires_at,
                )
                conn.commit()
        return result

    def redeem_wine_with_goda_coupons(
        self,
        user_id: int,
        listing_id: int,
        jars: int = 1,
        idempotency_key: Optional[str] = None,
    ) -> dict:
        """咯哒券兑换坛装白酒（服务层实现，第一阶段仅暴露报价接口）。

        Q7：扣买家咯哒券、**不扣底池券**，合同权属转移给买家，买家不获得积分。
        卖家 80% 货款与 20% 积分结算依赖 Q9/Q10/Q15，属第二阶段，未在此实现。
        """
        needed = goda_coupons_for_jars(jars)
        fingerprint = _fingerprint({"listing_id": listing_id, "jars": jars})
        with get_conn() as conn:
            with conn.cursor() as cur:
                pools = self.lock_pools(cur)
                assets = self.lock_user_assets(cur, user_id)
                if idempotency_key:
                    replay = self._replay_idempotent(cur, user_id, OP_WINE_REDEMPTION, idempotency_key, fingerprint)
                    if replay is not None:
                        conn.rollback()
                        return replay
                row = self._load_listing(cur, listing_id)
                if row["listing_status"] != "listed":
                    raise RightsError(ERR_LISTING_UNAVAILABLE, 409, "酒坛当前不可兑换")
                if int(row["seller_id"]) == int(user_id):
                    raise RightsError(ERR_SELF_TRADE_FORBIDDEN, 422, "不得购买本人挂牌的酒坛")
                if int(row["owner_id"]) != int(row["seller_id"]):
                    raise RightsError(ERR_STATE_CONFLICT, 409, "酒坛权属与挂牌人不一致")
                if to_decimal(assets["goda_coupon_balance"]) < needed:
                    raise RightsError(ERR_INSUFFICIENT_BALANCE, 422, "咯哒券余额不足")

                cur.execute(
                    """UPDATE wine_listings
                       SET status = 'sold', buyer_id = %s, sold_at = NOW(), version = version + 1, updated_at = NOW()
                       WHERE id = %s AND status = 'listed'""",
                    (user_id, listing_id),
                )
                if cur.rowcount != 1:
                    raise RightsError(ERR_LISTING_UNAVAILABLE, 409, "酒坛已被其他买家锁定")
                cur.execute(
                    """UPDATE wine_jars
                       SET owner_id = %s, status = 'owned', ownership_version = ownership_version + 1,
                           acquired_at = NOW(), updated_at = NOW()
                       WHERE id = %s AND owner_id = %s""",
                    (user_id, row["jar_id"], row["seller_id"]),
                )
                if cur.rowcount != 1:
                    raise RightsError(ERR_STATE_CONFLICT, 409, "酒坛权属变更冲突")
                cur.execute(
                    """UPDATE user_assets
                       SET goda_coupon_balance = goda_coupon_balance - %s, updated_at = NOW()
                       WHERE user_id = %s AND goda_coupon_balance >= %s""",
                    (needed, user_id, needed),
                )
                if cur.rowcount != 1:
                    raise RightsError(ERR_INSUFFICIENT_BALANCE, 409, "咯哒券余额不足")

                operation_no = _new_operation_no("WRD")
                unit_value = compute_unit_value(pools["pool_coupon_balance"], pools["platform_egg_balance"])
                goda_after = to_decimal(assets["goda_coupon_balance"]) - needed
                self._write_ledger(
                    cur, user_id, ASSET_GODA_COUPON, EV_WINE_REDEMPTION, -needed, goda_after, unit_value,
                    operation_no, related_order_no=row["contract_no"],
                )
                self._write_ledger(
                    cur, user_id, ASSET_GODA_COUPON, EV_WINE_OWNERSHIP_TRANSFER, Decimal("0"), goda_after, unit_value,
                    operation_no, related_order_no=row["contract_no"],
                )
                result = {
                    "redemption_id": operation_no,
                    "status": "succeeded",
                    "listing_id": str(listing_id),
                    "contract_no": row["contract_no"],
                    "jars": jars,
                    "goda_coupon_quantity": format_amount(needed),
                    "goda_coupon_balance_after": format_amount(goda_after),
                    "pool_coupon_debit": format_amount(Decimal("0")),
                    "buyer_points": format_amount(Decimal("0")),
                    "created_at": datetime.now(),
                    "rule_version": RULE_VERSION,
                }
                self._record_operation(
                    cur,
                    operation_no=operation_no,
                    operation_type=OP_WINE_REDEMPTION,
                    user_id=user_id,
                    status="succeeded",
                    idempotency_key=idempotency_key,
                    request_fingerprint=fingerprint,
                    goda_coupon_quantity=needed,
                    unit_value_before=unit_value,
                    valuation_version_before=pools["valuation_version"],
                    target_type="wine_listing",
                    target_id=listing_id,
                    payload=_dumps({"listing_id": listing_id, "jars": jars}),
                    result=_dumps(result),
                    committed_at=datetime.now(),
                )
                conn.commit()
        return result
