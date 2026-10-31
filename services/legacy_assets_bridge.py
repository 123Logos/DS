"""旧账本 ⇄ V1.1 权益账本的桥接（漏洞 1 & 2：解决新旧账本分叉）。

背景
----
V1.1 把积分、雨点搬进了 `user_assets`，但旧业务路径（商品购买送积分、积分抵扣、
退款、旧券核销、线下收银、公益捐赠、雨点兑券……）仍然直接读写
`users.member_points` / `users.true_total_points`。两条链路各写各的，
用户在小程序看到的积分（读 users）和 V1.1 结算用的积分（读 user_assets）会分叉。

单向权威模型
------------
* `users.member_points`（积分）与 `users.true_total_points`（雨点）是**唯一写入点**；
* `user_assets.points` / `user_assets.rain_balance` 是**镜像**，由数据库触发器
  `trg_users_assets_mirror_update`（见 `migrations/008_legacy_assets_bridge.sql`）
  在同一事务内按增量维护；
* 任何新代码（含 V1.1 日结）要改积分/雨点，都必须走本模块写 users 侧，
  **禁止直接 UPDATE user_assets.points / rain_balance**。

为什么不做「双写”
----------------
触发器已经在 users 侧改动时镜像到 user_assets，如果应用层再补一次写，
同一笔增量会被记两次。所以本模块只写 users，镜像交给触发器，天然不重复。

加锁顺序
--------
触发器在 users 行锁之后才拿 user_assets 行锁。为了让全库只有一种获取顺序，
需要跨两张表操作时必须先 :func:`lock_legacy_user`（锁 users）再
`RightsService.lock_user_assets`（锁 user_assets）；只操作 user_assets 的路径
（如兑换咯哒蛋）不得反向去更新 users。
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Optional

from core.logging import get_logger
from services.rights_service import AMOUNT_QUANT, RightsError, ERR_STATE_CONFLICT, format_amount, quantize_amount, to_decimal

logger = get_logger(__name__)

#: 旧账本积分列（唯一写入点）
LEGACY_POINTS_COLUMN = "member_points"
#: 旧账本雨点列（唯一写入点）
LEGACY_RAIN_COLUMN = "true_total_points"

#: 桥接依赖的触发器，缺失时对账与结算都必须显式失败，不能"看起来正常"
REQUIRED_TRIGGERS = ("trg_users_assets_mirror_insert", "trg_users_assets_mirror_update")

#: 单批对账扫描上限
PARITY_SCAN_LIMIT = 500


class LegacyBridgeError(RuntimeError):
    """旧账本桥接失败（会员不存在、桥接触发器未安装等）。"""


def lock_legacy_user(cur, user_id: int) -> dict:
    """加锁顺序第 1 步（相对 users）：锁定旧账本会员行。

    必须在 `RightsService.lock_user_assets` **之前**调用，保证全库获取顺序一致：
    `users` 先于 `user_assets`，与数据库镜像触发器的加锁方向相同，避免死锁。
    """
    cur.execute(
        "SELECT id, member_points, true_total_points FROM users WHERE id = %s FOR UPDATE",
        (user_id,),
    )
    row = cur.fetchone()
    if not row:
        raise LegacyBridgeError(f"会员不存在: {user_id}")
    # 镜像行缺失时按旧账本绝对值补建：否则触发器那条带 WHERE user_id 的增量 UPDATE
    # 会匹配 0 行，本次变动静默丢失。补建同样受 users 行锁保护，不会与并发写打架。
    # 这里不做任何负数夹取：旧账本为负说明上游越界扣减，应当由 CHECK 约束/迁移报告
    # 暴露出来，而不是悄悄补成 0。
    cur.execute(
        """INSERT IGNORE INTO user_assets (user_id, points, rain_balance)
           SELECT id, COALESCE(member_points, 0), COALESCE(true_total_points, 0)
           FROM users WHERE id = %s""",
        (user_id,),
    )
    return row


def _apply_legacy_delta(cur, user_id: int, column: str, delta: Decimal) -> Decimal:
    """对旧账本积分列做带下界保护的增量更新，返回更新后的旧账本余额。

    `AND {column} + %s >= 0` 让扣减在余额不足时影响 0 行而不是写出负值，
    由调用方决定是抛错还是跳过。
    """
    if column not in (LEGACY_POINTS_COLUMN, LEGACY_RAIN_COLUMN):
        raise ValueError(f"不支持的旧账本列: {column}")
    cur.execute(
        f"""UPDATE users SET {column} = {column} + %s
            WHERE id = %s AND {column} + %s >= 0""",
        (delta, user_id, delta),
    )
    if cur.rowcount != 1:
        raise LegacyBridgeError(f"旧账本 {column} 更新失败（余额不足或会员不存在）: user={user_id} delta={delta}")
    cur.execute(f"SELECT {column} AS balance FROM users WHERE id = %s", (user_id,))
    return to_decimal(cur.fetchone()["balance"])


def add_points(cur, user_id: int, delta: Any) -> Decimal:
    """积分增量（正为发、负为扣），写 `users.member_points`，镜像由触发器完成。

    调用前若同一事务还要写 `user_assets`，请先 :func:`lock_legacy_user`。
    """
    return _apply_legacy_delta(cur, user_id, LEGACY_POINTS_COLUMN, quantize_amount(to_decimal(delta, "points_delta")))


def add_rain(cur, user_id: int, delta: Any) -> Decimal:
    """雨点增量，写 `users.true_total_points`，镜像由触发器完成。"""
    return _apply_legacy_delta(cur, user_id, LEGACY_RAIN_COLUMN, quantize_amount(to_decimal(delta, "rain_delta")))


def read_assets(cur, user_id: int) -> dict:
    """读取镜像侧资产快照（不加锁），不存在时返回零值字典。"""
    cur.execute(
        """SELECT points, rain_balance, coupon_balance, egg_quantity,
                  avg_cost_goda_value, goda_coupon_balance
           FROM user_assets WHERE user_id = %s""",
        (user_id,),
    )
    row = cur.fetchone()
    if row:
        return row
    zero = Decimal("0")
    return {
        "points": zero,
        "rain_balance": zero,
        "coupon_balance": zero,
        "egg_quantity": zero,
        "avg_cost_goda_value": zero,
        "goda_coupon_balance": zero,
    }


def total_legacy_points(cur) -> Decimal:
    cur.execute("SELECT COALESCE(SUM(member_points), 0) AS total FROM users")
    return to_decimal(cur.fetchone()["total"] or 0)


def total_legacy_rain(cur) -> Decimal:
    cur.execute("SELECT COALESCE(SUM(true_total_points), 0) AS total FROM users")
    return to_decimal(cur.fetchone()["total"] or 0)


def total_v1_points(cur) -> Decimal:
    cur.execute("SELECT COALESCE(SUM(points), 0) AS total FROM user_assets")
    return to_decimal(cur.fetchone()["total"] or 0)


def total_v1_rain(cur) -> Decimal:
    cur.execute("SELECT COALESCE(SUM(rain_balance), 0) AS total FROM user_assets")
    return to_decimal(cur.fetchone()["total"] or 0)


def parity_report(cur) -> dict:
    """全库对账：旧账本合计 vs V1.1 镜像合计。

    `balanced` 为 True 才是可交付状态。差额单位与积分/雨点相同（1:1）。
    """
    totals = {
        "legacy_points": total_legacy_points(cur),
        "v1_points": total_v1_points(cur),
        "legacy_rain": total_legacy_rain(cur),
        "v1_rain": total_v1_rain(cur),
    }
    totals["drift_points"] = totals["legacy_points"] - totals["v1_points"]
    totals["drift_rain"] = totals["legacy_rain"] - totals["v1_rain"]
    cur.execute(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN COALESCE(a.points, 0) <> COALESCE(u.member_points, 0) THEN 1 ELSE 0 END) AS points_mismatch,
                  SUM(CASE WHEN COALESCE(a.rain_balance, 0) <> COALESCE(u.true_total_points, 0) THEN 1 ELSE 0 END) AS rain_mismatch,
                  SUM(CASE WHEN a.user_id IS NULL THEN 1 ELSE 0 END) AS assets_row_missing
           FROM users u LEFT JOIN user_assets a ON a.user_id = u.id"""
    )
    row = cur.fetchone() or {}
    totals["users"] = int(row.get("total") or 0)
    totals["points_mismatch_users"] = int(row.get("points_mismatch") or 0)
    totals["rain_mismatch_users"] = int(row.get("rain_mismatch") or 0)
    totals["assets_row_missing"] = int(row.get("assets_row_missing") or 0)
    totals["balanced"] = (
        totals["drift_points"] == 0
        and totals["drift_rain"] == 0
        and totals["points_mismatch_users"] == 0
        and totals["rain_mismatch_users"] == 0
        and totals["assets_row_missing"] == 0
    )
    return totals


def format_parity(report: dict) -> dict:
    """把对账结果转成接口/报告可读的字符串形式。"""
    formatted = {}
    for key, value in report.items():
        formatted[key] = format_amount(value) if isinstance(value, Decimal) else value
    return formatted


def drift_users(cur, limit: int = PARITY_SCAN_LIMIT) -> list[dict]:
    """列出对不齐的会员（按 user_id 升序），用于运维定位。"""
    cur.execute(
        """SELECT u.id AS user_id,
                  COALESCE(u.member_points, 0) AS legacy_points,
                  COALESCE(a.points, 0) AS v1_points,
                  COALESCE(u.true_total_points, 0) AS legacy_rain,
                  COALESCE(a.rain_balance, 0) AS v1_rain
           FROM users u LEFT JOIN user_assets a ON a.user_id = u.id
           WHERE a.user_id IS NULL
              OR COALESCE(a.points, 0) <> COALESCE(u.member_points, 0)
              OR COALESCE(a.rain_balance, 0) <> COALESCE(u.true_total_points, 0)
           ORDER BY u.id LIMIT %s""",
        (int(limit),),
    )
    return list(cur.fetchall() or [])


def installed_triggers(cur) -> set[str]:
    cur.execute(
        """SELECT TRIGGER_NAME AS name FROM INFORMATION_SCHEMA.TRIGGERS
           WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = 'users'"""
    )
    return {row["name"] for row in (cur.fetchall() or [])}


def assert_bridge_installed(cur) -> None:
    """确认镜像触发器已安装。

    触发器缺失时镜像不会发生，此时若不拦住，V1.1 结算的积分/雨点会静默丢失，
    因此对账与结算前置检查一律显式失败。
    """
    missing = [name for name in REQUIRED_TRIGGERS if name not in installed_triggers(cur)]
    if missing:
        raise RightsError(
            ERR_STATE_CONFLICT,
            503,
            "旧账本桥接触发器未安装，请先执行 migrations/008_legacy_assets_bridge.sql："
            + ", ".join(missing),
        )


def assets_snapshot(cur, user_id: int) -> Optional[dict]:
    """返回 (旧账本, 镜像) 两套值，便于测试与对账断言。"""
    cur.execute(
        "SELECT member_points, true_total_points FROM users WHERE id = %s",
        (user_id,),
    )
    legacy = cur.fetchone()
    if not legacy:
        return None
    mirror = read_assets(cur, user_id)
    return {
        "legacy_points": to_decimal(legacy["member_points"] or 0),
        "legacy_rain": to_decimal(legacy["true_total_points"] or 0),
        "mirror_points": to_decimal(mirror["points"] or 0),
        "mirror_rain": to_decimal(mirror["rain_balance"] or 0),
    }


__all__ = [
    "AMOUNT_QUANT",
    "LEGACY_POINTS_COLUMN",
    "LEGACY_RAIN_COLUMN",
    "LegacyBridgeError",
    "REQUIRED_TRIGGERS",
    "add_points",
    "add_rain",
    "assert_bridge_installed",
    "assets_snapshot",
    "drift_users",
    "format_parity",
    "installed_triggers",
    "lock_legacy_user",
    "parity_report",
    "read_assets",
]
