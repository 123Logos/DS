#!/usr/bin/env python3
"""旧账本资产迁移：users → user_assets（漏洞 1 & 2 的数据侧修复）。

做两件事
--------
1. `users.member_points`      → `user_assets.points`
2. `users.true_total_points`  → `user_assets.rain_balance`

幂等
----
* 按 user_id 游标分页（`WHERE u.id > ? ORDER BY u.id LIMIT ?`），不整表加载、不锁全表；
* 先 `INSERT IGNORE`，已存在则仅在该会员两列**实际不等**时才 UPDATE，
  因此重复执行第二次起写入行数为 0，可安全重跑（上线校验、回滚重放都靠这一点）；
* 每批独立提交，中断后从任意批次继续不会重复计数（写的是绝对值，不是增量）。

对账
----
运行前后各出一份全库对账：
    旧账本 SUM(users.member_points)  ==  V1.1 SUM(user_assets.points)
    旧账本 SUM(users.true_total_points) == V1.1 SUM(user_assets.rain_balance)
迁移完成后必须**完全相等**且逐会员零差异，否则进程以退出码 1 结束。

负值
----
旧账本出现负数说明上游存在越界扣减 Bug（`migrations/008` 的镜像触发器已对
`users` 的写入直接 `SIGNAL` 拒绝）。本脚本**不夹 0、不做任何圆场**：负值会员
只登记到 `negative_users`、不写镜像，最终退出码 1，要求业务方先修数据再重跑。
把负值悄悄变成 0 会让账面凭空多出资产，且永远查不出来。

注意：本脚本直接写 `user_assets.points / rain_balance`，这是**唯一**允许绕过
`services/legacy_assets_bridge.py` 的场合——它本身就是建立初始镜像的作业。
日常业务代码必须走 bridge 写 users 侧，由触发器镜像。

用法
----
    uv run python scripts/migrate_legacy_assets.py                # 正式执行
    uv run python scripts/migrate_legacy_assets.py --dry-run      # 只出报告，不写库
    uv run python scripts/migrate_legacy_assets.py --report out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Iterable, Iterator, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.database import get_conn  # noqa: E402
from core.logging import get_logger  # noqa: E402
from services import legacy_assets_bridge as bridge  # noqa: E402
from services.rights_service import format_amount, to_decimal  # noqa: E402

logger = get_logger(__name__)

DEFAULT_BATCH_SIZE = 500


def iter_legacy_users(cur, batch_size: int, limit: Optional[int] = None) -> Iterator[list[dict]]:
    """游标分页读取旧账本（keyset pagination，避免 OFFSET 越翻越慢）。"""
    last_id = 0
    fetched = 0
    while True:
        size = batch_size
        if limit is not None:
            remaining = limit - fetched
            if remaining <= 0:
                return
            size = min(size, remaining)
        cur.execute(
            """SELECT id, member_points, true_total_points
               FROM users WHERE id > %s ORDER BY id LIMIT %s""",
            (last_id, size),
        )
        rows = list(cur.fetchall() or [])
        if not rows:
            return
        last_id = int(rows[-1]["id"])
        fetched += len(rows)
        yield rows
        if len(rows) < size:
            return


def _is_negative(value: Decimal) -> bool:
    """旧账本出现负值 = 上游越界扣减的 Bug，迁移不得替它圆场。"""
    return value < 0


def migrate_batch(
    cur,
    rows: Iterable[dict],
    dry_run: bool,
    offenders: Optional[list[dict]] = None,
) -> dict:
    """迁移一批会员，返回本批统计。

    负值会员只登记、**不写库**（镜像侧 `CHECK (points >= 0)` 也不可能接受负值）。
    这类会员必须由业务方先查清越界扣减来源并修正旧账本，再重跑本脚本；
    脚本最终以退出码 1 结束，不会给出「已对齐」的假象。
    """
    stats = {
        "scanned": 0,
        "inserted": 0,
        "updated": 0,
        "unchanged": 0,
        "negative": 0,
    }
    for row in rows:
        user_id = int(row["id"])
        points = to_decimal(row["member_points"] or 0)
        rain = to_decimal(row["true_total_points"] or 0)
        stats["scanned"] += 1

        if _is_negative(points) or _is_negative(rain):
            stats["negative"] += 1
            logger.error(
                "legacy_negative_balance user=%s points=%s rain=%s（拒绝迁移，请先修正旧账本）",
                user_id, points, rain,
            )
            if offenders is not None:
                offenders.append({
                    "user_id": user_id,
                    "member_points": format_amount(points),
                    "true_total_points": format_amount(rain),
                })
            continue

        if dry_run:
            # 只统计"需要动"的会员数，不写库
            cur.execute(
                """SELECT 1 FROM user_assets
                   WHERE user_id = %s AND points = %s AND rain_balance = %s""",
                (user_id, points, rain),
            )
            if cur.fetchone():
                stats["unchanged"] += 1
            else:
                stats["updated"] += 1
            continue

        cur.execute(
            """INSERT IGNORE INTO user_assets (user_id, points, rain_balance)
               VALUES (%s, %s, %s)""",
            (user_id, points, rain),
        )
        if cur.rowcount == 1:
            stats["inserted"] += 1
            continue
        # 行已存在：只有真正不一致才写，保证重跑 0 行
        cur.execute(
            """UPDATE user_assets
               SET points = %s, rain_balance = %s, updated_at = NOW()
               WHERE user_id = %s AND (points <> %s OR rain_balance <> %s)""",
            (points, rain, user_id, points, rain),
        )
        if cur.rowcount == 1:
            stats["updated"] += 1
        else:
            stats["unchanged"] += 1
    return stats


def reconcile(dry_run: bool) -> dict:
    """对账：旧账本合计 vs V1.1 镜像合计，必须完全相等。"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            report = bridge.parity_report(cur)
    return report


def _print_report(title: str, report: dict) -> None:
    print(f"\n=== {title} ===")
    print(f"  会员数                      : {report['users']}")
    print(f"  旧账本积分合计 (users)      : {format_amount(report['legacy_points'])}")
    print(f"  V1.1 镜像积分合计           : {format_amount(report['v1_points'])}")
    print(f"  积分差额                    : {format_amount(report['drift_points'])}")
    print(f"  旧账本雨点合计 (users)      : {format_amount(report['legacy_rain'])}")
    print(f"  V1.1 镜像雨点合计           : {format_amount(report['v1_rain'])}")
    print(f"  雨点差额                    : {format_amount(report['drift_rain'])}")
    print(f"  积分不一致会员数            : {report['points_mismatch_users']}")
    print(f"  雨点不一致会员数            : {report['rain_mismatch_users']}")
    print(f"  缺失镜像行的会员数          : {report['assets_row_missing']}")
    print(f"  是否完全对齐                : {'是' if report['balanced'] else '否'}")


def run(batch_size: int = DEFAULT_BATCH_SIZE, limit: Optional[int] = None, dry_run: bool = False) -> dict:
    """执行迁移，返回结构化结果（含前后对账）。"""
    before = reconcile(dry_run)
    _print_report("迁移前对账", before)

    totals = {"scanned": 0, "inserted": 0, "updated": 0, "unchanged": 0, "negative": 0}
    offenders: list[dict] = []
    started_at = datetime.now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            for rows in iter_legacy_users(cur, batch_size, limit):
                stats = migrate_batch(cur, rows, dry_run, offenders)
                for key in totals:
                    totals[key] += stats[key]
                if not dry_run:
                    conn.commit()
                logger.info(
                    "legacy_assets_batch scanned=%s inserted=%s updated=%s unchanged=%s negative=%s",
                    stats["scanned"], stats["inserted"], stats["updated"], stats["unchanged"], stats["negative"],
                )
    if dry_run:
        logger.info("dry-run 模式：以上统计为「若不写库会有多少会员受影响」")

    after = reconcile(dry_run)
    _print_report("迁移后对账", after)

    result = {
        "mode": "dry-run" if dry_run else "apply",
        "started_at": started_at.isoformat(timespec="seconds"),
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "batch_size": batch_size,
        "limit": limit,
        "written": totals,
        "before": bridge.format_parity(before),
        "after": bridge.format_parity(after),
        "balanced": bool(after["balanced"]),
        # 负值会员被拒绝迁移，即使合计差额恰好抵消也不算成功
        "negative_users": offenders,
        "ok": bool(after["balanced"]) and not offenders,
    }

    if not dry_run and after["drift_points"] != 0:
        logger.error("legacy_assets_reconcile_failed drift_points=%s", after["drift_points"])
    if not dry_run and after["drift_rain"] != 0:
        logger.error("legacy_assets_reconcile_failed drift_rain=%s", after["drift_rain"])
    if offenders:
        logger.error(
            "legacy_assets_negative_users count=%s sample=%s",
            len(offenders), offenders[:10],
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="旧账本资产迁移与对账（幂等）")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="每批会员数，默认 500")
    parser.add_argument("--limit", type=int, default=None, help="仅迁移前 N 个会员（灰度/演练）")
    parser.add_argument("--dry-run", action="store_true", help="只出对账报告，不写库")
    parser.add_argument("--report", type=Path, default=None, help="把结构化报告写入 JSON 文件")
    parser.add_argument("--check-triggers", action="store_true", help="同时校验镜像触发器已安装")
    args = parser.parse_args()

    if args.check_triggers:
        with get_conn() as conn:
            with conn.cursor() as cur:
                bridge.assert_bridge_installed(cur)
        print("镜像触发器已安装 ✓")

    result = run(batch_size=args.batch_size, limit=args.limit, dry_run=args.dry_run)

    if args.report:
        args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n报告已写入: {args.report}")

    # 迁移模式要求严格相等且无负值会员；dry-run 本来就是"迁移前"状态，以是否可对齐为主
    if not args.dry_run and not result["ok"]:
        if result["negative_users"]:
            print(f"\n发现 {len(result['negative_users'])} 个负值会员，已拒绝迁移（旧账本越界扣减 Bug）：")
            for item in result["negative_users"][:20]:
                print(
                    f"  user={item['user_id']} member_points={item['member_points']} "
                    f"true_total_points={item['true_total_points']}"
                )
            print("请先修正旧账本，再重跑本脚本；不要通过改脚本/改约束绕过。")
        if not result["balanced"]:
            print("\n对账未通过：新旧账本仍存在差额，请勿继续上线。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
