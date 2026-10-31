#!/usr/bin/env python3
"""
数据库迁移入口（替代 on_startup 竞态 DDL）。

用法:
  python scripts/migrate.py              # 执行 migrations/*.sql + 条件 ALTER
  python scripts/migrate.py --dry-run    # 仅打印将执行的操作

生产部署顺序见 docs/RELEASE_OPS_TASK2.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.database import get_conn  # noqa: E402
from core.logging import get_logger  # noqa: E402
from core.sql_split import split_sql_statements  # noqa: E402

logger = get_logger(__name__)

POINTS_COLUMNS = {
    "member_points": "DECIMAL(12,6) NOT NULL DEFAULT 0.000000 COMMENT '会员积分'",
    "merchant_points": "DECIMAL(12,6) NOT NULL DEFAULT 0.000000 COMMENT '商家积分'",
}


def _column_exists(cur, table: str, column: str) -> bool:
    cur.execute(
        """
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s
        LIMIT 1
        """,
        (table, column),
    )
    return cur.fetchone() is not None


def run_sql_file(path: Path, dry_run: bool) -> None:
    sql = path.read_text(encoding="utf-8")
    # 用词法切分而非 split(";")：008 的触发器体是 BEGIN...END 复合语句，
    # 内部含分号，必须先识别 DELIMITER 指令与引号/注释边界。
    statements = split_sql_statements(sql)
    logger.info("迁移文件: %s (%s 条语句)", path.name, len(statements))
    if dry_run:
        for s in statements:
            print(f"-- would run:\n{s[:200]}...\n")
        return
    with get_conn() as conn:
        with conn.cursor() as cur:
            for stmt in statements:
                # Historical migration003 used MariaDB syntax; keep its checksum stable.
                if path.name == '003_rain_point_monthly_coupon.sql' and 'ADD COLUMN IF NOT EXISTS rain_settlement_id' in stmt:
                    if _column_exists(cur, 'coupons', 'rain_settlement_id'):
                        continue
                    stmt = stmt.replace('ADD COLUMN IF NOT EXISTS rain_settlement_id', 'ADD COLUMN rain_settlement_id')
                cur.execute(stmt)
            conn.commit()


def ensure_users_points_columns(dry_run: bool) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            for col, ddl in POINTS_COLUMNS.items():
                if _column_exists(cur, "users", col):
                    logger.info("users.%s 已存在，跳过", col)
                    continue
                stmt = f"ALTER TABLE users ADD COLUMN {col} {ddl}"
                logger.info("将执行: %s", stmt)
                if dry_run:
                    continue
                cur.execute(stmt)
            if not dry_run:
                conn.commit()


def run_migrations(dry_run: bool = False) -> None:
    migrations_dir = ROOT / "migrations"
    with get_conn() as conn:
        with conn.cursor() as cur:
            if not dry_run:
                cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY, sha256 CHAR(64) NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB")
                conn.commit()
            for path in sorted(migrations_dir.glob("*.sql")):
                import hashlib
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if not dry_run:
                    cur.execute("SELECT sha256 FROM schema_migrations WHERE version=%s", (path.name,))
                    applied = cur.fetchone()
                    if applied:
                        if applied['sha256'] != digest:
                            raise RuntimeError("Applied migration checksum changed: " + path.name)
                        continue
                run_sql_file(path, dry_run)
                if not dry_run:
                    cur.execute("INSERT INTO schema_migrations(version,sha256) VALUES(%s,%s)", (path.name, digest))
                    conn.commit()
    ensure_users_points_columns(dry_run)
    logger.info("迁移完成")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    run_migrations(dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
