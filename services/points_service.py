from decimal import Decimal

from core.database import get_conn
from core.table_access import build_dynamic_select, get_table_structure, _quote_identifier
from core.logging import get_logger

logger = get_logger(__name__)


def add_points(
    user_id: int,
    type: str,
    amount: Decimal,
    reason: str = "系统赠送",
    operator_id: int | None = None,
    event_id: str | None = None,
    source: str = "automatic",
):
    """积分变动：写流水 + 更新余额（运行时仅 DML；列由 migrations 保证）。"""
    if type not in ["member", "merchant"]:
        raise ValueError("无效的积分类型")
    points_field = "member_points" if type == "member" else "merchant_points"
    with get_conn() as conn:
        with conn.cursor() as cur:
            structure = get_table_structure(cur, "users", use_cache=True)
            if points_field not in structure["fields"]:
                raise RuntimeError(
                    f"users.{points_field} 不存在，请先执行: python scripts/migrate.py"
                )
            cur.execute(
                f"UPDATE {_quote_identifier('users')} SET {_quote_identifier(points_field)}="
                f"COALESCE({_quote_identifier(points_field)}, 0)+%s WHERE id=%s",
                (amount, user_id),
            )
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="id=%s",
                select_fields=[points_field],
            )
            cur.execute(select_sql, (user_id,))
            row = cur.fetchone()
            balance_after = Decimal(str(row.get(points_field, 0) or 0))
            balance_before = balance_after - Decimal(str(amount))
            cur.execute(
                "INSERT INTO points_log(user_id, type, change_amount, balance_after, "
                "balance_before, reason, operator_id, event_id, source) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (user_id, type, amount, balance_after, balance_before, reason,
                 operator_id, event_id, source),
            )
            if operator_id is not None:
                from services.auth_security_service import audit
                audit(cur, operator_id, user_id, "points_adjustment",
                      {"type": type, "balance": balance_before},
                      {"type": type, "balance": balance_after, "event_id": event_id}, reason)
            conn.commit()
