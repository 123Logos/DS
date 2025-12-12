from decimal import Decimal
from core.database import get_conn
from core.table_access import build_dynamic_select, get_table_structure, clear_table_cache
from core.logging import get_logger

logger = get_logger(__name__)


def add_points(user_id: int, type: str, amount: Decimal, reason: str = "系统赠送"):
    """积分变动：写流水 + 更新余额

    Args:
        user_id: 用户ID
        type: 积分类型，'member' 或 'merchant'
        amount: 积分数量，支持小数点后4位精度
        reason: 变动原因
    """
    if type not in ["member", "merchant"]:
        raise ValueError("无效的积分类型")
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 使用动态表访问获取表结构
            structure = get_table_structure(cur, "users", use_cache=False)
            columns = structure['fields']
            
            points_field = "member_points" if type == "member" else "merchant_points"
            
            # 如果字段不存在，自动创建
            if points_field not in columns:
                try:
                    cur.execute(
                        f"ALTER TABLE users ADD COLUMN {points_field} DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT '积分字段'"
                    )
                    conn.commit()
                    # 清除缓存，确保下次获取最新结构
                    from core.table_access import clear_table_cache
                    clear_table_cache("users")
                except Exception as e:
                    # 如果字段已存在（并发创建），忽略错误
                    logger.warning(f"字段 {points_field} 可能已存在: {e}")
            
            # 1. 更新余额并获取更新后的余额
            # 使用 COALESCE 处理字段可能为 NULL 的情况
            # 如果字段不存在，使用 0 作为默认值
            try:
                cur.execute(
                    f"UPDATE users SET {points_field}=COALESCE({points_field}, 0)+%s WHERE id=%s",
                    (amount, user_id)
                )
            except Exception as e:
                # 如果字段仍然不存在，尝试再次创建
                if "Unknown column" in str(e):
                    cur.execute(
                        f"ALTER TABLE users ADD COLUMN {points_field} DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT '积分字段'"
                    )
                    conn.commit()
                    clear_table_cache("users")
                    # 重试更新
                    cur.execute(
                        f"UPDATE users SET {points_field}=COALESCE({points_field}, 0)+%s WHERE id=%s",
                        (amount, user_id)
                    )
                else:
                    raise
            
            # 使用动态 SELECT 获取更新后的余额
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="id=%s",
                select_fields=[points_field]
            )
            cur.execute(select_sql, (user_id,))
            row = cur.fetchone()
            balance_after = Decimal(str(row.get(points_field, 0) or 0))
            
            # 2. 写流水
            cur.execute(
                "INSERT INTO points_log(user_id, type, change_amount, balance_after, reason) VALUES (%s,%s,%s,%s,%s)",
                (user_id, type, amount, balance_after, reason)
            )
            conn.commit()
