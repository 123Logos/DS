from decimal import Decimal
from core.database import get_conn


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
            # 1. 更新余额并获取更新后的余额
            if type == "member":
                cur.execute("UPDATE users SET member_points=member_points+%s WHERE id=%s", (amount, user_id))
                cur.execute("SELECT member_points FROM users WHERE id=%s", (user_id,))
            else:
                cur.execute("UPDATE users SET merchant_points=merchant_points+%s WHERE id=%s", (amount, user_id))
                cur.execute("SELECT merchant_points FROM users WHERE id=%s", (user_id,))
            balance_after = Decimal(str(cur.fetchone()[0]))
            # 2. 写流水
            cur.execute(
                "INSERT INTO points_log(user_id, type, change_amount, balance_after, reason) VALUES (%s,%s,%s,%s,%s)",
                (user_id, type, amount, balance_after, reason)
            )
