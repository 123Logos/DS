from core.database import get_conn


def add_points(user_id: int, points_type: str, amount: int, reason: str = "系统赠送"):
    """积分变动：写流水 + 更新余额"""
    if points_type not in ["member", "merchant"]:
        raise ValueError("无效的积分类型")
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 更新余额
            if points_type == "member":
                cur.execute("UPDATE users SET member_points=member_points+%s WHERE id=%s", (amount, user_id))
            else:
                cur.execute("UPDATE users SET merchant_points=merchant_points+%s WHERE id=%s", (amount, user_id))
            # 2. 写流水
            cur.execute(
                "INSERT INTO points_log(user_id, points_type, change_amount, reason) VALUES (%s,%s,%s,%s)",
                (user_id, points_type, amount, reason)
            )
