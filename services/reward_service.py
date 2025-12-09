from typing import Optional
from core.database import get_conn



class TeamRewardService:
    @staticmethod
    def add_reward(user_id: int, from_user_id: int, layer: int, amount: float, order_id: Optional[int] = None):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO team_rewards(user_id, from_user_id, order_id, layer, reward_amount)
                    VALUES (%s,%s,%s,%s,%s)
                """, (user_id, from_user_id, order_id, layer, amount))

    @staticmethod
    def get_reward_list_by_user(user_id: int, page: int = 1, size: int = 10):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT tr.id, tr.from_user_id, tr.order_id, tr.layer, tr.reward_amount, tr.created_at,
                           u.mobile AS from_mobile, u.name AS from_name
                    FROM team_rewards tr
                    JOIN users u ON u.id = tr.from_user_id
                    WHERE tr.user_id=%s
                    ORDER BY tr.created_at DESC
                    LIMIT %s OFFSET %s
                """, (user_id, size, (page - 1) * size))
                return cur.fetchall()

    @staticmethod
    def get_reward_by_order(order_id: int):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT tr.id, tr.user_id, tr.from_user_id, tr.layer, tr.reward_amount, tr.created_at,
                           u.mobile AS user_mobile, u.name AS user_name,
                           fu.mobile AS from_mobile, fu.name AS from_name
                    FROM team_rewards tr
                    JOIN users u ON u.id = tr.user_id
                    JOIN users fu ON fu.id = tr.from_user_id
                    WHERE tr.order_id=%s
                    ORDER BY tr.layer, tr.id
                """, (order_id,))
                return cur.fetchall()
