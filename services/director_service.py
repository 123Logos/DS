import datetime

from core.database import get_conn
from core.table_access import build_dynamic_select
from decimal import Decimal
from typing import List, Dict

class DirectorService:
    """荣誉董事 晋升/分红/查询 原子接口"""

    # ------------- 0. 刷新用户六星计数（后台每天或每周跑） -------------
    @staticmethod
    def _refresh_six_counter():
        """刷六星直推 & 团队人数，刷完即可直接判定晋升"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 直推六星：用派生表+IFNULL 绕过 MySQL 1093 和 NULL 问题
                cur.execute("""
                    UPDATE users u
                    SET six_director = IFNULL((
                        SELECT cnt
                        FROM (
                            SELECT referrer_id, COUNT(*) AS cnt
                            FROM user_referrals r
                            JOIN users x ON x.id = r.user_id
                            WHERE x.member_level = 6
                            GROUP BY referrer_id
                        ) AS t
                        WHERE t.referrer_id = u.id
                    ), 0)
                """)
                # 团队六星（含自己）：同样派生表+IFNULL
                cur.execute("""
                    UPDATE users u
                    SET six_team = IFNULL((
                        SELECT cnt
                        FROM (
                            SELECT u2.id, COUNT(*) AS cnt
                            FROM users u2
                            WHERE u2.id IN (
                                SELECT user_id
                                FROM user_referrals
                                WHERE referrer_id = u.id
                                UNION ALL
                                SELECT u.id
                            ) AND u2.member_level = 6
                            GROUP BY u2.id
                        ) AS t
                        WHERE t.id = u.id
                    ), 0)
                """)
            conn.commit()

    # ------------- 1. 晋升判定 -------------
    @staticmethod
    def try_promote(user_id: int) -> bool:
        """单次晋升尝试，返回是否成功"""
        DirectorService._refresh_six_counter()
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT member_level, six_director, six_team
                    FROM users WHERE id=%s
                """, (user_id,))
                row = cur.fetchone()
                if not row or row['member_level'] != 6:
                    return False
                if row['six_director'] < 3 or row['six_team'] < 10:
                    return False
                # 符合晋升
                cur.execute("""
                    INSERT INTO directors(user_id, status, activated_at)
                    VALUES (%s,'active',NOW())
                    ON DUPLICATE KEY UPDATE status='active', activated_at=NOW()
                """, (user_id,))
                conn.commit()
                return True

    # ------------- 2. 每周分红计算 -------------
    @staticmethod
    def calc_week_dividend(period: datetime.date) -> Decimal:
        """
        计算并发放本周荣誉董事分红
        返回总发放金额
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 本周新业绩 = 会员+普通商品销售额
                cur.execute("""
                    SELECT SUM(total_amount) AS s
                    FROM orders
                    WHERE DATE(created_at) BETWEEN %s AND DATE_ADD(%s, INTERVAL 6 DAY)
                      AND status IN ('paid','completed')
                """, (period, period))
                new_sales = cur.fetchone()['s'] or 0
                pool = new_sales * 0.02   # 2% 加权池

                # 2. 所有活跃荣誉董事
                cur.execute("""
                    SELECT user_id
                    FROM directors
                    WHERE status='active'
                """)
                directors = cur.fetchall()
                if not directors:
                    return 0

                # 3. 计算权重（简化：按团队六星人数线性加权）
                total_weight = 0
                rows = []
                for d in directors:
                    uid = d['user_id']
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id=%s",
                        select_fields=["six_team"]
                    )
                    cur.execute(select_sql, (uid,))
                    six_team = cur.fetchone()['six_team']
                    weight = max(1, six_team)   # 至少为 1
                    rows.append((uid, weight))
                    total_weight += weight

                # 4. 发放
                paid = 0
                for uid, w in rows:
                    amt = round(pool * w / total_weight, 2)
                    if amt <= 0:
                        continue
                    # 写分红明细
                    cur.execute("""
                        INSERT INTO director_dividends
                        (user_id, period_date, dividend_amount, new_sales, weight)
                        VALUES (%s,%s,%s,%s,%s)
                    """, (uid, period, amt, new_sales, w))
                    # 累加到可提现余额
                    cur.execute("""
                        UPDATE users
                        SET withdrawable_balance=withdrawable_balance+%s
                        WHERE id=%s
                    """, (amt, uid))
                    # 累加 directors 总分红
                    cur.execute("""
                        UPDATE directors
                        SET dividend_amount=dividend_amount+%s
                        WHERE user_id=%s
                    """, (amt, uid))
                    paid += amt
                conn.commit()
                return paid

    # ------------- 3. 查询接口 -------------
    @staticmethod
    def is_director(user_id: int) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM directors
                    WHERE user_id=%s AND status='active'
                """, (user_id,))
                return cur.fetchone() is not None

    @staticmethod
    def get_dividend_detail(user_id: int, page=1, size=10) -> List[Dict]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT period_date, dividend_amount, new_sales, weight, created_at
                    FROM director_dividends
                    WHERE user_id=%s
                    ORDER BY period_date DESC
                    LIMIT %s OFFSET %s
                """, (user_id, size, (page-1)*size))
                return cur.fetchall()

    @staticmethod
    def list_all_directors(page=1, size=10):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT d.user_id, u.name, u.mobile,
                           d.dividend_amount, d.created_at
                    FROM directors d
                    JOIN users u ON u.id=d.user_id
                    WHERE d.status='active'
                    ORDER BY d.id DESC
                    LIMIT %s OFFSET %s
                """, (size, (page-1)*size))
                return cur.fetchall()
