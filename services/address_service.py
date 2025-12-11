from typing import Optional
from core.database import get_conn


class AddressService:
    # ------------- 新增地址 -------------
    @staticmethod
    def add_address(
            user_id: int,
            consignee_name: str,
            consignee_phone: str,
            province: str,
            city: str,
            district: str,
            detail: str,
            label: str,
            is_default: bool = False,
            addr_type: str = "shipping",
            lng: Optional[float] = None,
            lat: Optional[float] = None,
    ) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                if is_default:
                    cur.execute("UPDATE user_addresses SET is_default=0 WHERE user_id=%s", (user_id,))
                cur.execute(
                    """
                    INSERT INTO user_addresses
                    (user_id, label, consignee_name, consignee_phone,
                     province, city, district, detail,
                     lng, lat, is_default, addr_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        label,
                        consignee_name,
                        consignee_phone,
                        province,
                        city,
                        district,
                        detail,
                        lng or None,
                        lat or None,
                        int(is_default),
                        addr_type,
                    ))
                return cur.lastrowid

    # ------------- 删除地址 -------------
    @staticmethod
    def delete_address(user_id: int, addr_id: int) -> None:
        with get_conn() as conn:
            with conn.cursor() as cur:
               cur.execute("DELETE FROM user_addresses WHERE id=%s AND user_id=%s", (addr_id, user_id))
               if cur.rowcount == 0:
                   raise ValueError("地址不存在或无权删除")

    # ------------- 更新地址 -------------
    @staticmethod
    def update_address(user_id: int, addr_id: int, **kwargs) -> None:
        if not kwargs:
            raise ValueError("无更新内容")
        set_clause = ", ".join([f"{k}=%s" for k in kwargs])
        values = list(kwargs.values()) + [addr_id, user_id]
        with get_conn() as conn:
            with conn.cursor() as cur:
                if kwargs.get("is_default"):
                    cur.execute("UPDATE user_addresses SET is_default=0 WHERE user_id=%s", (user_id,))
                cur.execute(f"UPDATE user_addresses SET {set_clause} WHERE id=%s AND user_id=%s", values)
                if cur.rowcount == 0:
                    raise ValueError("地址不存在或无权修改")

    # ------------- 分页查询地址 -------------
    @staticmethod
    def get_address_list(user_id: int, page: int = 1, size: int = 10) -> list:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                        SELECT id, consignee_name, consignee_phone, province, city, district, detail, label, is_default, created_at
                        FROM user_addresses
                        WHERE user_id=%s
                        ORDER BY is_default DESC, id DESC
                        LIMIT %s OFFSET %s
                    """, (user_id, size, (page - 1) * size))
                return cur.fetchall()

    # ------------- 获取默认地址 -------------
    @staticmethod
    def get_default_address(user_id: int) -> Optional[dict]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, consignee_name, consignee_phone, province, city, district, detail, label, created_at
                    FROM user_addresses
                    WHERE user_id=%s AND is_default=1
                    LIMIT 1
                """, (user_id,))
                return cur.fetchone()
