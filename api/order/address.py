from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from core.database import get_conn
from typing import List, Dict, Any

router = APIRouter()

class AddressManager:
    @staticmethod
    def add(user_id: int, label: str, name: str, phone: str,
            province: str, city: str, district: str, detail: str,
            lng: Optional[float] = None, lat: Optional[float] = None, is_default: bool = False) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS c FROM user_addresses WHERE user_id=%s", (user_id,))
                if cur.fetchone()["c"] == 0:
                    is_default = True
                else:
                    if is_default:
                        cur.execute("UPDATE user_addresses SET is_default=0 WHERE user_id=%s", (user_id,))
                cur.execute("""INSERT INTO user_addresses
                               (user_id,label,consignee_name,consignee_phone,province,city,district,detail,lng,lat,is_default)
                               VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                            (user_id, label, name, phone, province, city, district, detail, lng, lat, is_default))
                conn.commit()
                return cur.lastrowid

    @staticmethod
    def list_by_user(user_id: int) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM user_addresses WHERE user_id=%s ORDER BY is_default DESC,id DESC", (user_id,))
                return cur.fetchall()

    @staticmethod
    def set_default(addr_id: int, user_id: int) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE user_addresses SET is_default=0 WHERE user_id=%s", (user_id,))
                cur.execute("UPDATE user_addresses SET is_default=1 WHERE id=%s AND user_id=%s", (addr_id, user_id))
                conn.commit()
                return cur.rowcount > 0

    @staticmethod
    def delete(addr_id: int, user_id: int) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_addresses WHERE id=%s AND user_id=%s", (addr_id, user_id))
                conn.commit()
                return cur.rowcount > 0

# ---------------- 路由 ----------------
class AddressAdd(BaseModel):
    label: str
    consignee_name: str
    consignee_phone: str
    province: str
    city: str
    district: str
    detail: str
    lng: Optional[float] = None
    lat: Optional[float] = None
    is_default: bool = False

@router.post("/add", summary="新增收货地址")
def add_address(body: AddressAdd, user_id: int):
    addr_id = AddressManager.add(user_id, body.label, body.consignee_name,
                                 body.consignee_phone, body.province, body.city,
                                 body.district, body.detail, body.lng, body.lat,
                                 body.is_default)
    return {"id": addr_id}

@router.get("/{user_id}", summary="查询用户地址列表")
def list_addresses(user_id: int):
    return AddressManager.list_by_user(user_id)

@router.post("/set_default", summary="设置默认地址")
def set_default(addr_id: int, user_id: int):
    return {"ok": AddressManager.set_default(addr_id, user_id)}

@router.delete("/{addr_id}", summary="删除收货地址")
def delete_addr(addr_id: int, user_id: int):
    return {"ok": AddressManager.delete(addr_id, user_id)}
