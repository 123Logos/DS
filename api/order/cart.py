from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, PositiveInt
from core.database import get_conn
from typing import List, Dict, Any, Optional
import json

router = APIRouter()

class CartManager:
    @staticmethod
    def add(
        user_id: int,
        product_id: int,
        quantity: int = 1,
        specifications: Optional[Dict[str, Any]] = None
    ) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 用户是否存在
                cur.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail=f"users 表中不存在 id={user_id}")

                # 2. 商品是否存在
                cur.execute("SELECT 1 FROM products WHERE id = %s", (product_id,))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail=f"products 表中不存在 id={product_id}")

                # 3. 取一个 sku_id
                cur.execute(
                    "SELECT id FROM product_skus WHERE product_id = %s LIMIT 1",
                    (product_id,)
                )
                sku_row = cur.fetchone()
                if not sku_row:
                    raise HTTPException(status_code=404, detail=f"product_skus 里找不到 product_id={product_id} 的记录")
                sku_id = sku_row["id"]

                # 4. 规格转 JSON 字符串
                spec_str = json.dumps(specifications, ensure_ascii=False) if specifications else None

                # 5. 插入或更新（含规格）
                cur.execute(
                    "SELECT quantity FROM cart WHERE user_id = %s AND product_id = %s",
                    (user_id, product_id),
                )
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "UPDATE cart SET quantity = quantity + %s, specifications = %s "
                        "WHERE user_id = %s AND product_id = %s",
                        (quantity, spec_str, user_id, product_id),
                    )
                else:
                    cur.execute(
                        "INSERT INTO cart(user_id, product_id, sku_id, quantity, specifications) "
                        "VALUES (%s, %s, %s, %s, %s)",
                        (user_id, product_id, sku_id, quantity, spec_str),
                    )
                conn.commit()
                return True

    @staticmethod
    def list_items(user_id: int) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                sql = """
                    SELECT c.*,
                        p.name                     AS product_name,
                        s.price                    AS unit_price,
                        (c.quantity * s.price)     AS total_price
                    FROM cart c
                    JOIN products p  ON p.id  = c.product_id
                    JOIN product_skus s ON s.id = c.sku_id   -- 关键：用 sku_id 精准匹配
                    WHERE c.user_id = %s
                    ORDER BY c.added_at DESC
                """
                cur.execute(sql, (user_id,))
                rows = cur.fetchall()
                for r in rows:
                    r["unit_price"] = float(r["unit_price"])
                    r["total_price"] = float(r["total_price"])
                    # 仅反序列化库里的 JSON
                    r["specifications"] = json.loads(r["specifications"]) if r["specifications"] else None
                return rows

    @staticmethod
    def remove(user_id: int, product_id: int) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM cart WHERE user_id = %s AND product_id = %s",
                    (user_id, product_id),
                )
                conn.commit()
                return True


# ----------- 请求模型 -----------
class CartAdd(BaseModel):
    user_id: int
    product_id: int
    quantity: PositiveInt = 1
    specifications: Optional[Dict[str, Any]] = None


# ----------- 路由 -----------
@router.post("/add", summary="添加商品到购物车")
def cart_add(body: CartAdd):
    return {"ok": CartManager.add(body.user_id,
                                  body.product_id,
                                  body.quantity,
                                  body.specifications)}


@router.get("/{user_id}", summary="获取购物车列表")
def get_cart(user_id: int):
    # 去掉 spec_map_str 参数，只读库
    return CartManager.list_items(user_id)


@router.delete("/{user_id}/{product_id}", summary="从购物车移除商品")
def cart_remove(user_id: int, product_id: int):
    return {"ok": CartManager.remove(user_id, product_id)}