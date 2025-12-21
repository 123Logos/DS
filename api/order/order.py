from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from core.database import get_conn
from services.finance_service import split_order_funds
from core.config import VALID_PAY_WAYS
from core.table_access import build_dynamic_select, get_table_structure, _quote_identifier
from decimal import Decimal
import uuid
from datetime import datetime, timedelta
from enum import Enum
import json

router = APIRouter()

class OrderManager:
    @staticmethod
    def _build_orders_select(cursor) -> str:
        structure = get_table_structure(cursor, "orders")
        select_parts = []
        for field in structure['fields']:
            if field in structure['asset_fields']:
                select_parts.append(f"COALESCE({_quote_identifier(field)}, 0) AS {_quote_identifier(field)}")
            else:
                select_parts.append(_quote_identifier(field))
        return ", ".join(select_parts)

    @staticmethod
    def create(
        user_id: int,
        address_id: Optional[int],
        custom_addr: Optional[dict],
        specifications: Optional[str] = None,      # 新增：规格 JSON 字符串
        buy_now: bool = False,
        buy_now_items: Optional[List[Dict[str, Any]]] = None,
        delivery_way: str = "platform"
    ) -> Optional[str]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # ---------- 1. 组装订单明细 ----------
                if buy_now:
                    if not buy_now_items:
                        raise HTTPException(status_code=422, detail="立即购买时 buy_now_items 不能为空")
                    items = []
                    for it in buy_now_items:
                        cur.execute("SELECT is_member_product FROM products WHERE id = %s", (it["product_id"],))
                        prod = cur.fetchone()
                        if not prod:
                            raise HTTPException(status_code=404, detail=f"products 表中不存在 id={it['product_id']}")
                        items.append({
                            "sku_id": it["sku_id"],
                            "product_id": it["product_id"],
                            "quantity": it["quantity"],
                            "price": Decimal(str(it["price"])),
                            "is_vip": prod["is_member_product"]
                        })
                    if custom_addr:
                        consignee_name = custom_addr.get("consignee_name")
                        consignee_phone = custom_addr.get("consignee_phone")
                        province = custom_addr.get("province", "")
                        city = custom_addr.get("city", "")
                        district = custom_addr.get("district", "")
                        shipping_address = custom_addr.get("detail", "")
                    else:
                        raise HTTPException(status_code=422, detail="立即购买必须上传 custom_address")
                else:
                    cur.execute("""
                        SELECT c.product_id,
                            c.sku_id,            
                            c.quantity,
                            s.price,
                            p.is_member_product AS is_vip,
                            c.specifications
                        FROM cart c
                        JOIN product_skus s ON s.id = c.sku_id
                        JOIN products p ON p.id = c.product_id
                        WHERE c.user_id = %s AND c.selected = 1
                    """, (user_id,))
                    items = cur.fetchall()
                    if not items:
                        return None
                    consignee_name = consignee_phone = province = city = district = shipping_address = None

                # ---------- 2. 订单主表 ----------
                total = sum(Decimal(str(i["quantity"])) * Decimal(str(i["price"])) for i in items)
                has_vip = any(i["is_vip"] for i in items)
                order_number = datetime.now().strftime("%Y%m%d%H%M%S") + str(user_id) + str(uuid.uuid4().int)[:6]

                # 规格 JSON 写进 refund_reason（下单时该字段一定空）
                cur.execute("""
                    INSERT INTO orders(
                        user_id, order_number, total_amount, status, is_vip_item,
                        consignee_name, consignee_phone,
                        province, city, district, shipping_address, delivery_way,
                        pay_way, auto_recv_time, refund_reason)
                    VALUES (%s, %s, %s, 'pending_pay', %s,
                            %s, %s, %s, %s, %s, %s, %s,
                            'wechat', %s, %s)
                """, (
                    user_id, order_number, total, has_vip,
                    consignee_name, consignee_phone,
                    province, city, district, shipping_address, delivery_way,
                    datetime.now() + timedelta(days=7),
                    specifications
                ))
                oid = cur.lastrowid

                # ---------- 3. 库存校验 & 扣减 ----------
                structure = get_table_structure(cur, "product_skus")
                has_stock_field = 'stock' in structure['fields']
                if has_stock_field:
                    stock_select = (
                        f"COALESCE({_quote_identifier('stock')}, 0) AS {_quote_identifier('stock')}"
                        if 'stock' in structure['asset_fields']
                        else _quote_identifier('stock')
                    )
                else:
                    stock_select = f"0 AS {_quote_identifier('stock')}"

                for i in items:
                    cur.execute(
                        f"SELECT {stock_select} FROM {_quote_identifier('product_skus')} WHERE product_id=%s",
                        (i['product_id'],)
                    )
                    result = cur.fetchone()
                    product_stock = result.get('stock', 0) if result else 0
                    if product_stock < i["quantity"]:
                        raise HTTPException(
                            status_code=400,
                            detail=f"商品库存不足：商品ID {i['product_id']} 当前库存 {product_stock}，需要 {i['quantity']}"
                        )

                # ---------- 4. 写订单明细 ----------
                for i in items:
                    cur.execute("""
                        INSERT INTO order_items(order_id, product_id, sku_id, quantity, unit_price, total_price)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        oid,
                        i["product_id"],
                        i["sku_id"],          # 新增
                        i["quantity"],
                        i["price"],
                        Decimal(str(i["quantity"])) * Decimal(str(i["price"]))
                    ))      
                # ---------- 5. 扣库存 ----------
                if has_stock_field:
                    for i in items:
                        cur.execute(
                            "UPDATE product_skus SET stock = stock - %s WHERE product_id = %s",
                            (i["quantity"], i["product_id"])
                        )

                # ---------- 6. 清空购物车（仅购物车结算场景） ----------
                if not buy_now:
                    cur.execute("DELETE FROM cart WHERE user_id = %s AND selected = 1", (user_id,))

                # ---------- 7. 资金拆分 ----------
                split_order_funds(order_number, total, has_vip, cursor=cur)

                conn.commit()
                return order_number

    @staticmethod
    def list_by_user(user_id: int, status: Optional[str] = None):
        """
        返回订单列表，每条订单带：
        - 订单主信息
        - 第一条商品明细（含规格）
        - 规格取自 orders.refund_reason（JSON 字符串）
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 主订单
                select_fields = OrderManager._build_orders_select(cur)
                sql = f"SELECT {select_fields} FROM orders WHERE user_id = %s"
                params = [user_id]
                if status:
                    sql += " AND status = %s"
                    params.append(status)
                sql += " ORDER BY created_at DESC"
                cur.execute(sql, tuple(params))
                orders = cur.fetchall()

                # 2. 补齐第一条商品 + 规格
                for o in orders:
                    cur.execute("""
                        SELECT oi.*, p.name
                        FROM order_items oi
                        JOIN products p ON oi.product_id = p.id
                        WHERE oi.order_id = %s
                        LIMIT 1
                    """, (o["id"],))
                    first_item = cur.fetchone()
                    o["first_product"] = first_item
                    # 规格 JSON 原样透出
                    o["specifications"] = o.get("refund_reason")

                return orders

    @staticmethod
    def detail(order_number: str) -> Optional[dict]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_fields = OrderManager._build_orders_select(cur)
                cur.execute(f"SELECT {select_fields} FROM orders WHERE order_number = %s", (order_number,))
                order_info = cur.fetchone()
                if not order_info:
                    return None

                cur.execute("""
                    SELECT oi.*, p.name
                    FROM order_items oi
                    JOIN products p ON oi.product_id = p.id
                    WHERE oi.order_id = %s
                """, (order_info["id"],))
                items = cur.fetchall()

                addr = {
                    "consignee_name": order_info.get("consignee_name"),
                    "consignee_phone": order_info.get("consignee_phone"),
                    "province": order_info.get("province"),
                    "city": order_info.get("city"),
                    "district": order_info.get("district"),
                    "detail": order_info.get("shipping_address")
                } if any(order_info.get(k) for k in (
                    "consignee_name", "consignee_phone", "province",
                    "city", "district", "shipping_address"
                )) else None

                return {
                    "order_info": order_info,
                    "address": addr,
                    "items": items,
                    "specifications": order_info.get("refund_reason")  # 原样透出
                }

    @staticmethod
    def update_status(order_number: str, new_status: str, reason: Optional[str] = None) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE orders SET status = %s, refund_reason = %s WHERE order_number = %s",
                    (new_status, reason, order_number)
                )
                conn.commit()
                return cur.rowcount > 0

# ---------------- 请求模型 ----------------
class DeliveryWay(str, Enum):
    platform = "platform"   # 平台配送
    pickup   = "pickup"
    
class OrderCreate(BaseModel):
    user_id:int
    delivery_way:DeliveryWay = DeliveryWay.platform   # 新增
    address_id:Optional[int]=None
    custom_address:Optional[dict]=None
    specifications:Optional[str]=None
    buy_now:bool=False
    buy_now_items:Optional[List[Dict[str,Any]]]=None

class OrderPay(BaseModel):
    order_number: str
    pay_way: str

class StatusUpdate(BaseModel):
    order_number: str
    new_status: str
    reason: Optional[str] = None

# ---------------- 路由 ----------------
@router.post("/create", summary="创建订单")
def create_order(body: OrderCreate):
    no = OrderManager.create(
        body.user_id,
        body.address_id,
        body.custom_address,
        specifications=body.specifications,   # 透传
        buy_now=body.buy_now,
        buy_now_items=body.buy_now_items,
        delivery_way=body.delivery_way
    )
    if not no:
        raise HTTPException(status_code=422, detail="购物车为空或地址缺失")
    return {"order_number": no}

@router.post("/pay", summary="订单支付")
def order_pay(body: OrderPay):
    if body.pay_way not in VALID_PAY_WAYS:
        raise HTTPException(status_code=422, detail="非法支付方式")
    return {"ok": OrderManager.update_status(body.order_number, "pending_ship")}

@router.get("/{user_id}", summary="查询用户订单列表")
def list_orders(user_id: int, status: Optional[str] = None):
    return OrderManager.list_by_user(user_id, status)

@router.get("/detail/{order_number}", summary="查询订单详情")
def order_detail(order_number: str):
    d = OrderManager.detail(order_number)
    if not d:
        raise HTTPException(status_code=404, detail="订单不存在")
    return d

@router.post("/status", summary="更新订单状态")
def update_status(body: StatusUpdate):
    return {"ok": OrderManager.update_status(body.order_number, body.new_status, body.reason)}