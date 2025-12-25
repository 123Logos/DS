from services.finance_service import FinanceService
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from core.database import get_conn
from services.finance_service import split_order_funds
from core.config import VALID_PAY_WAYS, POINTS_DISCOUNT_RATE
from core.table_access import build_dynamic_select, get_table_structure, _quote_identifier
from decimal import Decimal
import uuid
from datetime import datetime, timedelta
from enum import Enum
import json
import threading
import time
from core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

# 在 order.py 的 _cancel_expire_orders 函数中
def _cancel_expire_orders():
    """每分钟扫描一次，把过期的 pending_pay 订单取消"""
    while True:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    now = datetime.now()
                    cur.execute("""
                        SELECT id, order_number
                        FROM orders
                        WHERE status='pending_pay'
                          AND expire_at IS NOT NULL
                          AND expire_at <= %s
                    """, (now,))
                    for o in cur.fetchall():
                        oid, ono = o["id"], o["order_number"]

                        # ✅ 新增：删除该订单的待发放奖励记录
                        cur.execute(
                            "SELECT id FROM pending_rewards WHERE order_id = %s AND status = 'pending'",
                            (oid,)
                        )
                        rewards = cur.fetchall()
                        for reward in rewards:
                            cur.execute(
                                "DELETE FROM pending_rewards WHERE id = %s",
                                (reward['id'],)
                            )
                            print(f"[expire] 删除订单 {ono} 的待发放奖励记录: ID={reward['id']}")

                        # 回滚库存
                        cur.execute(
                            "SELECT product_id,quantity FROM order_items WHERE order_id=%s",
                            (oid,)
                        )
                        for it in cur.fetchall():
                            cur.execute(
                                "UPDATE product_skus SET stock=stock+%s WHERE product_id=%s",
                                (it["quantity"], it["product_id"])
                            )

                        # 改状态
                        cur.execute(
                            "UPDATE orders SET status='cancelled',updated_at=NOW() WHERE id=%s",
                            (oid,)
                        )
                        print(f"[expire] 订单 {ono} 已自动取消")
                    conn.commit()
        except Exception as e:
            print(f"[expire] error: {e}")
        time.sleep(60)

def start_order_expire_task():
    """由 api.order 包初始化时调用一次即可"""
    t = threading.Thread(target=_cancel_expire_orders, daemon=True)
    t.start()
    print("[expire] 订单过期守护线程已启动")

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
            specifications: Optional[str] = None,
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

                        sku_id = it.get("sku_id")
                        if not sku_id:
                            cur.execute("SELECT id FROM product_skus WHERE product_id = %s LIMIT 1", (it['product_id'],))
                            sku_row = cur.fetchone()
                            if sku_row:
                                sku_id = sku_row.get('id')
                            else:
                                raise HTTPException(status_code=422, detail=f"商品 {it['product_id']} 无可用 SKU，请提供 sku_id")

                        if "price" not in it:
                            raise HTTPException(status_code=422, detail=f"buy_now_items 必须包含 price 字段：product_id={it['product_id']}")

                        items.append({
                            "sku_id": sku_id,
                            "product_id": it["product_id"],
                            "quantity": it["quantity"],
                            "price": Decimal(str(it["price"])),
                            "is_vip": prod["is_member_product"]
                        })
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

                # ---------- 2. 地址信息 ----------
                if delivery_way == "pickup":
                    consignee_name = consignee_phone = province = city = district = shipping_address = ""
                elif custom_addr:
                    consignee_name = custom_addr.get("consignee_name")
                    consignee_phone = custom_addr.get("consignee_phone")
                    province = custom_addr.get("province", "")
                    city = custom_addr.get("city", "")
                    district = custom_addr.get("district", "")
                    shipping_address = custom_addr.get("detail", "")
                else:
                    raise HTTPException(status_code=422, detail="必须上传收货地址或选择自提")

                # ---------- 3. 订单主表 ----------
                total = sum(Decimal(str(i["quantity"])) * Decimal(str(i["price"])) for i in items)
                has_vip = any(i["is_vip"] for i in items)
                order_number = datetime.now().strftime("%Y%m%d%H%M%S") + str(user_id) + str(uuid.uuid4().int)[:6]
                init_status = "pending_pay"  # 统一待支付

                cur.execute("""
                    INSERT INTO orders(
                        user_id, order_number, total_amount, status, is_vip_item,
                        consignee_name, consignee_phone,
                        province, city, district, shipping_address, delivery_way,
                        pay_way, auto_recv_time, refund_reason, expire_at)
                    VALUES (%s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s,
                            'wechat', %s, %s, %s)
                """, (
                    user_id, order_number, total, init_status, has_vip,
                    consignee_name, consignee_phone,
                    province, city, district, shipping_address, delivery_way,
                    datetime.now() + timedelta(days=7),
                    specifications,
                    datetime.now() + timedelta(hours=12) if init_status == "pending_pay" else None
                ))
                oid = cur.lastrowid

                # ---------- 4. 库存校验 & 扣减 ----------
                structure = get_table_structure(cur, "product_skus")
                has_stock_field = 'stock' in structure['fields']
                stock_select = (
                    f"COALESCE({_quote_identifier('stock')}, 0) AS {_quote_identifier('stock')}"
                    if has_stock_field and 'stock' in structure['asset_fields']
                    else _quote_identifier('stock')
                ) if has_stock_field else "0 AS stock"

                for i in items:
                    cur.execute(f"SELECT {stock_select} FROM {_quote_identifier('product_skus')} WHERE id=%s", (i['sku_id'],))
                    result = cur.fetchone()
                    current_stock = result.get('stock', 0) if result else 0
                    if current_stock < i["quantity"]:
                        raise HTTPException(status_code=400, detail=f"SKU {i['sku_id']} 库存不足")

                # ---------- 5. 写订单明细 ----------
                for i in items:
                    cur.execute("""
                        INSERT INTO order_items(order_id, product_id, sku_id, quantity, unit_price, total_price)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        oid, i["product_id"], i["sku_id"], i["quantity"],
                        i["price"], Decimal(str(i["quantity"])) * Decimal(str(i["price"]))
                    ))

                # ---------- 6. 扣库存 ----------
                if has_stock_field:
                    for i in items:
                        cur.execute("UPDATE product_skus SET stock = stock - %s WHERE id = %s", (i["quantity"], i["sku_id"]))

                # ---------- 7. 清空购物车（仅购物车结算场景） ----------
                if not buy_now:
                    cur.execute("DELETE FROM cart WHERE user_id = %s AND selected = 1", (user_id,))

                # ---------- 8. 资金拆分 ----------
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
                # 1. 构造 orders 表字段（全部带 o. 前缀，避免歧义）
                structure = get_table_structure(cur, "orders")
                select_parts = []
                for field in structure["fields"]:
                    if field in structure["asset_fields"]:
                        select_parts.append(
                            f"COALESCE(o.{_quote_identifier(field)}, 0) AS {_quote_identifier(field)}"
                        )
                    else:
                        select_parts.append(f"o.{_quote_identifier(field)}")

                select_fields = ", ".join(select_parts)

                # 2. 查询订单 + 用户
                cur.execute(f"""
                    SELECT 
                        {select_fields},
                        u.id     AS user_id,
                        u.name   AS user_name,
                        u.mobile AS user_mobile
                    FROM orders o
                    JOIN users u ON o.user_id = u.id
                    WHERE o.order_number = %s
                """, (order_number,))
                order_info = cur.fetchone()

                if not order_info:
                    return None

                # 3. 商品明细
                cur.execute("""
                    SELECT oi.*, p.name
                    FROM order_items oi
                    JOIN products p ON oi.product_id = p.id
                    WHERE oi.order_id = %s
                """, (order_info["id"],))
                items = cur.fetchall()

                # 4. 用户信息（方案一：兜底手机号）
                user_info = {
                    "id": order_info.get("user_id"),
                    "name": order_info.get("user_name"),
                    "mobile": order_info.get("user_mobile")      # 只取 users.mobile
                }

                # （推荐）清理 order_info 中的用户字段，避免语义混乱
                for k in ["user_id", "user_name", "user_mobile"]:
                    order_info.pop(k, None)

                # 如果还有类似 "u.user_id" 这种异常 key，也一并清掉
                for k in list(order_info.keys()):
                    if "." in k:
                        order_info.pop(k, None)

                # 5. 地址信息（你原来的，保持不变）
                address = {
                    "consignee_name": order_info.get("consignee_name"),
                    "consignee_phone": order_info.get("consignee_phone"),
                    "province": order_info.get("province"),
                    "city": order_info.get("city"),
                    "district": order_info.get("district"),
                    "detail": order_info.get("shipping_address")
                } if any(order_info.get(k) for k in (
                    "consignee_name",
                    "consignee_phone",
                    "province",
                    "city",
                    "district",
                    "shipping_address"
                )) else None

                # 6. 最终返回
                return {
                    "order_info": order_info,
                    "user": user_info,
                    "address": address,
                    "items": items,
                    "specifications": order_info.get("refund_reason")
                }

    @staticmethod
    def update_status(order_number: str, new_status: str, reason: Optional[str] = None, external_conn=None) -> bool:
        # 先读取订单当前状态与id
        order_id = None
        old_status = None

        if external_conn:
            cur = external_conn.cursor()
            try:
                cur.execute("SELECT id, status FROM orders WHERE order_number = %s", (order_number,))
                res = cur.fetchone()
                if not res:
                    return False
                order_id = res['id']
                old_status = res['status']

                # 如果状态已经是目标状态，则视为成功（幂等）
                if old_status == new_status:
                    return True

                cur.execute(
                    "UPDATE orders SET status = %s, refund_reason = %s, updated_at = NOW() WHERE id = %s",
                    (new_status, reason, order_id)
                )
                if cur.rowcount == 0:
                    return False
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
        else:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, status FROM orders WHERE order_number = %s", (order_number,))
                    res = cur.fetchone()
                    if not res:
                        return False
                    order_id = res['id']
                    old_status = res['status']

                    if old_status == new_status:
                        return True

                    cur.execute(
                        "UPDATE orders SET status = %s, refund_reason = %s, updated_at = NOW() WHERE id = %s",
                        (new_status, reason, order_id)
                    )
                    if cur.rowcount == 0:
                        return False
                    # 确保在使用内部连接时提交更改
                    try:
                        conn.commit()
                    except Exception:
                        pass

        # ✅ **移除**：积分已在支付时发放，确认收货后不再发放
        # if old_status == 'pending_recv' and new_status == 'completed':
        #     try:
        #         fs = FinanceService()
        #         fs.grant_points_on_receive(order_number, external_conn=external_conn)
        #     except Exception as e:
        #         logger.error(f"订单{order_number}确认收货后积分发放失败: {e}", exc_info=True)

        return True


# ---------------- 请求模型 ----------------
class DeliveryWay(str, Enum):
    platform = "platform"  # 平台配送
    pickup = "pickup"


class OrderCreate(BaseModel):
    user_id: int
    delivery_way: DeliveryWay = DeliveryWay.platform  # 新增
    address_id: Optional[int] = None
    custom_address: Optional[dict] = None
    specifications: Optional[str] = None
    buy_now: bool = False
    buy_now_items: Optional[List[Dict[str, Any]]] = None


class OrderPay(BaseModel):
    order_number: str
    pay_way: str
    coupon_id: Optional[int] = None  # 新增：使用的优惠券ID（如果有）
    points_to_use: Optional[Decimal] = Decimal('0')


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
        specifications=body.specifications,  # 透传
        buy_now=body.buy_now,
        buy_now_items=body.buy_now_items,
        delivery_way=body.delivery_way
    )
    if not no:
        raise HTTPException(status_code=422, detail="购物车为空或地址缺失")
    return {"order_number": no}

@router.post("/pay", summary="订单支付")
def order_pay(body: OrderPay):
    """支付回调：完成财务结算后再把订单状态改为待发货"""
    if body.pay_way not in VALID_PAY_WAYS:
        raise HTTPException(status_code=422, detail="非法支付方式")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 取订单基本信息
            cur.execute(
                "SELECT id,user_id,total_amount,status,is_vip_item,delivery_way "
                "FROM orders WHERE order_number=%s",
                (body.order_number,)
            )
            order_info = cur.fetchone()
            if not order_info:
                raise HTTPException(status_code=404, detail="订单不存在")
            user_id = order_info.get("user_id")
            if order_info["status"] != "pending_pay":
                raise HTTPException(status_code=400, detail="订单状态不是待付款")

            # 2. 获取order_id
            cur.execute("SELECT id FROM orders WHERE order_number=%s", (body.order_number,))
            order = cur.fetchone()
            if not order:
                raise HTTPException(status_code=404, detail="订单不存在")
            order_id = order['id']

            # 3. 处理优惠抵扣（积分 + 优惠券）—— 完全分离处理
            total_points_to_use = Decimal('0')
            coupon_amount = Decimal('0')

            # 3.1 处理积分抵扣
            if body.points_to_use and body.points_to_use > 0:
                cur.execute(
                    "SELECT COALESCE(member_points, 0) as points FROM users WHERE id = %s",
                    (order_info["user_id"],)
                )
                user = cur.fetchone()
                if not user or Decimal(str(user['points'])) < body.points_to_use:
                    raise HTTPException(status_code=400, detail="积分余额不足")

                total_points_to_use = body.points_to_use
                logger.debug(f"用户{user_id}使用积分{total_points_to_use}分")

            # 3.2 处理优惠券抵扣（不转换为积分）
            if body.coupon_id:
                cur.execute(
                    "UPDATE coupons SET status = 'used', used_at = NOW() WHERE id = %s AND user_id = %s AND status = 'unused'",
                    (body.coupon_id, user_id)
                )
                if cur.rowcount == 0:
                    raise HTTPException(status_code=400, detail="优惠券不存在或已使用")

                cur.execute("SELECT amount FROM coupons WHERE id = %s", (body.coupon_id,))
                coupon = cur.fetchone()
                coupon_amount = Decimal(str(coupon['amount']))
                logger.debug(f"用户{user_id}使用优惠券#{body.coupon_id}: 金额¥{coupon_amount}")

            # 4. 财务结算（传入分离的参数）
            fs = FinanceService()
            fs.settle_order(
                order_no=body.order_number,
                user_id=order_info["user_id"],
                order_id=order_id,
                points_to_use=total_points_to_use,  # 仅积分
                coupon_discount=coupon_amount,  # 仅优惠券
                external_conn=conn
            )

            # 5. 更新订单状态
            next_status = "pending_recv" if order_info["delivery_way"] == "pickup" else "pending_ship"
            ok = OrderManager.update_status(body.order_number, next_status, external_conn=conn)
            if not ok:
                raise HTTPException(status_code=500, detail="订单状态更新失败")

            conn.commit()

    return {"ok": True}

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

def auto_receive_task(db_cfg: dict = None):
    """自动收货守护进程（不再发放积分）"""
    import threading
    import time
    from datetime import datetime

    def run():
        while True:
            try:
                from core.database import get_conn
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        now = datetime.now()
                        cur.execute(
                            "SELECT id, order_number, total_amount FROM orders "
                            "WHERE status='pending_recv' AND auto_recv_time<=%s",
                            (now,)
                        )
                        for row in cur.fetchall():
                            order_id = row["id"]
                            order_number = row["order_number"]

                            # 更新订单状态为已完成
                            cur.execute(
                                "UPDATE orders SET status='completed' WHERE id=%s",
                                (order_id,)
                            )

                            # ✅ **移除**：积分已在支付时发放，自动收货不再发放
                            # try:
                            #     fs = FinanceService()
                            #     fs.grant_points_on_receive(order_number, external_conn=conn)
                            # except Exception as e:
                            #     logger.error(f"[auto_receive] 订单{order_number}积分发放失败: {e}", exc_info=True)

                            conn.commit()
                            logger.debug(f"[auto_receive] 订单 {order_number} 已自动完成。")
            except Exception as e:
                logger.error(f"[auto_receive] 异常: {e}")
            time.sleep(3600)  # 每小时检查一次

    t = threading.Thread(target=run, daemon=True)
    t.start()
    logger.info("自动收货守护进程已启动（不再发放积分）")

# 模块被导入时自动启动守护线程
start_order_expire_task()