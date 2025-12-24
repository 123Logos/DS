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
            specifications: Optional[str] = None,  # 新增：规格 JSON 字符串
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
                        pay_way, auto_recv_time, refund_reason, expire_at)
                    VALUES (%s, %s, %s, 'pending_pay', %s,
                            %s, %s, %s, %s, %s, %s, %s,
                            'wechat', %s, %s, %s)
                """, (
                    user_id, order_number, total, has_vip,
                    consignee_name, consignee_phone,
                    province, city, district, shipping_address, delivery_way,
                    datetime.now() + timedelta(days=7),
                    specifications,
                    datetime.now() + timedelta(hours=12)
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
                        i["sku_id"],  # 新增
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
                    "mobile": (
                            order_info.get("user_mobile")
                            or order_info.get("consignee_phone")
                    )
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
    def update_status(order_number: str, new_status: str, reason: Optional[str] = None) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询订单并加锁（防并发）
                cur.execute(
                    "SELECT id, status FROM orders WHERE order_number = %s FOR UPDATE",
                    (order_number,)
                )
                result = cur.fetchone()
                if not result:
                    return False

                old_status = result['status']
                order_id = result['id']

                # 更新状态
                cur.execute(
                    "UPDATE orders SET status = %s, refund_reason = %s WHERE order_number = %s",
                    (new_status, reason, order_number)
                )

                # 如果状态从pending_recv变为completed时发放积分
                if old_status == 'pending_recv' and new_status == 'completed':
                    try:
                        # 幂等性检查：确认是否已发放过积分
                        cur.execute(
                            "SELECT id FROM points_log WHERE related_order = %s AND type = 'member' AND reason LIKE '%确认收货%' LIMIT 1",
                            (order_id,)
                        )
                        if cur.fetchone():
                            logger.info(f"订单{order_number}积分已发放，跳过")
                        else:
                            fs = FinanceService()
                            # 调用积分发放并检查返回值
                            if not fs.grant_points_on_receive(order_number, external_conn=conn):
                                logger.error(f"订单{order_number}积分发放返回失败")
                    except Exception as e:
                        logger.error(f"订单{order_number}确认收货后积分发放失败: {e}", exc_info=True)
                        # 不抛出异常，避免影响订单状态更新

                conn.commit()
                return cur.rowcount > 0


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
                "SELECT id,user_id,total_amount,status,is_vip_item FROM orders WHERE order_number=%s",
                (body.order_number,)
            )
            order = cur.fetchone()
            if not order:
                raise HTTPException(status_code=404, detail="订单不存在")
            if order["status"] != "pending_pay":
                raise HTTPException(status_code=400, detail="订单状态不是待付款")

            user_id = order["user_id"]
            total_amt = Decimal(str(order["total_amount"]))
            is_vip = bool(order["is_vip_item"])

            # 2. 取订单里第一件商品作为结算主体
            cur.execute(
                "SELECT product_id,quantity FROM order_items WHERE order_id=%s LIMIT 1",
                (order["id"],)
            )
            item = cur.fetchone()
            if not item:
                raise HTTPException(status_code=422, detail="订单无商品明细")
            product_id = item["product_id"]
            quantity = item["quantity"]

            # 3. 处理优惠抵扣（积分 + 优惠券）
            total_points_to_use = Decimal('0')
            total_coupon_discount = Decimal('0')

            # 3.1 处理积分抵扣
            if body.points_to_use and body.points_to_use > 0:
                # 只读取用户积分用于快速校验（真正的扣减在 finance_service 中使用原子更新）
                cur.execute(
                    "SELECT COALESCE(member_points, 0) as points FROM users WHERE id = %s",
                    (user_id,)
                )
                user = cur.fetchone()
                if not user or Decimal(str(user['points'])) < body.points_to_use:
                    raise HTTPException(status_code=400, detail="积分余额不足")

                # 积分抵扣金额
                points_discount = body.points_to_use * POINTS_DISCOUNT_RATE

                # ✅ 移除：50%限制检查
                # if points_discount > total_amt * Decimal('0.5'):
                #     raise HTTPException(status_code=400, detail="积分抵扣不能超过订单金额的50%")

                total_points_to_use = body.points_to_use
                logger.debug(f"用户{user_id}使用积分{total_points_to_use}分，抵扣金额¥{points_discount}")

            # 3.2 处理优惠券抵扣
            if body.coupon_id:
                # 原子性标记优惠券为已使用，避免长事务锁等待
                cur.execute(
                    "UPDATE coupons SET status = 'used', used_at = NOW() WHERE id = %s AND user_id = %s AND status = 'unused'",
                    (body.coupon_id, user_id)
                )
                if cur.rowcount == 0:
                    raise HTTPException(status_code=400, detail="优惠券不存在或已使用")

                # 查询金额（更新成功则只有本事务拥有该券）
                cur.execute("SELECT amount FROM coupons WHERE id = %s", (body.coupon_id,))
                coupon = cur.fetchone()
                coupon_amount = Decimal(str(coupon['amount']))

                # 将优惠券金额转换为等效积分数量
                coupon_points = coupon_amount / POINTS_DISCOUNT_RATE if POINTS_DISCOUNT_RATE > 0 else Decimal('0')

                # 累加到总积分抵扣
                total_points_to_use += coupon_points
                total_coupon_discount = coupon_amount

                logger.debug(f"用户{user_id}使用优惠券#{body.coupon_id}: 金额¥{coupon_amount}, 等效积分{coupon_points}")

            # ✅ 移除：总抵扣金额50%限制检查
            # total_discount = (total_points_to_use * POINTS_DISCOUNT_RATE) + total_coupon_discount
            # if total_discount > total_amt * Decimal('0.5'):
            #     raise HTTPException(status_code=400, detail="总优惠金额不能超过订单金额的50%")

            # 4. 财务结算（传入总积分抵扣量和优惠券抵扣金额，使用同一连接避免死锁）
            fs = FinanceService()
            fs.settle_order(
                order_no=body.order_number,
                user_id=user_id,
                product_id=product_id,
                quantity=quantity,
                points_to_use=total_points_to_use,
                coupon_discount=total_coupon_discount,  # ✅ 新增：传递优惠券抵扣金额
                external_conn=conn  # ✅ 关键修复：传递连接避免卡死
            )

            # 5. 更新订单状态
            ok = OrderManager.update_status(body.order_number, "pending_ship")
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
    """自动收货和结算守护进程

    该函数会启动一个后台线程，每小时检查一次待收货订单，
    如果订单超过自动收货时间，则自动完成订单并发放积分。
    """
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

                            # 更新订单状态
                            cur.execute(
                                "UPDATE orders SET status='completed' WHERE id=%s",
                                (order_id,)
                            )

                            # ✅ 新增：确认收货后发放积分
                            try:
                                fs = FinanceService()
                                # 使用同一连接调用grant_points_on_receive以避免死锁
                                fs.grant_points_on_receive(order_number, external_conn=conn)
                                logger.debug(
                                    f"[auto_receive] 订单 {order_number} 已自动完成并发放积分。")
                            except Exception as e:
                                logger.error(
                                    f"[auto_receive] 订单{order_number}积分发放失败: {e}",
                                    exc_info=True
                                )

                            conn.commit()
                            logger.debug(f"[auto_receive] 订单 {order_number} 已自动完成。")
            except Exception as e:
                logger.error(f"[auto_receive] 异常: {e}")
            time.sleep(3600)  # 每小时检查一次

    t = threading.Thread(target=run, daemon=True)
    t.start()
    logger.info("自动收货守护进程已启动（包含积分发放）")


# 模块被导入时自动启动守护线程
start_order_expire_task()