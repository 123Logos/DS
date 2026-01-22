from services.finance_service import FinanceService
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, cast
from core.config import Settings, settings
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
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from io import BytesIO
from typing import List, Dict, Any
from fastapi.responses import StreamingResponse

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
                    "name": order_info.get("consignee_name"),
                    "mobile": order_info.get("consignee_phone")      # 只取 users.mobile
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

    @staticmethod
    def export_to_excel(order_numbers: List[str]) -> bytes:
        """
        将多个订单详情导出为Excel文件
        :param order_numbers: 订单号列表
        :return: Excel文件的二进制数据
        """
        # 创建工作簿
        wb = Workbook()
        ws = wb.active
        ws.title = "订单详情"

        # 定义表头（中文名称）
        headers = [
            "订单号", "订单状态", "订单金额", "支付方式", "配送方式",
            "用户ID", "用户姓名", "用户手机号",
            "收货人", "收货电话", "省份", "城市", "区县", "详细地址",
            "商品信息", "商品规格", "下单时间", "支付时间", "发货时间"
        ]

        # 设置表头样式
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
        header_alignment = Alignment(horizontal="center", vertical="center")
        thin_border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )

        # 写入表头
        for col_idx, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
            cell.border = thin_border

        # 数据行
        row_idx = 2
        for order_number in order_numbers:
            order_data = OrderManager.detail(order_number)
            if not order_data:
                continue

            order_info = order_data["order_info"]
            user_info = order_data["user"]
            address = order_data["address"] or {}
            items = order_data["items"]
            specifications = order_data.get("specifications") or {}

            # 处理商品信息（多个商品用换行符分隔）
            product_names = "\n".join([item.get("product_name", "") for item in items])
            quantities = "\n".join([f"数量: {item.get('quantity', 0)}" for item in items])
            unit_prices = "\n".join([f"单价: ¥{item.get('unit_price', 0)}" for item in items])
            product_info = f"{product_names}\n{quantities}\n{unit_prices}"

            # 处理规格信息
            spec_str = ""
            if isinstance(specifications, dict):
                spec_str = "\n".join([f"{k}: {v}" for k, v in specifications.items()])

            # 整理行数据
            row_data = [
                order_info.get("order_number", ""),
                order_info.get("status", ""),
                float(order_info.get("total_amount", 0)),
                order_info.get("pay_way", "wechat"),
                order_info.get("delivery_way", "platform"),
                user_info.get("id", ""),
                user_info.get("name", ""),
                user_info.get("mobile", ""),
                address.get("consignee_name", ""),
                address.get("consignee_phone", ""),
                address.get("province", ""),
                address.get("city", ""),
                address.get("district", ""),
                address.get("detail", ""),
                product_info,
                spec_str,
                order_info.get("created_at", ""),
                order_info.get("paid_at", ""),
                order_info.get("shipped_at", "")
            ]

            # 写入数据行
            for col_idx, value in enumerate(row_data, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.alignment = Alignment(vertical="center", wrap_text=True)
                cell.border = thin_border

                # 金额列设置为货币格式
                if col_idx == 3 and isinstance(value, (int, float)):
                    cell.number_format = '¥#,##0.00'

            row_idx += 1

        # 调整列宽（自动适应内容）
        for column in ws.columns:
            max_length = 0
            column_letter = get_column_letter(column[0].column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)  # 最大宽度限制为50
            ws.column_dimensions[column_letter].width = adjusted_width

        # 调整行高（适应多行内容）
        for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
            max_lines = 1
            for cell in row:
                if cell.value and isinstance(cell.value, str):
                    lines = cell.value.count('\n') + 1
                    max_lines = max(max_lines, lines)
            ws.row_dimensions[row[0].row].height = min(15 * max_lines, 100)  # 最大高度限制为100

        # 保存到内存
        excel_data = BytesIO()
        wb.save(excel_data)
        excel_data.seek(0)
        return excel_data.getvalue()
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
    coupon_id: Optional[int] = None
    points_to_use: Optional[Decimal] = Decimal('0')


class StatusUpdate(BaseModel):
    order_number: str
    new_status: str
    reason: Optional[str] = None

class WechatPayParams(BaseModel):
    appId: str
    timeStamp: str
    nonceStr: str
    package: str
    signType: str
    paySign: str


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
    """支付回调：完成财务结算前验证优惠券适用范围，验证通过后完成财务结算并更新订单状态"""
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

            # 3.1 处理积分抵扣（只校验，不扣）
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

            # 3.2 处理优惠券抵扣（只校验，不标记已用）
            if body.coupon_id:
                today = datetime.now().date()
                cur.execute(
                    """SELECT c.id, c.amount, c.applicable_product_type, c.valid_from, c.valid_to 
                       FROM coupons c 
                       WHERE c.id = %s AND c.user_id = %s AND c.status = 'unused'""",
                    (body.coupon_id, user_id)
                )
                coupon = cur.fetchone()
                if not coupon:
                    raise HTTPException(status_code=400, detail="优惠券不存在或已使用")
                if not (coupon['valid_from'] <= today <= coupon['valid_to']):
                    raise HTTPException(status_code=400, detail="优惠券不在有效期内")

                cur.execute(
                    """SELECT DISTINCT p.is_member_product 
                       FROM order_items oi JOIN products p ON oi.product_id=p.id 
                       WHERE oi.order_id=%s""",
                    (order_id,)
                )
                prod_types = [r["is_member_product"] for r in cur.fetchall()]
                has_member = any(prod_types)
                app_type = coupon["applicable_product_type"]
                if app_type == "normal_only" and has_member:
                    raise HTTPException(status_code=400, detail="该优惠券仅限普通商品使用")
                if app_type == "member_only" and not has_member:
                    raise HTTPException(status_code=400, detail="该优惠券仅限会员商品使用")

                coupon_amount = Decimal(str(coupon["amount"]))
                logger.debug(f"用户{user_id}使用优惠券#{body.coupon_id}: 金额¥{coupon_amount}, 类型:{app_type}")

            # 4. 把“待抵扣”数据暂存到订单（不扣减/不标记已用）
            cur.execute(
                "UPDATE orders SET pending_points=%s, pending_coupon_id=%s WHERE id=%s",
                (int(total_points_to_use), body.coupon_id, order_id)
            )

            # 5. 计算微信应收现金（分）
            cash_fee = int((Decimal(order_info["total_amount"]) * 100) \
                           - int(total_points_to_use) * 100 \
                           - coupon_amount * 100)
            cash_fee = max(cash_fee, 1)   # 防 0 分

            # 6. 调微信统一下单（Mock 模式直接返回空）
            if settings.WX_MOCK_MODE:
                logger.info(f"[MOCK] 微信 unified-order 成功，订单{body.order_number}")
            else:
                import services.notify_service as ns
                req = {
                    "appid": settings.WECHAT_APP_ID,
                    "mchid": settings.WECHAT_PAY_MCH_ID,
                    "description": f"订单{body.order_number}",
                    "out_trade_no": body.order_number,
                    "notify_url": settings.WECHAT_PAY_NOTIFY_URL,
                    "amount": {"total": cash_fee, "currency": "CNY"}
                }
                # 获取用户 openid（优先从 users 表读取），若无则提示前端传入或绑定
                cur.execute("SELECT openid FROM users WHERE id=%s", (user_id,))
                user_row = cur.fetchone()
                openid = (user_row.get('openid') if user_row else None) or ''
                if not openid:
                    logger.error(f"下单失败：用户 {user_id} 未绑定 openid，无法创建 JSAPI 支付单")
                    raise HTTPException(status_code=422, detail="缺少 openid：请在小程序端传入或在用户资料中绑定 openid")

                # 将 payer.openid 填入请求，供 async_unified_order 使用
                req["payer"] = {"openid": openid}
                try:
                    import asyncio
                    # 在 AnyIO 的线程池中可能没有当前事件循环，使用 asyncio.run 在独立循环中执行协程
                    asyncio.run(ns.async_unified_order(req))
                except Exception as e:
                    logger.error(f"微信下单失败: {e}")
                    raise HTTPException(status_code=502, detail="生成支付单失败")

            # 7. 原样返回成功（前端收到后自行调起微信 SDK）
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




class OrderExportRequest(BaseModel):
    order_numbers: List[str]


@router.post("/export", summary="导出订单详情到Excel")
def export_orders(body: OrderExportRequest):
    """
    批量导出订单详情为Excel文件
    请求示例: {"order_numbers": ["20250101120000", "20250101120001"]}
    """
    if not body.order_numbers:
        raise HTTPException(status_code=422, detail="订单号列表不能为空")

    # 限制一次最多导出100个订单
    if len(body.order_numbers) > 100:
        raise HTTPException(status_code=422, detail="单次导出订单数不能超过100个")

    try:
        excel_data = OrderManager.export_to_excel(body.order_numbers)
        return StreamingResponse(
            BytesIO(excel_data),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=orders_export.xlsx"}
        )
    except Exception as e:
        logger.error(f"导出订单失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"导出失败: {str(e)}")

# 模块被导入时自动启动守护线程
start_order_expire_task()