from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, field_validator, StringConstraints
from typing import Optional, List, Dict, Any, Annotated
from core.database import get_conn
from services.finance_service import get_balance, withdraw
from decimal import Decimal
from .refund import RefundManager
from .wechat_shipping import WechatShippingManager, WechatShippingService
from core.logging import get_logger
import time
import json  # ==================== 新增：导入json用于记录日志 ====================

router = APIRouter()
logger = get_logger(__name__)


class MerchantManager:
    @staticmethod
    def list_orders(status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查 users 表是否有 phone 字段
                cur.execute("""
                    SELECT COLUMN_NAME 
                    FROM information_schema.COLUMNS 
                    WHERE TABLE_SCHEMA = DATABASE() 
                    AND TABLE_NAME = 'users' 
                    AND COLUMN_NAME = 'phone'
                """)
                has_phone = cur.fetchone() is not None

                if has_phone:
                    sql = """SELECT o.*, u.name AS user_name, COALESCE(u.phone, '') AS user_phone
                             FROM orders o JOIN users u ON o.user_id=u.id"""
                else:
                    sql = """SELECT o.*, u.name AS user_name, NULL AS user_phone
                             FROM orders o JOIN users u ON o.user_id=u.id"""

                params = []
                if status:
                    sql += " WHERE o.status=%s"
                    params.append(status)
                sql += " ORDER BY o.created_at DESC LIMIT %s"
                params.append(limit)
                cur.execute(sql, tuple(params))
                orders = cur.fetchall()
                for o in orders:
                    cur.execute("""SELECT oi.*, p.name AS product_name
                                   FROM order_items oi JOIN products p ON oi.product_id=p.id
                                   WHERE oi.order_id=%s""", (o["id"],))
                    o["items"] = cur.fetchall()
                return orders

    @staticmethod
    def ship(
            order_number: str,
            tracking_number: str,
            express_company: Optional[str] = None,
            sync_to_wechat: bool = True,
            logistics_type: Optional[int] = None,
            item_desc: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        发货：写入快递单号、更新状态，并同步到微信小程序发货管理

        Args:
            order_number: 订单号
            tracking_number: 物流单号（实体物流必填，自提/虚拟商品可为空）
            express_company: 快递公司编码（如"YTO"=圆通，"SF"=顺丰）
            sync_to_wechat: 是否同步到微信发货管理（默认True）
            logistics_type: 物流类型，1=实体物流, 2=同城配送, 3=虚拟商品, 4=用户自提
            item_desc: 商品描述

        Returns:
            {"ok": True/False, "local_updated": True/False, "wechat_sync": {...}, "message": ""}
        """
        result = {
            "ok": False,
            "local_updated": False,
            "wechat_sync": None,
            "message": ""
        }

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 查询订单信息
                cur.execute(
                    """SELECT o.*, u.openid, u.mobile as user_phone, u.name as user_name,
                              o.delivery_way, o.transaction_id, o.consignee_phone
                       FROM orders o 
                       JOIN users u ON o.user_id = u.id 
                       WHERE o.order_number=%s""",
                    (order_number,)
                )
                order_info = cur.fetchone()

                if not order_info:
                    result["message"] = "订单不存在"
                    return result

                if order_info["status"] != "pending_ship":
                    result["message"] = f"订单状态不正确，当前状态：{order_info['status']}"
                    return result

                transaction_id = order_info.get("transaction_id")
                openid = order_info.get("openid")
                delivery_way = order_info.get("delivery_way", "platform")

                # 如未传入物流单号，回落到订单已存的 tracking_number
                if not tracking_number:
                    tracking_number = order_info.get("tracking_number", "")

                # 2. 更新本地订单状态
                cur.execute(
                    "UPDATE orders SET status='pending_recv', tracking_number=%s "
                    "WHERE order_number=%s AND status='pending_ship'",
                    (tracking_number, order_number)
                )
                conn.commit()

                updated = cur.rowcount > 0
                result["local_updated"] = updated

                if not updated:
                    result["message"] = "更新订单状态失败"
                    return result

                result["ok"] = True
                result["message"] = "本地发货成功"

                # 3. 同步到微信小程序发货管理
                if sync_to_wechat and transaction_id and openid:
                    try:
                        # 自动识别物流类型
                        if logistics_type is None:
                            logistics_type = WechatShippingService.get_logistics_type(delivery_way)

                        # 实体物流缺省时兜底一个快递编码（express_company 与 tracking_no 为必填）
                        if logistics_type == 1:
                            if not express_company:
                                express_company = "YTO"  # 默认圆通，避免空值导致微信拒绝
                                logger.info("订单%s实体物流未传快递公司，已兜底为 YTO", order_number)
                            else:
                                express_company = express_company.strip().upper()

                            # 校验运单号基本格式（微信通常要求 6-32 位字母数字）
                            tracking_trimmed = (tracking_number or "").strip()
                            if not tracking_trimmed or len(tracking_trimmed) < 6 or len(tracking_trimmed) > 32:
                                result["ok"] = False
                                result["message"] += "，物流单号长度不符合要求(6-32位)"
                                logger.warning("订单%s物流单号格式不合法: %s", order_number, tracking_trimmed)
                                return result
                            tracking_number = tracking_trimmed

                        # 构建商品描述
                        if not item_desc:
                            # 查询首个商品名称
                            cur.execute(
                                """SELECT p.name, oi.quantity 
                                   FROM order_items oi 
                                   JOIN products p ON oi.product_id = p.id 
                                   WHERE oi.order_id = %s LIMIT 1""",
                                (order_info["id"],)
                            )
                            item = cur.fetchone()
                            if item:
                                item_desc = f"{item['name']} x{item['quantity']}"
                            else:
                                item_desc = "商品"

                        # 判断是否为顺丰（需要特殊处理联系方式）
                        is_sfeng = express_company and express_company.upper() in ['SF', 'SFEXPRESS', '顺丰']

                        # 收件人手机号优先使用订单收货人，缺省时回落到用户手机号
                        receiver_phone = order_info.get("consignee_phone") or order_info.get("user_phone")

                        # 记录即将同步的关键信息（含十六进制视图，便于定位非UTF-8字符）
                        def _hex(v: Any) -> str:
                            try:
                                return str(v).encode("utf-8", "backslashreplace").hex()
                            except Exception:
                                return "encode_error"

                        logger.info(
                            "微信发货同步参数 | order=%s tracking=%s express=%s item_desc=%s consignee_phone=%s user_name=%s",
                            order_number, tracking_number, express_company, item_desc, receiver_phone,
                            order_info.get("user_name")
                        )
                        logger.info(
                            "微信发货同步参数HEX | tracking=%s express=%s item_desc=%s consignee_phone=%s user_name=%s",
                            _hex(tracking_number), _hex(express_company), _hex(item_desc), _hex(receiver_phone),
                            _hex(order_info.get("user_name"))
                        )

                        # 清洗为 UTF-8，剔除控制字符，避免微信接口非 UTF-8 报错
                        def _clean(val: Any) -> str:
                            s = "" if val is None else str(val)
                            # 去除非打印控制字符
                            s = "".join(ch for ch in s if ch >= " " or ch == "\n")
                            return s.encode("utf-8", "ignore").decode("utf-8")

                        wx_result = WechatShippingService.sync_order_to_wechat(
                            transaction_id=_clean(transaction_id),
                            openid=_clean(openid),
                            delivery_way=delivery_way,
                            tracking_number=_clean(tracking_number),
                            express_company=_clean(express_company),
                            item_desc=_clean(item_desc),
                            receiver_phone=_clean(receiver_phone),
                            is_sfeng=is_sfeng
                        )

                        result["wechat_sync"] = wx_result

                        if wx_result.get("errcode") == 0:
                            result["message"] += "，已同步到微信发货管理"
                            logger.info(f"订单{order_number}同步到微信发货管理成功")

                            # ==================== 新增：记录成功日志到数据库 ====================
                            try:
                                cur.execute("""
                                    INSERT INTO wechat_shipping_logs 
                                    (order_id, order_number, transaction_id, action_type, logistics_type, 
                                     express_company, tracking_no, is_success, response_data, created_at)
                                    VALUES (%s, %s, %s, 'upload', %s, %s, %s, 1, %s, NOW())
                                """, (
                                    order_info['id'],
                                    order_number,
                                    transaction_id,
                                    logistics_type,
                                    express_company,
                                    tracking_number,
                                    json.dumps(wx_result)
                                ))

                                # 更新订单的微信发货状态为已上传(1)
                                cur.execute("""
                                    UPDATE orders 
                                    SET wechat_shipping_status = 1,
                                        wechat_shipping_time = NOW(),
                                        wechat_shipping_msg = NULL
                                    WHERE id = %s
                                """, (order_info['id'],))
                                conn.commit()
                            except Exception as e:
                                logger.error(f"记录微信发货成功日志失败: {e}")
                                conn.rollback()

                        else:
                            error_msg = wx_result.get("errmsg", "未知错误")
                            result["message"] += f"，同步到微信失败：{error_msg}"
                            logger.error(f"订单{order_number}同步到微信发货管理失败：{error_msg}")

                            # ==================== 新增：记录失败日志 ====================
                            try:
                                cur.execute("""
                                    INSERT INTO wechat_shipping_logs 
                                    (order_id, order_number, transaction_id, action_type, logistics_type,
                                     express_company, tracking_no, is_success, errmsg, response_data, created_at)
                                    VALUES (%s, %s, %s, 'upload', %s, %s, %s, 0, %s, %s, NOW())
                                """, (
                                    order_info['id'],
                                    order_number,
                                    transaction_id,
                                    logistics_type,
                                    express_company,
                                    tracking_number,
                                    error_msg,
                                    json.dumps(wx_result)
                                ))

                                # 更新订单的微信发货状态为失败(2)
                                cur.execute("""
                                    UPDATE orders 
                                    SET wechat_shipping_status = 2,
                                        wechat_shipping_msg = %s
                                    WHERE id = %s
                                """, (error_msg[:500], order_info['id']))
                                conn.commit()
                            except Exception as e:
                                logger.error(f"记录微信发货失败日志失败: {e}")
                                conn.rollback()

                    except Exception as e:
                        logger.error(f"同步订单{order_number}到微信发货管理异常: {e}")
                        result["wechat_sync"] = {"error": str(e)}
                        result["message"] += f"，同步到微信异常：{str(e)}"

                        # ==================== 新增：记录异常状态 ====================
                        try:
                            cur.execute("""
                                UPDATE orders 
                                SET wechat_shipping_status = 2,
                                    wechat_shipping_msg = %s
                                WHERE id = %s
                            """, (str(e)[:500], order_info['id']))
                            conn.commit()
                        except:
                            pass
                elif sync_to_wechat:
                    missing = []
                    if not transaction_id:
                        missing.append("微信支付单号")
                    if not openid:
                        missing.append("用户openid")
                    result["message"] += f"，缺少信息无法同步到微信：{', '.join(missing)}"
                    logger.warning(f"订单{order_number}缺少{', '.join(missing)}，无法同步到微信")

                return result

    @staticmethod
    def approve_refund(order_number: str, approve: bool = True, reject_reason: Optional[str] = None):
        RefundManager.audit(order_number, approve, reject_reason)

    @staticmethod
    def notify_confirm_receive(order_number: str) -> Dict[str, Any]:
        """
        发送确认收货提醒到微信
        用于物流已签收时提醒用户确认收货（每个订单只能调用一次）
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT o.transaction_id, o.order_number, o.paid_at, u.openid
                       FROM orders o 
                       JOIN users u ON o.user_id = u.id 
                       WHERE o.order_number=%s AND o.status='pending_recv'""",
                    (order_number,)
                )
                order_info = cur.fetchone()

                if not order_info:
                    return {"ok": False, "error": "订单不存在或状态不正确"}

                if not order_info.get("transaction_id"):
                    return {"ok": False, "error": "缺少微信支付单号"}

                # 签收时间，使用当前时间
                received_time = int(time.time())

                result = WechatShippingManager.notify_confirm_receive(
                    transaction_id=order_info["transaction_id"],
                    received_time=received_time
                )

                if result.get("errcode") == 0:
                    logger.info(f"订单{order_number}确认收货提醒发送成功")
                    return {"ok": True, "data": result}
                else:
                    logger.error(f"订单{order_number}确认收货提醒发送失败：{result}")
                    return {"ok": False, "error": result.get("errmsg"), "data": result}


# ---------------- 请求模型 ----------------
class MShip(BaseModel):
    order_number: str
    tracking_number: str
    express_company: Optional[str] = None
    sync_to_wechat: bool = True
    logistics_type: Optional[int] = None  # 1=实体物流, 2=同城配送, 3=虚拟商品, 4=用户自提
    item_desc: Optional[str] = None


class MRefundAudit(BaseModel):
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None


class MWithdraw(BaseModel):
    amount: float


class MBindBank(BaseModel):
    user_id: int
    bank_name: str
    bank_account: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=30)]

    @field_validator("bank_account")
    @classmethod
    def digits_only(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("银行卡号只能为数字")
        return v


class NotifyConfirmReceiveRequest(BaseModel):
    order_number: str


# ---------------- 路由 ----------------
@router.get("/orders", summary="查询订单列表")
def m_orders(status: Optional[str] = None):
    return MerchantManager.list_orders(status)


@router.post("/ship", summary="订单发货（自动同步微信发货管理）")
def m_ship(body: MShip):
    """
    订单发货接口，支持同步到微信小程序发货管理

    - 实体物流（快递）：需要填写 tracking_number 和 express_company
    - 用户自提/虚拟商品：tracking_number 可为空

    快递公司编码参考微信文档，常见编码：
    - SF = 顺丰速运
    - YTO = 圆通速递
    - ZTO = 中通快递
    - STO = 申通快递
    - YD = 韵达速递
    - EMS = EMS
    """
    result = MerchantManager.ship(
        order_number=body.order_number,
        tracking_number=body.tracking_number,
        express_company=body.express_company,
        sync_to_wechat=body.sync_to_wechat,
        logistics_type=body.logistics_type,
        item_desc=body.item_desc
    )

    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])

    return result


@router.post("/approve_refund", summary="审核退款申请")
def m_refund_audit(body: MRefundAudit):
    MerchantManager.approve_refund(body.order_number, body.approve, body.reject_reason)
    return {"ok": True}


@router.post("/withdraw", summary="申请提现", operation_id="merchant_withdraw")
def m_withdraw(body: MWithdraw):
    ok = withdraw(Decimal(str(body.amount)))
    if not ok:
        raise HTTPException(status_code=400, detail="余额不足")
    return {"ok": True}


@router.post("/bind_bank", summary="绑定银行卡", operation_id="merchant_bind_bank")
def m_bind(body: MBindBank):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE id=%s LIMIT 1", (body.user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="用户不存在")
            cur.execute(
                "SELECT id FROM user_bankcards WHERE user_id=%s AND bank_account=%s LIMIT 1",
                (body.user_id, body.bank_account)
            )
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="该银行卡已绑定，无需重复绑定")
            cur.execute(
                "INSERT INTO user_bankcards (user_id, bank_name, bank_account) VALUES (%s, %s, %s)",
                (body.user_id, body.bank_name, body.bank_account)
            )
            conn.commit()
    return {"ok": True}


@router.post("/notify-confirm-receive", summary="发送确认收货提醒")
def m_notify_confirm_receive(body: NotifyConfirmReceiveRequest):
    """
    发送确认收货提醒给用户（当物流显示已签收时调用）
    每个订单只能调用一次
    """
    result = MerchantManager.notify_confirm_receive(body.order_number)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "发送失败"))
    return result


# ---------------- 微信发货管理相关接口 ----------------
@router.get("/wechat/delivery-list", summary="获取快递公司列表")
def get_delivery_list():
    """获取微信小程序支持的快递公司列表"""
    result = WechatShippingManager.get_delivery_list()
    if result.get("errcode") != 0:
        raise HTTPException(status_code=500, detail=result.get("errmsg", "获取失败"))
    return result


@router.get("/wechat/order-status/{order_number}", summary="查询订单在微信的发货状态")
def get_wechat_order_status(order_number: str):
    """
    查询订单在微信小程序发货管理中的状态

    订单状态：
    - 1: 待发货
    - 2: 已发货
    - 3: 确认收货
    - 4: 交易完成
    - 5: 已退款
    - 6: 资金待结算
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT transaction_id FROM orders WHERE order_number=%s",
                (order_number,)
            )
            row = cur.fetchone()
            if not row or not row.get("transaction_id"):
                raise HTTPException(status_code=404, detail="订单不存在或缺少微信支付单号")

            transaction_id = row["transaction_id"]

    result = WechatShippingManager.get_order(transaction_id)
    if result.get("errcode") != 0:
        raise HTTPException(status_code=500, detail=result.get("errmsg", "查询失败"))
    return result


@router.post("/wechat/set-jump-path", summary="设置发货通知跳转路径")
def set_msg_jump_path(path: str = Query(..., description="小程序页面路径，如 pages/order/detail")):
    """
    设置用户点击微信发货通知消息后的跳转页面
    建议设置为订单详情页
    """
    result = WechatShippingManager.set_msg_jump_path(path)
    if result.get("errcode") != 0:
        raise HTTPException(status_code=500, detail=result.get("errmsg", "设置失败"))
    return {"ok": True, "data": result}


@router.get("/wechat/check-managed", summary="查询是否已开通发货管理服务")
def check_trade_managed():
    """查询小程序是否已开通发货信息管理服务"""
    result = WechatShippingManager.is_trade_managed()
    return result