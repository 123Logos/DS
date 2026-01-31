"""
微信小程序订单发货管理服务模块
对接微信发货信息管理服务API
文档：https://developers.weixin.qq.com/miniprogram/dev/platform-capabilities/business-capabilities/order-shipping/order-shipping.html
"""
import requests
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from fastapi import HTTPException
from core.config import settings
from core.logging import get_logger

logger = get_logger(__name__)


class WechatShippingManager:
    """微信小程序发货管理服务"""

    BASE_URL = "https://api.weixin.qq.com"
    UPLOAD_SHIPPING_INFO_URL = f"{BASE_URL}/wxa/sec/order/upload_shipping_info"
    NOTIFY_CONFIRM_RECEIVE_URL = f"{BASE_URL}/wxa/sec/order/notify_confirm_receive"
    GET_ORDER_URL = f"{BASE_URL}/wxa/sec/order/get_order"
    GET_ORDER_LIST_URL = f"{BASE_URL}/wxa/sec/order/get_order_list"
    SET_MSG_JUMP_PATH_URL = f"{BASE_URL}/wxa/sec/order/set_msg_jump_path"
    GET_DELIVERY_LIST_URL = f"{BASE_URL}/cgi-bin/express/delivery/open_msg/get_delivery_list"
    IS_TRADE_MANAGED_URL = f"{BASE_URL}/wxa/sec/order/is_trade_managed"
    IS_TRADE_MANAGEMENT_CONFIRMATION_COMPLETED_URL = f"{BASE_URL}/wxa/sec/order/is_trade_management_confirmation_completed"
    ACCESS_TOKEN_URL = f"{BASE_URL}/cgi-bin/token"

    _access_token_cache = {}

    @classmethod
    def _get_access_token(cls, force_refresh: bool = False) -> str:
        """获取微信小程序access_token，缓存2小时"""
        cache_key = f"access_token_{settings.WECHAT_APP_ID}"

        if not force_refresh and cache_key in cls._access_token_cache:
            cached = cls._access_token_cache[cache_key]
            if cached['expires_at'] > time.time() + 300:
                return cached['token']

        try:
            params = {
                'grant_type': 'client_credential',
                'appid': settings.WECHAT_APP_ID,
                'secret': settings.WECHAT_APP_SECRET
            }
            resp = requests.get(cls.ACCESS_TOKEN_URL, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()

            if 'access_token' not in data:
                error_msg = data.get('errmsg', 'Unknown error')
                raise HTTPException(status_code=500, detail=f"获取微信access_token失败: {error_msg}")

            token = data['access_token']
            expires_in = data.get('expires_in', 7200)

            cls._access_token_cache[cache_key] = {
                'token': token,
                'expires_at': time.time() + expires_in
            }
            return token

        except requests.RequestException as e:
            raise HTTPException(status_code=500, detail=f"请求微信access_token失败: {str(e)}")

    @classmethod
    def _make_request(cls, url: str, data: Dict[str, Any], method: str = "POST") -> Dict[str, Any]:
        """发送带access_token的请求"""
        token = cls._get_access_token()
        full_url = f"{url}?access_token={token}"
        headers = {'Content-Type': 'application/json; charset=utf-8'}

        def _post_payload(body: Dict[str, Any]):
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            return requests.post(full_url, data=payload, headers=headers, timeout=10)

        try:
            if method == "GET":
                resp = requests.get(full_url, headers=headers, timeout=10)
            else:
                resp = _post_payload(data)

            resp.raise_for_status()
            result = resp.json()

            # Token过期处理
            if result.get('errcode') == 40001:
                token = cls._get_access_token(force_refresh=True)
                full_url = f"{url}?access_token={token}"
                if method == "GET":
                    resp = requests.get(full_url, headers=headers, timeout=10)
                else:
                    resp = _post_payload(data)
                result = resp.json()

            return result

        except requests.RequestException as e:
            logger.error(f"微信API请求失败 {url}: {e}")
            raise HTTPException(status_code=500, detail=f"微信API请求失败: {str(e)}")

    @staticmethod
    def _format_rfc3339(dt: Optional[datetime] = None) -> str:
        """格式化为RFC3339格式: 2022-12-15T13:29:35.120+08:00"""
        if dt is None:
            dt = datetime.now(timezone(timedelta(hours=8)))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "+08:00"

    @classmethod
    def upload_shipping_info(
            cls,
            transaction_id: str,
            openid: str,
            logistics_type: int,
            shipping_list: List[Dict[str, Any]],
            delivery_mode: int = 1,
            is_all_delivered: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        发货信息录入接口

        Args:
            transaction_id: 微信支付单号
            openid: 用户openid
            logistics_type: 1-实体物流, 2-同城配送, 3-虚拟商品, 4-用户自提
            shipping_list: 物流信息列表
            delivery_mode: 1-统一发货, 2-分拆发货
            is_all_delivered: 分拆发货时是否已全部完成
        """
        data = {
            "order_key": {
                "order_number_type": 2,  # 使用微信支付单号
                "transaction_id": transaction_id
            },
            "logistics_type": logistics_type,
            "delivery_mode": delivery_mode,
            "shipping_list": shipping_list,
            "upload_time": cls._format_rfc3339(),
            "payer": {"openid": openid}
        }

        if is_all_delivered is not None:
            data["is_all_delivered"] = is_all_delivered

        return cls._make_request(cls.UPLOAD_SHIPPING_INFO_URL, data)

    @classmethod
    def notify_confirm_receive(
            cls,
            received_time: int,
            transaction_id: Optional[str] = None,
            merchant_id: Optional[str] = None,
            merchant_trade_no: Optional[str] = None
    ) -> Dict[str, Any]:
        """确认收货提醒接口，每个订单只能调用一次"""
        data = {"received_time": received_time}

        if transaction_id:
            data["transaction_id"] = transaction_id
        if merchant_id:
            data["merchant_id"] = merchant_id
        if merchant_trade_no:
            data["merchant_trade_no"] = merchant_trade_no

        return cls._make_request(cls.NOTIFY_CONFIRM_RECEIVE_URL, data)

    @classmethod
    def get_order(cls, transaction_id: str) -> Dict[str, Any]:
        """查询订单发货状态"""
        return cls._make_request(cls.GET_ORDER_URL, {"transaction_id": transaction_id})

    @classmethod
    def get_order_list(
            cls,
            pay_time_range: Optional[Dict[str, int]] = None,
            order_state: Optional[int] = None,
            openid: Optional[str] = None,
            page_size: int = 100
    ) -> Dict[str, Any]:
        """查询订单列表"""
        data = {"page_size": page_size}
        if pay_time_range:
            data["pay_time_range"] = pay_time_range
        if order_state:
            data["order_state"] = order_state
        if openid:
            data["openid"] = openid
        return cls._make_request(cls.GET_ORDER_LIST_URL, data)

    @classmethod
    def set_msg_jump_path(cls, path: str) -> Dict[str, Any]:
        """设置发货通知消息跳转路径"""
        return cls._make_request(cls.SET_MSG_JUMP_PATH_URL, {"path": path})

    @classmethod
    def get_delivery_list(cls) -> Dict[str, Any]:
        """获取快递公司列表"""
        return cls._make_request(cls.GET_DELIVERY_LIST_URL, {}, method="GET")

    @classmethod
    def is_trade_managed(cls) -> Dict[str, Any]:
        """查询小程序是否已开通发货信息管理服务"""
        return cls._make_request(cls.IS_TRADE_MANAGED_URL, {}, method="GET")

    @classmethod
    def is_trade_management_confirmation_completed(cls) -> Dict[str, Any]:
        """查询小程序是否已完成交易结算管理确认"""
        return cls._make_request(
            cls.IS_TRADE_MANAGEMENT_CONFIRMATION_COMPLETED_URL,
            {},
            method="GET"
        )

    @staticmethod
    def mask_phone(phone: str) -> str:
        """手机号掩码处理，格式：189****1234"""
        if not phone or len(phone) != 11:
            return phone
        return f"{phone[:3]}****{phone[-4:]}"


class WechatShippingService:
    """微信发货业务逻辑层"""

    @staticmethod
    def get_logistics_type(delivery_way: str) -> int:
        """
        映射系统配送方式到微信物流类型
        1=实体物流, 2=同城配送, 3=虚拟商品, 4=用户自提
        """
        mapping = {
            "platform": 1,
            "express": 1,
            "pickup": 4,
            "same_city": 2,
            "virtual": 3,
        }
        return mapping.get(delivery_way, 1)

    @classmethod
    def sync_order_to_wechat(
            cls,
            transaction_id: str,
            openid: str,
            delivery_way: str,
            tracking_number: Optional[str] = None,
            express_company: Optional[str] = None,
            item_desc: Optional[str] = None,
            receiver_phone: Optional[str] = None,
            is_sfeng: bool = False  # 新增参数：是否为顺丰
    ) -> Dict[str, Any]:
        """便捷方法：同步发货信息到微信"""
        logistics_type = cls.get_logistics_type(delivery_way)

        shipping_item = {
            "item_desc": item_desc or "商品",
        }

        if tracking_number:
            shipping_item["tracking_no"] = tracking_number
        if express_company:
            shipping_item["express_company"] = express_company

        # 顺丰需要联系方式（掩码格式）
        if is_sfeng and receiver_phone:
            shipping_item["contact"] = {
                "receiver_contact": WechatShippingManager.mask_phone(receiver_phone)
            }

        return WechatShippingManager.upload_shipping_info(
            transaction_id=transaction_id,
            openid=openid,
            logistics_type=logistics_type,
            shipping_list=[shipping_item],
            delivery_mode=1
        )