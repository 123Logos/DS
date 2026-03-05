"""
微信小程序订单发货管理服务模块 - 已废弃

此模块已废弃，不再使用微信发货管理功能。
保留空壳文件以避免导入错误。

如需重新启用微信发货管理，请从历史版本恢复完整代码。
"""

from typing import Dict, Any
from core.logging import get_logger

logger = get_logger(__name__)


class WechatShippingManager:
    """微信小程序发货管理服务 - 已废弃"""

    @classmethod
    def get_delivery_list(cls, force_refresh: bool = False) -> Dict[str, Any]:
        """已废弃：返回空列表"""
        logger.warning("WechatShippingManager 已废弃，不再使用微信发货管理")
        return {"errcode": 0, "errmsg": "ok", "delivery_list": [], "count": 0}

    @classmethod
    def get_order(cls, transaction_id: str) -> Dict[str, Any]:
        """已废弃：返回空结果"""
        logger.warning("WechatShippingManager 已废弃，不再使用微信发货管理")
        return {"errcode": 0, "order_state": 3}  # 返回已确认收货状态，避免影响业务


class WechatShippingService:
    """微信发货业务逻辑层 - 已废弃"""

    @staticmethod
    def get_logistics_type(delivery_way: str) -> int:
        """已废弃：返回默认值"""
        return 1

    @classmethod
    def sync_order_to_wechat(cls, **kwargs) -> Dict[str, Any]:
        """已废弃：直接返回成功"""
        logger.warning("WechatShippingService 已废弃，不再同步微信发货信息")
        return {"errcode": 0, "errmsg": "ok"}