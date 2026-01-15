# api/wechat_pay/routes.py
from fastapi import APIRouter, Request, HTTPException
from core.wx_pay_client import WeChatPayClient
from core.config import ENVIRONMENT
from core.response import success_response
from core.database import get_conn
from services.wechat_applyment_service import WechatApplymentService
import json
import logging
import xml.etree.ElementTree as ET  # 用于生成XML响应

router = APIRouter(prefix="/wechat-pay", tags=["微信支付"])

logger = logging.getLogger(__name__)
pay_client = WeChatPayClient()


@router.post("/notify", summary="微信支付回调通知")
async def wechat_pay_notify(request: Request):
    """
    处理微信支付异步通知
    1. 验证签名
    2. 解密回调数据
    3. 更新订单/进件状态
    4. 返回成功响应
    """
    try:
        body = await request.body()
        # 调试：记录收到的原始请求体及长度（repr 格式，便于发现隐藏字符）
        try:
            logger.debug(f"收到原始请求体 ({len(body)} bytes): {body!r}")
            logger.debug(f"请求头 Content-Type: {headers.get('content-type') if 'headers' in locals() else request.headers.get('content-type')}")
        except Exception:
            logger.debug("无法记录原始请求体（调试日志）")

        # 检查请求体是否为空（防止JSONDecodeError）
        if not body or len(body.strip()) == 0:
            logger.warning("收到空请求体，返回错误响应")
            return _xml_response("FAIL", "Empty request body")

        headers = request.headers

        # 验证签名头
        signature = headers.get("Wechatpay-Signature")
        timestamp = headers.get("Wechatpay-Timestamp")
        nonce = headers.get("Wechatpay-Nonce")
        serial = headers.get("Wechatpay-Serial")

        # 开发绕过：允许在非 production 环境下通过自定义头跳过签名校验（仅用于本地/测试）
        bypass_header = headers.get("X-DEV-BYPASS-VERIFY") or headers.get("X-DEV-BYPASS")
        # 支持基于共享测试令牌的绕过（在 systemd/.env 中设置 TEST_NOTIFY_TOKEN）
        test_token_header = headers.get("X-DEV-TEST-TOKEN")
        test_token_env = None
        try:
            import os

            test_token_env = os.getenv("TEST_NOTIFY_TOKEN")
        except Exception:
            test_token_env = None

        if (bypass_header and ENVIRONMENT != "production") or (
            test_token_header and test_token_env and test_token_header == test_token_env
        ):
            logger.warning("开发模式：绕过回调签名校验（开发头或测试令牌触发）")
        else:
            if not all([signature, timestamp, nonce, serial]):
                logger.error("缺少必要的回调头信息")
                return _xml_response("FAIL", "Missing callback headers")

            try:
                if not pay_client.verify_signature(signature, timestamp, nonce, body.decode()):
                    logger.error("签名验证失败")
                    return _xml_response("FAIL", "Signature verification failed")
            except Exception as e:
                logger.error(f"签名验证异常: {str(e)}")
                return _xml_response("FAIL", f"Signature error: {str(e)}")

        # 支持开发调试绕过签名验证（兼容性备用头）
        if headers.get("X-Bypass-Signature", "").lower() == "true" and ENVIRONMENT != "production":
            logger.warning("开发模式：跳过签名验证 (X-Bypass-Signature)")

        # 解析回调数据（真实微信通知是JSON，部分测试可能使用XML包装）
        content_type = headers.get("content-type", "")
        if "xml" in content_type:
            import xmltodict  # 需要安装: pip install xmltodict

            data_dict = xmltodict.parse(body)
            data = data_dict.get("xml", {})
            if "resource" in data:
                resource = data["resource"]
                if isinstance(resource, str):
                    data = json.loads(resource)
                else:
                    data = {"resource": resource}
            else:
                data = {"resource": data}
        else:
            data = json.loads(body)

        # 解密回调数据
        resource = data.get("resource", {})
        if not resource:
            logger.error("回调数据中缺少resource字段")
            return _xml_response("FAIL", "Missing resource")

        # 开发绕过：若请求头包含 X-DEV-PLAIN-BODY，则认为 resource 已是明文 JSON（跳过 decrypt）
        plain_header = headers.get("X-DEV-PLAIN-BODY") or headers.get("X-DEV-PLAIN")
        if plain_header and ENVIRONMENT != "production":
            logger.info("开发模式：跳过回调解密，直接使用明文 resource（X-DEV-PLAIN-BODY detected）")
            decrypted_data = resource
        else:
            decrypted_data = pay_client.decrypt_callback_data(resource)

        # 根据事件类型处理
        event_type = decrypted_data.get("event_type")

        if event_type == "APPLYMENT_STATE_CHANGE":
            await handle_applyment_state_change(decrypted_data)
            return _xml_response("SUCCESS", "OK")
        elif event_type == "TRANSACTION.SUCCESS":
            await handle_transaction_success(decrypted_data)
            return _xml_response("SUCCESS", "OK")
        else:
            logger.warning(f"未知的事件类型: {event_type}")
            return _xml_response("FAIL", f"Unknown event_type: {event_type}")

    except json.JSONDecodeError as e:
        logger.error(f"JSON解析失败: {str(e)}")
        return _xml_response("FAIL", "Invalid JSON format")
    except Exception as e:
        logger.error(f"微信支付回调处理失败: {str(e)}", exc_info=True)
        return _xml_response("FAIL", str(e))


def _xml_response(code: str, message: str) -> str:
    """
    生成微信支付回调要求的XML格式响应
    微信要求返回格式：
    <xml>
        <return_code><![CDATA[SUCCESS/FAIL]]></return_code>
        <return_msg><![CDATA[OK/错误信息]]></return_msg>
    </xml>
    """
    return f"""<xml>
<return_code><![CDATA[{code}]]></return_code>
<return_msg><![CDATA[{message}]]></return_msg>
</xml>"""


async def handle_applyment_state_change(data: dict):
    """处理进件状态变更回调"""
    try:
        applyment_id = data.get("applyment_id")
        state = data.get("applyment_state")

        if not applyment_id or not state:
            logger.error("进件回调缺少必要字段")
            return

        service = WechatApplymentService()
        await service.handle_applyment_state_change(
            applyment_id,
            state,
            {
                "state_msg": data.get("state_msg"),
                "sub_mchid": data.get("sub_mchid"),
            },
        )
        logger.info(f"进件状态更新成功: {applyment_id} -> {state}")
    except Exception as e:
        logger.error(f"进件状态处理失败: {str(e)}", exc_info=True)


async def handle_transaction_success(data: dict):
    """处理支付成功回调"""
    try:
        out_trade_no = data.get("out_trade_no")
        transaction_id = data.get("transaction_id")
        amount = data.get("amount", {}).get("total")

        if not out_trade_no:
            logger.error("支付回调缺少out_trade_no")
            return

        logger.info(f"支付成功: 订单号={out_trade_no}, 微信流水号={transaction_id}, 金额={amount}")

        # TODO: 支付成功后的业务逻辑

    except Exception as e:
        logger.error(f"支付成功回调处理失败: {str(e)}", exc_info=True)


def register_wechat_pay_routes(app):
    """
    注册微信支付路由
    注意：prefix 已在 router 中定义，这里不需要重复
    """
    app.include_router(router)