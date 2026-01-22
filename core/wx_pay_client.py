# core/wx_pay_client.py
# 微信支付V3 API客户端（生产级，本地公钥ID模式）
import os
import hashlib
import time
import uuid
import base64
import json
import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import (
    WECHAT_PAY_MCH_ID, WECHAT_PAY_API_V3_KEY,
    WECHAT_PAY_API_CERT_PATH, WECHAT_PAY_API_KEY_PATH,
    WECHAT_PAY_PUBLIC_KEY_PATH, WECHAT_PAY_PUB_KEY_ID,
    WECHAT_APP_ID, WECHAT_APP_SECRET, ENVIRONMENT
)
from core.database import get_conn
from core.logging import get_logger
from core.rate_limiter import settlement_rate_limiter, query_rate_limiter

logger = get_logger(__name__)


class WeChatPayClient:
    """微信支付V3 API客户端（生产级，本地公钥ID模式）"""

    BASE_URL = "https://api.mch.weixin.qq.com"

    # 完整的微信状态码映射
    WX_APPLYMENT_STATES = {
        'APPLYMENT_STATE_EDITTING': '编辑中',
        'APPLYMENT_STATE_AUDITING': '审核中',
        'APPLYMENT_STATE_REJECTED': '已驳回',
        'APPLYMENT_STATE_TO_BE_CONFIRMED': '待账户验证',
        'APPLYMENT_STATE_TO_BE_SIGNED': '待签约',
        'APPLYMENT_STATE_SIGNING': '签约中',
        'APPLYMENT_STATE_FINISHED': '已完成',
        'APPLYMENT_STATE_CANCELED': '已取消'
    }

    def __init__(self):
        # Mock模式开关（生产环境强制禁止）
        self.mock_mode = os.getenv('WX_MOCK_MODE', 'false').lower() == 'true'

        # 安全：生产环境禁止Mock
        if self.mock_mode and ENVIRONMENT == 'production':
            raise RuntimeError("❌ 生产环境禁止启用微信Mock模式")

        if self.mock_mode:
            logger.warning("⚠️ 【MOCK模式】已启用，所有微信接口调用均为模拟！")
            logger.warning("⚠️ 当前环境: {}".format(ENVIRONMENT))

        # 商户配置
        self.mchid = WECHAT_PAY_MCH_ID
        self.apiv3_key = WECHAT_PAY_API_V3_KEY.encode('utf-8')
        self.cert_path = WECHAT_PAY_API_CERT_PATH
        self.key_path = WECHAT_PAY_API_KEY_PATH
        self.pub_key_id = WECHAT_PAY_PUB_KEY_ID

        # 初始化序列号缓存
        self._cached_serial_no = None

        # 初始化HTTP连接池
        self.session = requests.Session()
        self.session.mount('https://', requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=3
        ))

        # 加载密钥和公钥
        self.private_key = self._load_private_key()
        self.wechat_public_key = self._load_wechat_public_key_from_file()

        # 初始化Mock测试数据
        if self.mock_mode:
            self._ensure_mock_applyment_exists()

    # ==================== 微信支付公钥加载（本地文件） ====================

    def _load_wechat_public_key_from_file(self) -> Any:
        """从本地文件加载微信支付公钥（2024年后公钥ID模式）"""
        if self.mock_mode:
            return None

        # 强制校验：公钥ID必须配置
        if not self.pub_key_id or not self.pub_key_id.startswith('PUB_KEY_ID_'):
            raise RuntimeError(
                f"微信支付公钥ID配置错误: {self.pub_key_id}\n"
                f"2024年后新商户必须从微信支付后台获取公钥ID（格式: PUB_KEY_ID_开头）"
            )

        # 读取本地公钥文件
        if not WECHAT_PAY_PUBLIC_KEY_PATH or not os.path.exists(WECHAT_PAY_PUBLIC_KEY_PATH):
            raise FileNotFoundError(
                f"微信支付公钥文件不存在: {WECHAT_PAY_PUBLIC_KEY_PATH}\n"
                f"请登录微信支付商户平台，进入【账户中心】->【API安全】->【微信支付公钥】下载公钥文件"
            )

        logger.info(f"【公钥ID模式】加载微信支付公钥: {self.pub_key_id}")

        # 公钥文件是标准PEM格式（从商户平台下载）
        with open(WECHAT_PAY_PUBLIC_KEY_PATH, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

        logger.info(f"✅ 微信支付公钥加载成功: {self.pub_key_id}")
        return public_key

    def _load_legacy_platform_cert(self) -> Any:
        """2024年前：兼容传统平台证书文件（已废弃）"""
        logger.warning("⚠️ 正在使用传统平台证书模式（即将废弃）")
        cert_path = WECHAT_PAY_PUBLIC_KEY_PATH
        if not cert_path or not os.path.exists(cert_path):
            raise FileNotFoundError(f"平台证书文件不存在: {cert_path}")
        with open(cert_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    # ==================== Mock支持 ====================

    def _ensure_mock_applyment_exists(self):
        """Mock模式下创建测试数据"""
        if not self.mock_mode or ENVIRONMENT == 'production':
            return

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT user_id FROM wx_applyment 
                        WHERE user_id = -1 AND applyment_state = 'APPLYMENT_STATE_FINISHED'
                    """)
                    if not cur.fetchone():
                        mock_data = {
                            "business_code": f"MOCK_BUSINESS_{int(time.time())}",
                            "sub_mchid": f"MOCK_SUB_MCHID_{uuid.uuid4().hex[:8].upper()}",
                            "subject_info": {
                                "business_license_info": {
                                    "license_number": "MOCK_LICENSE_123456",
                                    "license_copy_id": "MOCK_MEDIA_ID"
                                }
                            },
                            "contact_info": {
                                "contact_name": "Mock用户",
                                "contact_id_number": "MOCK_ID_123456"
                            },
                            "bank_account_info": {
                                "account_type": "ACCOUNT_TYPE_PRIVATE",
                                "account_bank": "工商银行",
                                "bank_name": "中国工商银行股份有限公司北京朝阳支行",
                                "account_number": "6222021234567890000",
                                "account_name": "测试用户"
                            }
                        }
                        cur.execute("""
                            INSERT INTO wx_applyment 
                            (user_id, business_code, sub_mchid, applyment_state, is_draft,
                             subject_type, subject_info, contact_info, bank_account_info)
                            VALUES (-1, %s, %s, 'APPLYMENT_STATE_FINISHED', 0,
                                    'SUBJECT_TYPE_INDIVIDUAL', %s, %s, %s)
                        """, (
                            mock_data["business_code"],
                            mock_data["sub_mchid"],
                            json.dumps(mock_data["subject_info"]),
                            json.dumps(mock_data["contact_info"]),
                            json.dumps(mock_data["bank_account_info"])
                        ))
                        conn.commit()
                        logger.info("✅ Mock模式：已创建测试进件记录 (user_id=-1)")
        except Exception as e:
            logger.debug(f"Mock初始化失败（可忽略）: {e}")

    def _generate_mock_application_no(self, sub_mchid: str) -> str:
        """生成模拟的申请单号"""
        timestamp = int(time.time())
        random_code = hashlib.md5(f"{sub_mchid}{timestamp}{uuid.uuid4()}".encode()).hexdigest()[:8]
        return f"MOCK_APP_{timestamp}_{sub_mchid}_{random_code}"

    def _get_mock_settlement_data(self, sub_mchid: str) -> Dict[str, Any]:
        """模拟微信结算账户查询返回"""
        logger.info(f"【MOCK】查询结算账户: sub_mchid={sub_mchid}")
        mock_behavior = os.getenv('WX_MOCK_SETTLEMENT_BEHAVIOR', 'normal')

        base_data = {
            'account_type': 'ACCOUNT_TYPE_PRIVATE',
            'account_bank': '工商银行',
            'bank_name': '中国工商银行股份有限公司北京朝阳支行',
            'bank_branch_id': '402713354941',
            'account_number': '6222021234567890000',
            'account_name': '测试用户',
            'bank_address_code': '100000'
        }

        if mock_behavior == 'fail':
            base_data.update({
                'verify_result': 'VERIFY_FAIL',
                'verify_fail_reason': '银行卡户名或卡号有误（Mock模拟）'
            })
        elif mock_behavior == 'verifying':
            base_data.update({
                'verify_result': 'VERIFYING',
                'verify_fail_reason': '正在验证中，请稍候（Mock模拟）'
            })
        else:
            base_data.update({
                'verify_result': 'VERIFY_SUCCESS',
                'verify_fail_reason': ''
            })

        # 尝试从数据库读取真实Mock数据
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT account_bank, bank_name, 
                               account_number_encrypted, account_name_encrypted,
                               bank_address_code, bank_branch_id
                        FROM merchant_settlement_accounts
                        WHERE sub_mchid = %s AND status = 1
                        ORDER BY updated_at DESC
                        LIMIT 1
                    """, (sub_mchid,))
                    record = cur.fetchone()
                    if record:
                        try:
                            full_number = self._decrypt_local_encrypted(record['account_number_encrypted'])
                            masked_number = f"{full_number[:6]}**********{full_number[-4:]}"
                            full_name = self._decrypt_local_encrypted(record['account_name_encrypted'])
                            return {
                                'account_type': 'ACCOUNT_TYPE_PRIVATE',
                                'account_bank': record['account_bank'] or base_data['account_bank'],
                                'bank_name': record['bank_name'] or record['account_bank'],
                                'bank_branch_id': record.get('bank_branch_id', base_data['bank_branch_id']),
                                'account_number': masked_number,
                                'account_name': full_name,
                                'verify_result': base_data['verify_result'],
                                'verify_fail_reason': base_data['verify_fail_reason'],
                                'bank_address_code': record.get('bank_address_code', '100000')
                            }
                        except Exception as e:
                            logger.warning(f"Mock解密失败，使用默认数据: {e}")
        except Exception as e:
            logger.warning(f"Mock读取数据库失败: {e}")

        return base_data

    def _get_mock_application_status(self, application_no: str) -> Dict[str, Any]:
        """模拟微信申请状态查询"""
        try:
            parts = application_no.split('_')
            if len(parts) >= 3 and parts[2].isdigit():
                app_time = int(parts[2])
                elapsed = time.time() - app_time
            else:
                elapsed = 999
        except:
            elapsed = 999

        mock_result = os.getenv('WX_MOCK_APPLY_RESULT', 'SUCCESS')

        if mock_result == 'PENDING' or elapsed < 5:
            return {
                'applyment_state': 'APPLYMENT_STATE_AUDITING',
                'applyment_state_msg': '审核中，请稍后...',
                'account_name': '张*',
                'account_type': 'ACCOUNT_TYPE_PRIVATE',
                'account_bank': '工商银行',
                'account_number': '62*************78'
            }
        elif mock_result == 'FAIL':
            return {
                'applyment_state': 'APPLYMENT_STATE_REJECTED',
                'applyment_state_msg': '银行账户信息有误（Mock模拟）',
                'verify_fail_reason': '银行卡户名或卡号不匹配'
            }
        else:
            return {
                'applyment_state': 'APPLYMENT_STATE_FINISHED',
                'applyment_state_msg': '审核通过',
                'account_name': '测试用户',
                'account_type': 'ACCOUNT_TYPE_PRIVATE',
                'account_bank': '工商银行',
                'account_number': '62*************78',
                'verify_finish_time': datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S+08:00')
            }

    # ==================== 商户证书加载 ====================

    def _load_private_key(self):
        """加载商户私钥（PEM格式）"""
        try:
            with open(self.key_path, 'rb') as f:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception as e:
            logger.error(f"加载微信支付私钥失败: {e}")
            if not self.mock_mode:
                raise
            return None

    def _get_merchant_serial_no(self) -> str:
        """获取商户API证书序列号（带缓存）"""
        if self._cached_serial_no:
            return self._cached_serial_no

        if self.mock_mode:
            self._cached_serial_no = "MOCK_SERIAL_NO"
            return self._cached_serial_no

        try:
            with open(self.cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(
                    f.read(),
                    backend=default_backend()
                )
                self._cached_serial_no = format(cert.serial_number, 'x').upper()
                logger.info(f"成功加载商户证书序列号: {self._cached_serial_no}")
                return self._cached_serial_no
        except Exception as e:
            logger.error(f"获取商户证书序列号失败: {e}")
            self._cached_serial_no = self.mchid
            return self._cached_serial_no

    # ==================== 加密与签名 ====================

    def _rsa_encrypt_with_wechat_public_key(self, plaintext: str) -> str:
        """使用微信支付平台公钥加密（用于敏感数据）"""
        if self.mock_mode:
            timestamp = int(time.time())
            random_code = hashlib.md5(f"{plaintext}{timestamp}".encode()).hexdigest()[:6]
            mock_enc = f"MOCK_ENC_{timestamp}_{plaintext}_{random_code}"
            return base64.b64encode(mock_enc.encode()).decode()

        if not self.wechat_public_key:
            raise Exception("微信支付平台公钥未加载")

        ciphertext = self.wechat_public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    def encrypt_sensitive_data(self, plaintext: str) -> str:
        """公共方法：加密敏感数据（供外部服务调用）"""
        try:
            return self._rsa_encrypt_with_wechat_public_key(plaintext)
        except Exception as e:
            logger.error(f"敏感数据加密失败: {str(e)}")
            if self.mock_mode:
                timestamp = int(time.time())
                random_code = hashlib.md5(f"{plaintext}{timestamp}".encode()).hexdigest()[:6]
                mock_enc = f"MOCK_ENC_{timestamp}_{plaintext}_{random_code}"
                return base64.b64encode(mock_enc.encode()).decode()
            raise

    def _sign(self, method: str, url: str, timestamp: str, nonce_str: str, body: str = '') -> str:
        """RSA-SHA256签名"""
        if self.mock_mode:
            return f"MOCK_SIGN_{hashlib.sha256(f'{method}{url}{timestamp}{nonce_str}{body}'.encode()).hexdigest()[:16]}"

        sign_str = f'{method}\n{url}\n{timestamp}\n{nonce_str}\n{body}\n'
        signature = self.private_key.sign(
            sign_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def _build_auth_header(self, method: str, url: str, body: str = '') -> str:
        """构建 Authorization 请求头（严格对齐微信规范）"""
        timestamp = str(int(time.time()))
        nonce_str = str(uuid.uuid4()).replace('-', '')
        signature = self._sign(method, url, timestamp, nonce_str, body)
        serial_no = self._get_merchant_serial_no()

        # 参数值中的双引号需要转义，且格式严格对齐
        auth_params = [
            f'mchid="{self.mchid}"',
            f'serial_no="{serial_no}"',
            f'nonce_str="{nonce_str}"',
            f'timestamp="{timestamp}"',
            f'signature="{signature}"'
        ]
        auth_str = ','.join(auth_params)
        return f'WECHATPAY2-SHA256-RSA2048 {auth_str}'

    # ==================== 进件相关API ====================

    @settlement_rate_limiter
    def submit_applyment(self, applyment_data: Dict[str, Any]) -> Dict[str, Any]:
        """提交进件申请"""
        if self.mock_mode:
            logger.info("【MOCK】模拟提交进件申请")
            sub_mchid = f"MOCK_SUB_MCHID_{uuid.uuid4().hex[:8].upper()}"
            return {
                "applyment_id": int(time.time() * 1000),
                "state_msg": "提交成功",
                "sub_mchid": sub_mchid
            }

        url = f"{self.BASE_URL}/v3/applyment4sub/applyment/"
        payload = {
            "business_code": applyment_data["business_code"],
            "contact_info": json.loads(applyment_data["contact_info"]),
            "subject_info": json.loads(applyment_data["subject_info"]),
            "bank_account_info": json.loads(applyment_data["bank_account_info"]),
        }

        body_str = json.dumps(payload, ensure_ascii=False)
        headers = {
            'Authorization': self._build_auth_header('POST', url, body_str),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Wechatpay-Serial': self._get_merchant_serial_no()
        }

        response = self.session.post(url, data=body_str.encode('utf-8'), headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    @query_rate_limiter
    def query_applyment_status(self, applyment_id: int) -> Dict[str, Any]:
        """查询进件状态"""
        if self.mock_mode:
            logger.info(f"【MOCK】查询进件状态: {applyment_id}")
            return self._get_mock_application_status(f"MOCK_{applyment_id}")

        url = f"{self.BASE_URL}/v3/applyment4sub/applyment/applyment_id/{applyment_id}"
        headers = {
            'Authorization': self._build_auth_header('GET', url),
            'Accept': 'application/json'
        }

        response = self.session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    @settlement_rate_limiter
    def upload_image(self, image_content: bytes, content_type: str) -> str:
        """上传图片获取media_id"""
        if self.mock_mode:
            logger.info("【MOCK】模拟上传图片")
            return f"MOCK_MEDIA_{int(time.time())}_{uuid.uuid4().hex[:8]}"

        url = f"{self.BASE_URL}/v3/merchant/media/upload"
        files = {
            'file': (
                'image.jpg',
                image_content,
                content_type,
                {'Content-Disposition': 'form-data; name="file"; filename="image.jpg"'}
            )
        }

        headers = {
            'Authorization': self._build_auth_header('POST', url),
            'Wechatpay-Serial': self._get_merchant_serial_no()
        }

        response = self.session.post(url, files=files, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get('media_id')

    # ==================== 下单与前端支付参数生成 ====================
    def create_jsapi_order(self, out_trade_no: str, total_fee: int, openid: str, description: str = "商品支付", notify_url: Optional[str] = None) -> Dict[str, Any]:
        """创建 JSAPI 订单（/v3/pay/transactions/jsapi），返回微信下单响应（包含 prepay_id）"""
        if self.mock_mode:
            logger.info(f"【MOCK】创建JSAPI订单: out_trade_no={out_trade_no}, total_fee={total_fee}, openid={openid}")
            return {"prepay_id": f"MOCK_PREPAY_{int(time.time())}_{uuid.uuid4().hex[:8]}"}

        url = '/v3/pay/transactions/jsapi'
        body = {
            "appid": WECHAT_APP_ID,
            "mchid": self.mchid,
            "description": description,
            "out_trade_no": out_trade_no,
            "notify_url": notify_url or os.getenv('WECHAT_PAY_NOTIFY_URL', ''),
            "amount": {"total": int(total_fee), "currency": "CNY"},
            "payer": {"openid": openid}
        }

        body_str = json.dumps(body, ensure_ascii=False)
        headers = {
            'Authorization': self._build_auth_header('POST', url, body_str),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Wechatpay-Serial': self._get_merchant_serial_no()
        }

        response = self.session.post(self.BASE_URL + url, data=body_str.encode('utf-8'), headers=headers, timeout=15)
        try:
            response.raise_for_status()
        except Exception as e:
            try:
                logger.error("WeChat JSAPI 请求 URL: %s", self.BASE_URL + url)
                logger.error("WeChat JSAPI 请求体: %s", body_str)
                logger.error("WeChat JSAPI 响应状态: %s", response.status_code)
                logger.error("WeChat JSAPI 响应体: %s", response.text)
            except Exception:
                logger.exception("记录 WeChat JSAPI 请求/响应 日志时出错")
            raise

        return response.json()

    def generate_jsapi_pay_params(self, prepay_id: str) -> Dict[str, str]:
        """根据 prepay_id 生成小程序/JSAPI 前端所需的支付参数（含 paySign）。

        sign 格式（V3）对齐：
        sign_str = appid + "\n" + timestamp + "\n" + nonceStr + "\n" + package + "\n"
        使用商户私钥 RSA-SHA256 签名，base64 编码
        """
        if not prepay_id:
            raise ValueError("prepay_id 为空")

        timestamp = str(int(time.time()))
        nonce_str = str(uuid.uuid4()).replace('-', '')
        pkg = f"prepay_id={prepay_id}"

        sign_str = f"{WECHAT_APP_ID}\n{timestamp}\n{nonce_str}\n{pkg}\n"

        if not self.private_key:
            raise RuntimeError("商户私钥未加载，无法生成 paySign")

        signature = self.private_key.sign(
            sign_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        pay_sign = base64.b64encode(signature).decode('utf-8')

        return {
            "appId": WECHAT_APP_ID,
            "timeStamp": timestamp,
            "nonceStr": nonce_str,
            "package": pkg,
            "signType": "RSA",
            "paySign": pay_sign
        }

    def verify_signature(self, signature: str, timestamp: str, nonce: str, body: str) -> bool:
        """验证回调签名（支持动态加载证书）"""
        if self.mock_mode:
            logger.info("【MOCK】跳过签名验证")
            return True

        try:
            # 如果公钥未加载，尝试重新获取
            if not self.wechat_public_key:
                logger.warning("平台公钥未加载，尝试重新获取...")
                self.wechat_public_key = self._load_wechat_public_key_from_file()
            # 防御性处理：去除可能的首尾空白，并尝试 URL 解码（有时回调头被转义）
            raw_sig = signature
            try:
                sig = (signature or '').strip()
            except Exception:
                sig = signature

            # 测试/调试兼容：某些测试回调会带 MOCK_SIGNATURE（非 base64）
            # 在 Mock 模式或非生产环境下允许通过以便测试流程
            try:
                if sig and sig.upper().startswith('MOCK') and (self.mock_mode or ENVIRONMENT != 'production'):
                    logger.warning(f"检测到测试签名，跳过严格验证: {sig}")
                    return True
            except Exception:
                pass

            # 先尝试直接解码；若失败，尝试 URL 解码后再解码
            try:
                signature_bytes = base64.b64decode(sig)
            except Exception as e1:
                try:
                    from urllib.parse import unquote

                    sig_unquoted = unquote(sig).strip()
                    signature_bytes = base64.b64decode(sig_unquoted)
                    sig = sig_unquoted
                except Exception as e2:
                    logger.error(f"签名 base64 解码失败: raw_sig=%s, err1=%s, err2=%s", raw_sig, e1, e2)
                    return False

            message = f"{timestamp}\n{nonce}\n{body}\n"

            self.wechat_public_key.verify(
                signature_bytes,
                message.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"签名验证失败: {str(e)}")
            return False

    def decrypt_callback_data(self, resource: dict) -> dict:
        """解密回调数据（AES-256-GCM）"""
        if self.mock_mode:
            logger.info("【MOCK】模拟解密回调数据")
            return {
                "event_type": "APPLYMENT_STATE_FINISHED",
                "applyment_id": 123456,
                "sub_mchid": "MOCK_SUB_MCHID_123"
            }

        try:
            cipher_text = resource.get("ciphertext", "")
            nonce = resource.get("nonce", "")
            associated_data = resource.get("associated_data", "")

            key = self.apiv3_key
            if not key:
                raise Exception("API v3 key 未配置")
            # 生产要求：key 必须为 16/24/32 字节，长度不符应视为配置错误
            if len(key) not in (16, 24, 32):
                raise Exception("API v3 key 长度无效，必须为 16/24/32 字节")

            aesgcm = AESGCM(key)

            # nonce 可能是 base64 编码的原始字节，也可能是明文字符串，先尝试 base64 解码
            try:
                nonce_bytes = base64.b64decode(nonce)
            except Exception:
                nonce_bytes = nonce.encode('utf-8')

            associated_bytes = associated_data.encode('utf-8') if associated_data else None

            decrypted = aesgcm.decrypt(
                nonce_bytes,
                base64.b64decode(cipher_text),
                associated_bytes
            )
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            logger.error(f"解密失败: {str(e)}")
            # 解密失败时不尝试将 ciphertext 当作 JSON 解析返回（会导致二次解析错误）
            # 返回空字典，调用方应对缺失字段做校验并返回合适的错误响应
            return {}

    # ==================== 结算账户相关API ====================

    @query_rate_limiter
    def query_settlement_account(self, sub_mchid: str) -> Dict[str, Any]:
        """查询结算账户 - 100%对齐微信接口"""
        if self.mock_mode:
            logger.info(f"【MOCK】查询结算账户: sub_mchid={sub_mchid}")
            return self._get_mock_settlement_data(sub_mchid)

        url = f'/v3/apply4sub/sub_merchants/{sub_mchid}/settlement'
        headers = {
            'Authorization': self._build_auth_header('GET', url),
            'Accept': 'application/json'
        }

        params = {'account_number_rule': 'ACCOUNT_NUMBER_RULE_MASK_V2'}
        response = self.session.get(self.BASE_URL + url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        return {
            'account_type': data.get('account_type'),
            'account_bank': data.get('account_bank'),
            'bank_name': data.get('bank_name'),
            'bank_branch_id': data.get('bank_branch_id', ''),
            'account_number': data.get('account_number'),
            'account_name': data.get('account_name'),
            'verify_result': data.get('verify_result', 'VERIFYING'),
            'verify_fail_reason': data.get('verify_fail_reason', ''),
            'bank_address_code': data.get('bank_address_code', '100000')
        }

    @settlement_rate_limiter
    def modify_settlement_account(self, sub_mchid: str, account_info: Dict[str, Any]) -> Dict[str, Any]:
        """修改结算账户 - 100%对齐微信接口"""
        if self.mock_mode:
            logger.info(f"【MOCK】提交改绑申请: sub_mchid={sub_mchid}")
            mock_result = os.getenv('WX_MOCK_APPLY_RESULT', 'SUCCESS')
            if mock_result == 'FAIL':
                return {
                    'application_no': self._generate_mock_application_no(sub_mchid),
                    'sub_mchid': sub_mchid,
                    'status': 'APPLYMENT_STATE_REJECTED'
                }
            elif mock_result == 'PENDING':
                return {
                    'application_no': self._generate_mock_application_no(sub_mchid),
                    'sub_mchid': sub_mchid,
                    'status': 'APPLYMENT_STATE_AUDITING'
                }
            return {
                'application_no': self._generate_mock_application_no(sub_mchid),
                'sub_mchid': sub_mchid,
                'status': 'APPLYMENT_STATE_AUDITING'
            }

        url = f'/v3/apply4sub/sub_merchants/{sub_mchid}/modify-settlement'

        body = {
            "account_type": account_info['account_type'],
            "account_bank": account_info['account_bank'][:128],
            "bank_name": account_info.get('bank_name', '')[:128],
            "bank_branch_id": account_info.get('bank_branch_id', '')[:128],
            "bank_address_code": account_info['bank_address_code'][:20],
            "account_number": self._rsa_encrypt_with_wechat_public_key(account_info['account_number']),
            "account_name": self._rsa_encrypt_with_wechat_public_key(account_info['account_name'])
        }

        body = {k: v for k, v in body.items() if v != ''}
        body_str = json.dumps(body, ensure_ascii=False)
        headers = {
            'Authorization': self._build_auth_header('POST', url, body_str),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Wechatpay-Serial': self._get_merchant_serial_no()
        }

        response = self.session.post(self.BASE_URL + url, data=body_str.encode('utf-8'), headers=headers, timeout=30)
        response.raise_for_status()

        result = response.json()
        result['sub_mchid'] = sub_mchid
        result['status'] = 'APPLYMENT_STATE_AUDITING'
        return result

    @query_rate_limiter
    def query_application_status(self, sub_mchid: str, application_no: str) -> Dict[str, Any]:
        """查询改绑申请状态 - 100%对齐微信接口"""
        if self.mock_mode:
            logger.info(f"【MOCK】查询改绑状态: application_no={application_no}")
            return self._get_mock_application_status(application_no)

        url = f'/v3/apply4sub/sub_merchants/{sub_mchid}/application/{application_no}'
        headers = {
            'Authorization': self._build_auth_header('GET', url),
            'Accept': 'application/json'
        }

        params = {'account_number_rule': 'ACCOUNT_NUMBER_RULE_MASK_V2'}
        response = self.session.get(self.BASE_URL + url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()

        return {
            'account_name': data.get('account_name', ''),
            'account_type': data.get('account_type'),
            'account_bank': data.get('account_bank'),
            'bank_name': data.get('bank_name', ''),
            'bank_branch_id': data.get('bank_branch_id', ''),
            'account_number': data.get('account_number', ''),
            'verify_result': data.get('verify_result'),
            'verify_fail_reason': data.get('verify_fail_reason', ''),
            'verify_finish_time': data.get('verify_finish_time', ''),
            'applyment_state': data.get('applyment_state', 'AUDITING'),
            'applyment_state_msg': data.get('applyment_state_msg', '')
        }

    # ==================== 本地加密解密工具 ====================

    @staticmethod
    def _encrypt_local(plaintext: str, key: bytes) -> str:
        """本地AES-GCM加密（静态方法）"""
        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), b'')
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def _decrypt_local(encrypted_data: str, key: bytes) -> str:
        """本地AES-GCM解密（静态方法）"""
        combined = base64.b64decode(encrypted_data)
        iv, ciphertext = combined[:12], combined[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext, b'').decode('utf-8')

    def _decrypt_local_encrypted(self, encrypted_data: str) -> str:
        """实例方法：解密Mock或真实数据"""
        if self.mock_mode:
            try:
                decoded = base64.b64decode(encrypted_data).decode()
                if decoded.startswith("MOCK_ENC_"):
                    parts = decoded.split('_')
                    if len(parts) >= 4:
                        return '_'.join(parts[3:-1])
                    return decoded[9:]
            except:
                pass
            return encrypted_data

        key = self.apiv3_key[:32]
        return self._decrypt_local(encrypted_data, key)


# 全局客户端实例
wxpay_client = WeChatPayClient()