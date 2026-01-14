# core/wx_pay_client.py
# 微信支付V3 API客户端（公钥ID模式 - 本地文件加载版）

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
    """微信支付V3 API客户端（公钥ID模式 - 纯本地加载）"""

    BASE_URL = "https://api.mch.weixin.qq.com"

    def __init__(self):
        # Mock模式开关
        self.mock_mode = os.getenv('WX_MOCK_MODE', 'false').lower() == 'true'
        if self.mock_mode:
            logger.warning("⚠️ 【MOCK模式】已启用，所有接口调用均为模拟！")

        # 商户基础配置（用于签名）
        self.mchid = WECHAT_PAY_MCH_ID
        self.apiv3_key = WECHAT_PAY_API_V3_KEY.encode('utf-8')
        self.cert_path = WECHAT_PAY_API_CERT_PATH
        self.key_path = WECHAT_PAY_API_KEY_PATH

        # 公钥ID配置（2024年后必填）
        self.pub_key_id = WECHAT_PAY_PUB_KEY_ID

        # 加载密钥
        self.private_key = self._load_private_key()
        self.wechat_public_key = self._load_wechat_public_key_from_file()

        # Mock初始化
        if self.mock_mode:
            self._ensure_mock_applyment_exists()

    # ==================== 微信支付公钥加载（核心） ====================

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
                            "subject_info": {"business_license_info": {"license_number": "MOCK_LICENSE_123456"}},
                            "contact_info": {"contact_name": "Mock用户"},
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
                        logger.info("Mock模式：已创建测试进件记录")
        except Exception as e:
            logger.debug(f"Mock初始化失败: {e}")

    # ==================== 商户证书加载 ====================

    def _load_private_key(self):
        """加载商户私钥（用于请求签名）"""
        try:
            with open(self.key_path, 'rb') as f:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception as e:
            logger.error(f"加载商户私钥失败: {e}")
            if not self.mock_mode:
                raise
            return None

    def _get_merchant_serial_no(self) -> str:
        """获取商户API证书序列号"""
        if self.mock_mode:
            return "MOCK_SERIAL_NO"

        with open(self.cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            serial_no = format(cert.serial_number, 'x').upper()
            logger.info(f"商户证书序列号: {serial_no}")
            return serial_no

    # ==================== 加密与签名 ====================

    def _rsa_encrypt_with_wechat_public_key(self, plaintext: str) -> str:
        """使用微信支付公钥加密"""
        if self.mock_mode:
            timestamp = int(time.time())
            mock_enc = f"MOCK_ENC_{timestamp}_{plaintext}_{uuid.uuid4().hex[:6]}"
            return base64.b64encode(mock_enc.encode()).decode()

        if not self.wechat_public_key:
            raise Exception("微信支付公钥未加载")

        ciphertext = self.wechat_public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')

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
        """构建Authorization请求头"""
        timestamp = str(int(time.time()))
        nonce_str = str(uuid.uuid4()).replace('-', '')
        signature = self._sign(method, url, timestamp, nonce_str, body)
        serial_no = self._get_merchant_serial_no()

        auth_params = [
            f'mchid="{self.mchid}"',
            f'serial_no="{serial_no}"',
            f'nonce_str="{nonce_str}"',
            f'timestamp="{timestamp}"',
            f'signature="{signature}"'
        ]
        return f'WECHATPAY2-SHA256-RSA2048 {",".join(auth_params)}'

    # ==================== 进件相关API ====================

    @settlement_rate_limiter
    def submit_applyment(self, applyment_data: Dict[str, Any]) -> Dict[str, Any]:
        """提交进件申请"""
        if self.mock_mode:
            logger.info("【MOCK】提交进件")
            return {
                "applyment_id": int(time.time() * 1000),
                "state_msg": "提交成功",
                "sub_mchid": f"MOCK_SUB_MCHID_{uuid.uuid4().hex[:8].upper()}"
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
            return {
                "applyment_state": "APPLYMENT_STATE_FINISHED",
                "applyment_state_msg": "审核通过",
                "sub_mchid": "MOCK_SUB_MCHID_123"
            }

        url = f"{self.BASE_URL}/v3/applyment4sub/applyment/applyment_id/{applyment_id}"
        headers = {
            'Authorization': self._build_auth_header('GET', url),
            'Accept': 'application/json'
        }

        response = self.session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    # ==================== 结算账户相关API ====================

    @query_rate_limiter
    def query_settlement_account(self, sub_mchid: str) -> Dict[str, Any]:
        """查询结算账户"""
        if self.mock_mode:
            return {
                'account_type': 'ACCOUNT_TYPE_PRIVATE',
                'account_bank': '工商银行',
                'account_number': '62*************78',
                'verify_result': 'VERIFY_SUCCESS'
            }

        url = f'/v3/apply4sub/sub_merchants/{sub_mchid}/settlement'
        headers = {
            'Authorization': self._build_auth_header('GET', url),
            'Accept': 'application/json'
        }

        response = self.session.get(self.BASE_URL + url, headers=headers, timeout=10)
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
        """修改结算账户"""
        if self.mock_mode:
            return {
                'application_no': f"MOCK_APP_{int(time.time())}",
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
        """查询改绑申请状态"""
        if self.mock_mode:
            return {
                'applyment_state': 'APPLYMENT_STATE_FINISHED',
                'applyment_state_msg': '审核通过',
                'account_number': '62*************78'
            }

        url = f'/v3/apply4sub/sub_merchants/{sub_mchid}/application/{application_no}'
        headers = {
            'Authorization': self._build_auth_header('GET', url),
            'Accept': 'application/json'
        }

        response = self.session.get(self.BASE_URL + url, headers=headers, timeout=30)
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
        """本地AES-GCM加密"""
        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), b'')
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def _decrypt_local(encrypted_data: str, key: bytes) -> str:
        """本地AES-GCM解密"""
        combined = base64.b64decode(encrypted_data)
        iv, ciphertext = combined[:12], combined[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext, b'').decode('utf-8')


# 全局客户端实例
wxpay_client = WeChatPayClient()