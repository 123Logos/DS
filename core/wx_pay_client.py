# core/wx_pay_client.py
# ...（保持原有imports）
import os
import hashlib
import time
import uuid
import base64
import json
import datetime
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests

from core.config import (
    WECHAT_PAY_MCH_ID, WECHAT_PAY_API_V3_KEY,
    WECHAT_PAY_API_CERT_PATH, WECHAT_PAY_API_KEY_PATH,
    WECHAT_PAY_PLATFORM_CERT_PATH, WECHAT_APP_ID, WECHAT_APP_SECRET,
    ENVIRONMENT  # 新增：环境标识
)
from core.database import get_conn
from core.logging import get_logger
from core.rate_limiter import settlement_rate_limiter, query_rate_limiter

logger = get_logger(__name__)


class WeChatPayClient:
    """微信支付V3 API客户端（生产级，支持无缝Mock切换）"""

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
        # ✅ Mock模式开关（生产环境强制禁止）
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
        self.platform_cert_path = WECHAT_PAY_PLATFORM_CERT_PATH

        # 初始化连接池
        self.session = requests.Session()
        self.session.mount('https://', requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=3
        ))

        # Mock模式下不强制加载证书
        self.private_key = self._load_private_key()
        self.wechat_public_key = self._load_wechat_public_key()
        self._cached_serial_no = None

        # 初始化Mock测试数据
        if self.mock_mode:
            self._ensure_mock_applyment_exists()

    # ==================== Mock数据生成（增强版） ====================

    def _ensure_mock_applyment_exists(self):
        """确保Mock模式下有测试用的进件记录（环境隔离）"""
        if not self.mock_mode:
            return

        if ENVIRONMENT == 'production':
            logger.error("Mock模式在生产环境被调用，已阻止")
            return

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 使用负数user_id避免冲突
                    cur.execute("""
                        SELECT user_id FROM wx_applyment 
                        WHERE user_id = -1 AND applyment_state = 'APPLYMENT_STATE_FINISHED'
                    """)
                    if not cur.fetchone():
                        # 插入完整的Mock数据
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
        """生成模拟的申请单号（包含时间戳和随机码）"""
        timestamp = int(time.time())
        random_code = hashlib.md5(f"{sub_mchid}{timestamp}{uuid.uuid4()}".encode()).hexdigest()[:8]
        return f"MOCK_APP_{timestamp}_{sub_mchid}_{random_code}"

    def _get_mock_settlement_data(self, sub_mchid: str) -> Dict[str, Any]:
        """模拟微信结算账户查询返回 - 100%对齐真实接口"""
        logger.info(f"【MOCK】查询结算账户: sub_mchid={sub_mchid}")

        # 从配置读取Mock行为
        mock_behavior = os.getenv('WX_MOCK_SETTLEMENT_BEHAVIOR', 'normal')  # normal | fail | verifying

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

        # 尝试从数据库读取真实数据（如果存在）
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT account_bank, bank_name, 
                               account_number_encrypted, account_name_encrypted,
                               bank_address_code, bank_branch_id
                        FROM merchant_settlement_accounts
                        WHERE sub_mchid = %s AND status = 1
                        ORDER BY updated_at DESC
                        LIMIT 1
                        """,
                        (sub_mchid,)
                    )
                    record = cur.fetchone()
                    if record:
                        try:
                            full_number = self._decrypt_local_encrypted(record['account_number_encrypted'])
                            # 使用微信掩码格式：前6位 + * + 后4位
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
        """模拟微信申请状态查询 - 支持配置化行为"""
        try:
            # 解析时间戳判断是否超时
            parts = application_no.split('_')
            if len(parts) >= 3 and parts[2].isdigit():
                app_time = int(parts[2])
                elapsed = time.time() - app_time
            else:
                elapsed = 999
        except:
            elapsed = 999

        # 读取Mock配置
        mock_result = os.getenv('WX_MOCK_APPLY_RESULT', 'SUCCESS')  # SUCCESS | FAIL | PENDING

        if mock_result == 'PENDING' or elapsed < 5:
            return {
                'applyment_state': 'APPLYMENT_STATE_AUDITING',
                'applyment_state_msg': '审核中，请稍后...',
                'account_name': '张*',  # 增加更多字段
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

    # ==================== 证书加载（保持不变） ====================

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

    def _load_wechat_public_key(self):
        """加载微信支付平台公钥"""
        try:
            with open(self.platform_cert_path, 'rb') as f:
                return serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        except Exception as e:
            logger.warning(f"加载微信支付平台公钥失败: {e}")
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
                cert = serialization.load_pem_x509_certificate(
                    f.read(),
                    backend=default_backend()
                )
                self._cached_serial_no = format(cert.serial_number, 'x').upper()
                return self._cached_serial_no
        except Exception as e:
            logger.error(f"获取商户证书序列号失败: {e}")
            self._cached_serial_no = self.mchid
            return self._cached_serial_no

    # ==================== 加密与签名（保持不变） ====================

    def _rsa_encrypt_with_wechat_public_key(self, plaintext: str) -> str:
        """使用微信支付平台公钥加密（用于敏感数据）"""
        if self.mock_mode:
            # Mock模式下返回模拟加密串，格式：MOCK_ENC_{时间戳}_{原文}_{随机码}
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

    def _sign(self, method: str, url: str, timestamp: str, nonce_str: str, body: str = '') -> str:
        """RSA-SHA256签名"""
        if self.mock_mode:
            # 生成模拟签名
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

        auth_str = f'mchid="{self.mchid}",serial_no="{serial_no}",nonce_str="{nonce_str}",timestamp="{timestamp}",signature="{signature}"'
        return f'WECHATPAY2-SHA256-RSA2048 {auth_str}'

    # ==================== 进件相关API（保持不变） ====================

    @settlement_rate_limiter
    def submit_applyment(self, applyment_data: Dict[str, Any]) -> Dict[str, Any]:
        """提交进件申请"""
        if self.mock_mode:
            logger.info("【MOCK】模拟提交进件申请")
            # 模拟生成sub_mchid
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

    def verify_signature(self, signature: str, timestamp: str, nonce: str, body: str) -> bool:
        """验证回调签名"""
        if self.mock_mode:
            logger.info("【MOCK】跳过签名验证")
            return True

        try:
            if not os.path.exists(self.platform_cert_path):
                logger.warning("微信支付平台证书不存在，跳过验签")
                return True

            with open(self.platform_cert_path, 'rb') as f:
                platform_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )

            message = f"{timestamp}\n{nonce}\n{body}\n"
            signature_bytes = base64.b64decode(signature)

            platform_key.verify(
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
            # 返回模拟数据
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
            aesgcm = AESGCM(key)

            decrypted = aesgcm.decrypt(
                nonce.encode('utf-8'),
                base64.b64decode(cipher_text),
                associated_data.encode('utf-8')
            )
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            logger.error(f"解密失败: {str(e)}")
            return json.loads(resource.get("ciphertext", "{}"))

    # ==================== 结算账户相关API（核心功能） ====================

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

        # 请求参数：account_number_rule 可选
        params = {
            'account_number_rule': 'ACCOUNT_NUMBER_RULE_MASK_V2'  # 使用v2格式：前6位+后4位
        }

        response = self.session.get(self.BASE_URL + url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        # 确保返回数据的完整性
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

            # 模拟随机失败（可配置）
            mock_result = os.getenv('WX_MOCK_APPLY_RESULT', 'SUCCESS')  # SUCCESS | FAIL | PENDING
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

        # 构建请求体（严格对齐微信文档）
        body = {
            "account_type": account_info['account_type'],
            "account_bank": account_info['account_bank'][:128],
            "bank_name": account_info.get('bank_name', '')[:128],
            "bank_branch_id": account_info.get('bank_branch_id', '')[:128],
            "bank_address_code": account_info['bank_address_code'][:20],
            "account_number": self._rsa_encrypt_with_wechat_public_key(account_info['account_number']),
            "account_name": self._rsa_encrypt_with_wechat_public_key(account_info['account_name'])
        }

        # 过滤空值字段（微信要求）
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

        # 微信返回：{"application_no":"xxx"}
        result = response.json()
        result['sub_mchid'] = sub_mchid
        result['status'] = 'APPLYMENT_STATE_AUDITING'  # 提交后初始状态
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

        # 请求参数：account_number_rule 可选
        params = {
            'account_number_rule': 'ACCOUNT_NUMBER_RULE_MASK_V2'
        }

        response = self.session.get(self.BASE_URL + url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()

        # 确保字段完整性（对齐微信文档）
        return {
            'account_name': data.get('account_name', ''),
            'account_type': data.get('account_type'),
            'account_bank': data.get('account_bank'),
            'bank_name': data.get('bank_name', ''),
            'bank_branch_id': data.get('bank_branch_id', ''),
            'account_number': data.get('account_number', ''),
            'verify_result': data.get('verify_result'),  # AUDIT_SUCCESS | AUDITING | AUDIT_FAIL
            'verify_fail_reason': data.get('verify_fail_reason', ''),
            'verify_finish_time': data.get('verify_finish_time', ''),
            'applyment_state': data.get('applyment_state', 'AUDITING'),
            'applyment_state_msg': data.get('applyment_state_msg', '')
        }

    # ==================== 本地加密解密工具（保持不变） ====================

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
            # 解密Mock格式
            try:
                decoded = base64.b64decode(encrypted_data).decode()
                if decoded.startswith("MOCK_ENC_"):
                    # 格式：MOCK_ENC_{timestamp}_{plaintext}_{random}
                    parts = decoded.split('_')
                    if len(parts) >= 4:
                        return '_'.join(parts[3:-1])  # 还原原文（处理原文含下划线的情况）
                    return decoded[9:]  # 兼容旧格式
            except:
                pass
            return encrypted_data  # 解密失败返回原文

        # 真实模式使用静态方法
        key = self.apiv3_key[:32]
        return self._decrypt_local(encrypted_data, key)


# 全局客户端实例
wxpay_client = WeChatPayClient()