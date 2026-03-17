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
    WECHAT_APP_ID, WECHAT_APP_SECRET, ENVIRONMENT,
    WX_SETTLE_RULE_ID
)
from core.database import get_conn
from core.logging import get_logger
from core.rate_limiter import settlement_rate_limiter, query_rate_limiter
from core.config import WECHAT_PAY_SP_MCH_ID

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
        # ✅ 使用 settings.wx_mock_mode_bool，确保正确解析
        try:
            from core.config import settings
            self.mock_mode = settings.wx_mock_mode_bool
            logger.info(f"【WeChatPayClient】WX_MOCK_MODE={settings.WX_MOCK_MODE} -> {self.mock_mode}")
        except Exception as e:
            # 回退到 os.getenv
            self.mock_mode = os.getenv('WX_MOCK_MODE', 'false').lower() == 'true'
            logger.warning(f"【WeChatPayClient】使用os.getenv回退: {self.mock_mode}, error: {e}")

        # 安全：生产环境禁止Mock
        if self.mock_mode and ENVIRONMENT == 'production':
            raise RuntimeError("❌ 生产环境禁止启用微信Mock模式")

        if self.mock_mode:
            logger.warning("⚠️ 【MOCK模式】已启用，所有微信接口调用均为模拟！")
            logger.warning("⚠️ 当前环境: {}".format(ENVIRONMENT))
        else:
            logger.warning("⚠️ 【MOCK模式】未启用，将调用真实微信接口！")

        # 商户配置（所有模式都需要基础配置）
        self.mchid = WECHAT_PAY_MCH_ID
        self.apiv3_key = WECHAT_PAY_API_V3_KEY.encode('utf-8') if WECHAT_PAY_API_V3_KEY else b''
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

        # ✅ 修复：Mock模式下跳过密钥加载，避免证书不存在报错
        if self.mock_mode:
            self.private_key = None
            self.wechat_public_key = None
            logger.info("🟡 Mock模式：跳过证书和密钥加载")
            # ✅ 修复：只在这里调用一次 Mock 数据初始化
            self._ensure_mock_applyment_exists()
        else:
            # 非Mock模式：加载真实密钥和公钥
            self.private_key = self._load_private_key()
            self.wechat_public_key = self._load_wechat_public_key_from_file()

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

    def _build_auth_header(self, method: str, url: str, body: str = '', mchid: str = None) -> str:
        """构建 Authorization 请求头（严格对齐微信规范）

        Args:
            method: HTTP 方法
            url: 请求路径
            body: 请求体
            mchid: 商户号（可选，默认使用初始化时的商户号）
                  在服务商模式下，应传入服务商商户号（SP_MCH_ID）
        """
        timestamp = str(int(time.time()))
        nonce_str = str(uuid.uuid4()).replace('-', '')
        signature = self._sign(method, url, timestamp, nonce_str, body)

        # 使用传入的商户号，或默认使用初始化时的商户号
        use_mchid = mchid or self.mchid

        # 参数值中的双引号需要转义，且格式严格对齐
        auth_params = [
            f'mchid="{use_mchid}"',
            f'serial_no="{self._get_merchant_serial_no()}"',
            f'nonce_str="{nonce_str}"',
            f'timestamp="{timestamp}"',
            f'signature="{signature}"'
        ]
        auth_str = ','.join(auth_params)
        return f'WECHATPAY2-SHA256-RSA2048 {auth_str}'

    # ==================== 进件相关API ====================

    @settlement_rate_limiter
    def submit_applyment(self, applyment_data: Dict[str, Any], is_sub_merchant: bool = True) -> Dict[str, Any]:
        """
        提交进件申请
        - is_sub_merchant=True: 作为二级子商户进件（使用服务商模式，需要platform_appid）
        - is_sub_merchant=False: 作为普通商户进件（兼容旧逻辑）
        """
        if self.mock_mode:
            logger.info("【MOCK】模拟提交进件申请")
            sub_mchid = f"MOCK_SUB_MCHID_{uuid.uuid4().hex[:8].upper()}"
            return {
                "applyment_id": int(time.time() * 1000),
                "state_msg": "提交成功",
                "sub_mchid": sub_mchid
            }

        # ✅ 使用路径构建签名（符合微信规范）
        url_path = "/v3/applyment4sub/applyment/"
        full_url = f"{self.BASE_URL}{url_path}"

        # ✅ 修复：安全解析 JSON 字段（处理已经是 dict 的情况）
        def safe_json_loads(data):
            if isinstance(data, str):
                return json.loads(data)
            return data or {}

        # ✅ 修复：解析所有 JSON 字段
        subject_info = safe_json_loads(applyment_data.get("subject_info", {}))
        contact_info = safe_json_loads(applyment_data.get("contact_info", {}))
        bank_account_info = safe_json_loads(applyment_data.get("bank_account_info", {}))
        business_info = safe_json_loads(applyment_data.get("business_info", {}))

        # ✅ 补齐 subject_type（微信必填字段），从表字段或已有值回填
        subject_type = applyment_data.get("subject_type") or subject_info.get("subject_type")
        subject_info["subject_type"] = subject_type or "SUBJECT_TYPE_INDIVIDUAL"

        # ✅ 规整 identity_info.id_holder_type，微信只接受合法枚举
        identity_info = subject_info.get("identity_info", {}) or {}
        if isinstance(identity_info, str):
            try:
                identity_info = json.loads(identity_info)
            except Exception:
                identity_info = {}

        id_holder_type = identity_info.get("id_holder_type")
        allowed_id_holder_types = {"LEGAL", "SUPER"}

        # 微信要求个体/企业不传 id_holder_type，避免触发枚举校验
        if subject_type in {"SUBJECT_TYPE_INDIVIDUAL", "SUBJECT_TYPE_ENTERPRISE"}:
            identity_info.pop("id_holder_type", None)
        elif id_holder_type and id_holder_type not in allowed_id_holder_types:
            # 对其他主体仅接受官方枚举，非法值回落为 LEGAL
            identity_info["id_holder_type"] = "LEGAL"

        # ✅ 加密并回填身份证信息（姓名、号码、介质media_id）
        id_card_info = identity_info.get("id_card_info") or {}

        raw_id_card_name = identity_info.get("id_card_name") or subject_info.get("name")
        raw_id_card_number = identity_info.get("id_card_number") or subject_info.get("id_number")

        if raw_id_card_name:
            try:
                id_card_info["id_card_name"] = self.encrypt_sensitive_data(str(raw_id_card_name))
            except Exception:
                logger.warning("身份证姓名加密失败，原文将被丢弃以避免提交非法值")

        if raw_id_card_number:
            try:
                id_card_info["id_card_number"] = self.encrypt_sensitive_data(str(raw_id_card_number))
            except Exception:
                logger.warning("身份证号码加密失败，原文将被丢弃以避免提交非法值")

        # 回填身份证有效期（不加密），优先使用 id_card_info 现有值，再回退主体/身份信息
        raw_card_period_begin = (
                id_card_info.get("card_period_begin")
                or identity_info.get("card_period_begin")
                or subject_info.get("card_period_begin")
        )
        raw_card_period_end = (
                id_card_info.get("card_period_end")
                or identity_info.get("card_period_end")
                or subject_info.get("card_period_end")
        )

        if raw_card_period_begin:
            id_card_info["card_period_begin"] = str(raw_card_period_begin)
        if raw_card_period_end:
            id_card_info["card_period_end"] = str(raw_card_period_end)

        if id_card_info:
            identity_info["id_card_info"] = id_card_info

        # 移除未加密的明文字段，避免被微信校验为空或非法
        identity_info.pop("id_card_name", None)
        identity_info.pop("id_card_number", None)

        # 调试日志：确认身份证信息关键字段是否存在（已加密，不含明文）
        log_id_card_info = identity_info.get("id_card_info", {})
        logger.info(
            "【submit_applyment】id_card_info keys=%s, card_period_begin=%s, card_period_end=%s",
            list(log_id_card_info.keys()),
            log_id_card_info.get("card_period_begin"),
            log_id_card_info.get("card_period_end"),
        )

        # 写回 subject_info，确保清洗生效
        subject_info["identity_info"] = identity_info

        # ✅ 修复：构建 business_info（必需字段），优先使用前端/DB传入
        if not business_info:
            business_info = subject_info.get("business_info", {}) or {}

        # 保证必填的 merchant_shortname 与 service_phone 不为空
        if not business_info.get("merchant_shortname"):
            business_info["merchant_shortname"] = subject_info.get("merchant_shortname") or subject_info.get(
                "name") or subject_info.get("business_name") or ""
        if not business_info.get("service_phone"):
            business_info["service_phone"] = contact_info.get("mobile") or contact_info.get(
                "mobile_phone") or contact_info.get("service_phone") or ""

        # 兜底业务类目
        if not business_info.get("business_category"):
            business_info["business_category"] = subject_info.get("business_category", [])

        # ✅ 确保 business_category 是数组
        if isinstance(business_info.get("business_category"), str):
            business_info["business_category"] = [business_info["business_category"]]
        elif not business_info.get("business_category"):
            business_info["business_category"] = []

        # ✅ 构建完整请求体
        payload = {
            "business_code": applyment_data["business_code"],
            "contact_info": contact_info,
            "subject_info": subject_info,
            "bank_account_info": bank_account_info,
            "business_info": business_info,  # ✅ 添加必需字段
            "settlement_info": {"settle_rule_id": WX_SETTLE_RULE_ID}  # ✅ 添加结算规则（微信必填）
        }

        # ✅ 关键修改：二级子商户进件需要添加 platform_appid（服务商模式）
        if is_sub_merchant:
            from core.config import WECHAT_PAY_SP_APPID
            if WECHAT_PAY_SP_APPID:
                payload["platform_appid"] = WECHAT_PAY_SP_APPID
                logger.info(f"【submit_applyment】使用服务商模式进件，platform_appid={WECHAT_PAY_SP_APPID}")
            else:
                logger.warning("【submit_applyment】未配置服务商APPID，将作为普通商户进件")

        # ✅ 修复：清理空值和敏感数据（微信 API 对空字符串敏感）
        def clean_payload(obj):
            if isinstance(obj, dict):
                cleaned = {}
                for k, v in obj.items():
                    if v is None or v == "":
                        continue
                    if isinstance(v, (dict, list)):
                        cleaned_v = clean_payload(v)
                        if cleaned_v or cleaned_v == []:  # 保留空数组
                            cleaned[k] = cleaned_v
                    else:
                        cleaned[k] = v
                return cleaned
            elif isinstance(obj, list):
                return [clean_payload(item) for item in obj if item is not None]
            return obj

        payload = clean_payload(payload)
        body_str = json.dumps(payload, ensure_ascii=False)

        headers = {
            'Authorization': self._build_auth_header('POST', url_path, body_str, mchid=WECHAT_PAY_SP_MCH_ID),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Wechatpay-Serial': self.pub_key_id or self._get_merchant_serial_no()
        }

        # ✅ 添加详细日志
        logger.info(f"【submit_applyment】请求URL: {full_url}")
        logger.info(f"【submit_applyment】使用服务商商户号: {WECHAT_PAY_SP_MCH_ID}")
        logger.info(f"【submit_applyment】请求体前500字: {body_str[:500]}...")
        logger.info(f"【submit_applyment】Wechatpay-Serial: {headers['Wechatpay-Serial']}")

        try:
            response = self.session.post(full_url, data=body_str.encode('utf-8'), headers=headers, timeout=30)

            # ✅ 添加响应日志
            logger.info(f"【submit_applyment】响应状态码: {response.status_code}")
            logger.info(f"【submit_applyment】响应内容前500字: {response.text[:500]}...")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            logger.error(f"【submit_applyment】HTTP错误: {e.response.status_code}")
            logger.error(f"【submit_applyment】错误响应: {e.response.text}")
            try:
                error_data = e.response.json()
                error_msg = error_data.get("message", error_data.get("detail", str(e)))
                raise Exception(f"微信API错误: {error_msg}")
            except json.JSONDecodeError:
                raise Exception(f"提交失败: {e.response.text}")
            except Exception as ex:
                raise Exception(f"提交失败: {str(ex)}")

    @query_rate_limiter
    def query_applyment_status(self, applyment_id: int) -> Dict[str, Any]:
        """查询进件状态"""
        if self.mock_mode:
            logger.info(f"【MOCK】查询进件状态: {applyment_id}")
            return self._get_mock_application_status(f"MOCK_{applyment_id}")

        # ✅ 使用路径构建签名
        url_path = f"/v3/applyment4sub/applyment/applyment_id/{applyment_id}"
        full_url = f"{self.BASE_URL}{url_path}"

        headers = {
            'Authorization': self._build_auth_header('GET', url_path),  # ✅ 使用路径
            'Accept': 'application/json'
        }

        response = self.session.get(full_url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    @settlement_rate_limiter
    def upload_image(self, image_content: bytes, content_type: str) -> str:
        """上传图片获取media_id - 修复版"""
        logger.info(f"【upload_image】mock_mode={self.mock_mode}, 图片大小={len(image_content)} bytes")

        if self.mock_mode:
            logger.info("【MOCK】模拟上传图片")
            mock_media_id = f"MOCK_MEDIA_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            return mock_media_id

        if not self.private_key:
            raise RuntimeError("非Mock模式下私钥未加载，请检查证书配置")

        # ✅ 使用路径构建签名（微信图片上传接口规范）
        url_path = "/v3/merchant/media/upload"
        full_url = f"{self.BASE_URL}{url_path}"

        meta = {
            "filename": "image.jpg",
            "sha256": hashlib.sha256(image_content).hexdigest()
        }

        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
        meta_json = json.dumps(meta, ensure_ascii=False)

        body_parts = []
        body_parts.append(f'--{boundary}\r\n'.encode('utf-8'))
        body_parts.append(f'Content-Disposition: form-data; name="meta"\r\n'.encode('utf-8'))
        body_parts.append(f'Content-Type: application/json\r\n\r\n'.encode('utf-8'))
        body_parts.append(meta_json.encode('utf-8'))
        body_parts.append(b'\r\n')
        body_parts.append(f'--{boundary}\r\n'.encode('utf-8'))
        body_parts.append(f'Content-Disposition: form-data; name="file"; filename="image.jpg"\r\n'.encode('utf-8'))
        body_parts.append(f'Content-Type: {content_type}\r\n\r\n'.encode('utf-8'))
        body_parts.append(image_content)
        body_parts.append(f'\r\n--{boundary}--\r\n'.encode('utf-8'))
        body = b''.join(body_parts)

        # ✅ 关键修复：使用商户证书序列号
        merchant_serial = self._get_merchant_serial_no()
        headers = {
            'Authorization': self._build_auth_header('POST', url_path, meta_json),  # ✅ 使用路径
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'Accept': 'application/json',
            'Wechatpay-Serial': merchant_serial
        }

        logger.info(f"【upload_image】调用微信接口: {full_url}")
        logger.info(f"【upload_image】商户证书序列号: {merchant_serial}")

        response = self.session.post(full_url, data=body, headers=headers, timeout=30)

        logger.info(f"【upload_image】微信响应: {response.status_code}")
        if response.status_code != 200:
            logger.error(f"【upload_image】错误响应: {response.text}")

        response.raise_for_status()
        result = response.json()
        return result.get('media_id')

    # ==================== 下单与前端支付参数生成 ====================
    def create_jsapi_order(self, out_trade_no: str, total_fee: int, openid: str, description: str = "商品支付",
                           notify_url: Optional[str] = None) -> Dict[str, Any]:
        """创建 JSAPI 订单（/v3/pay/transactions/jsapi），返回微信下单响应（包含 prepay_id）"""
        if self.mock_mode:
            logger.info(f"【MOCK】创建JSAPI订单: out_trade_no={out_trade_no}, total_fee={total_fee}, openid={openid}")
            return {"prepay_id": f"MOCK_PREPAY_{int(time.time())}_{uuid.uuid4().hex[:8]}"}

        # ✅ 使用路径构建签名
        url_path = '/v3/pay/transactions/jsapi'
        full_url = f"{self.BASE_URL}{url_path}"

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
            'Authorization': self._build_auth_header('POST', url_path, body_str),  # ✅ 使用路径
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Wechatpay-Serial': self._get_merchant_serial_no()
        }

        response = self.session.post(full_url, data=body_str.encode('utf-8'), headers=headers, timeout=15)
        try:
            response.raise_for_status()
        except Exception as e:
            try:
                logger.error("WeChat JSAPI 请求 URL: %s", full_url)
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

            # 记录密文/随机串长度与前后片段，便于排查是否被截断或改写
            try:
                def _preview(val: str) -> str:
                    if not isinstance(val, str):
                        return str(type(val))
                    if len(val) <= 80:
                        return val
                    return f"{val[:30]}...{val[-30:]}"

                logger.info(
                    "解密前检查: ct_len=%s, nonce_len=%s, ad_len=%s, ct_preview=%s",
                    len(cipher_text) if isinstance(cipher_text, str) else None,
                    len(nonce) if isinstance(nonce, str) else None,
                    len(associated_data) if isinstance(associated_data, str) else None,
                    _preview(cipher_text),
                )
            except Exception:
                logger.debug("记录解密前检查失败", exc_info=True)

            # 若收到非微信格式的测试回调（无密文或 nonce 长度异常），直接记录并返回空，避免报错刷屏
            if not cipher_text or not nonce:
                logger.warning("回调 resource 缺少 ciphertext/nonce，跳过解密")
                return {}
            if not (8 <= len(nonce) <= 128):
                logger.warning("回调 nonce 长度异常(%s)，跳过解密", len(nonce))
                return {}

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
            try:
                logger.error(
                    "解密失败: %s; ct_len=%s; nonce_len=%s; ad_len=%s; ct_preview=%s",
                    str(e),
                    len(cipher_text) if isinstance(cipher_text, str) else None,
                    len(nonce) if isinstance(nonce, str) else None,
                    len(associated_data) if isinstance(associated_data, str) else None,
                    cipher_text[:30] + "..." + cipher_text[-30:] if isinstance(cipher_text, str) and len(cipher_text) > 80 else cipher_text,
                )
            except Exception:
                logger.error(f"解密失败且记录日志时异常: {str(e)}")
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

        # ✅ 使用路径构建签名
        url_path = f'/v3/apply4sub/sub_merchants/{sub_mchid}/settlement'
        full_url = f"{self.BASE_URL}{url_path}"

        headers = {
            'Authorization': self._build_auth_header('GET', url_path),  # ✅ 使用路径
            'Accept': 'application/json'
        }

        params = {'account_number_rule': 'ACCOUNT_NUMBER_RULE_MASK_V2'}
        response = self.session.get(full_url, headers=headers, params=params, timeout=10)
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

        # ✅ 使用路径构建签名
        url_path = f'/v3/apply4sub/sub_merchants/{sub_mchid}/modify-settlement'
        full_url = f"{self.BASE_URL}{url_path}"

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
            'Authorization': self._build_auth_header('POST', url_path, body_str),  # ✅ 使用路径
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Wechatpay-Serial': self._get_merchant_serial_no()
        }

        response = self.session.post(full_url, data=body_str.encode('utf-8'), headers=headers, timeout=30)
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

        # ✅ 使用路径构建签名
        url_path = f'/v3/apply4sub/sub_merchants/{sub_mchid}/application/{application_no}'
        full_url = f"{self.BASE_URL}{url_path}"

        headers = {
            'Authorization': self._build_auth_header('GET', url_path),  # ✅ 使用路径
            'Accept': 'application/json'
        }

        params = {'account_number_rule': 'ACCOUNT_NUMBER_RULE_MASK_V2'}
        response = self.session.get(full_url, headers=headers, params=params, timeout=30)
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

    # ==================== 退款方法（调用微信支付V3退款接口） ====================
    def refund(self, transaction_id: str, out_refund_no: str, total_fee: int, refund_fee: int,
               notify_url: Optional[str] = None) -> Dict[str, Any]:
        """
        申请退款（支持部分退款）
        :param transaction_id: 微信支付订单号
        :param out_refund_no: 商户退款单号（需唯一）
        :param total_fee: 原订单总金额（分）
        :param refund_fee: 退款金额（分）
        :param notify_url: 退款结果回调地址（可选）
        :return: 微信退款接口返回的 JSON 数据
        """
        url_path = '/v3/refund/domestic/refunds'
        full_url = f"{self.BASE_URL}{url_path}"
        body = {
            "transaction_id": transaction_id,
            "out_refund_no": out_refund_no,
            "amount": {
                "refund": refund_fee,
                "total": total_fee,
                "currency": "CNY"
            }
        }
        if notify_url:
            body["notify_url"] = notify_url

        body_str = json.dumps(body, ensure_ascii=False)
        headers = {
            'Authorization': self._build_auth_header('POST', url_path, body_str),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Wechatpay-Serial': self._get_merchant_serial_no()
        }
        response = self.session.post(full_url, data=body_str.encode('utf-8'), headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()


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