# core/config.py - 统一配置管理
from decimal import Decimal
from enum import StrEnum, IntEnum
from typing import Final
import os
from dotenv import load_dotenv
from pathlib import Path
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# 加载环境变量
load_dotenv()


# ==================== 应用配置（使用 pydantic-settings） ====================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # JWT
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    ENABLE_UUID_AUTH: int = 0

    # 应用级配置
    UVICORN_PORT: int = 8000
    DRAFT_EXPIRE_DAYS: int = 7
    MAX_FILE_SIZE_MB: int = 10

    # 数据库
    MYSQL_HOST: str = "127.0.0.1"
    MYSQL_PORT: int = 3306
    MYSQL_USER: str
    MYSQL_PASSWORD: str
    MYSQL_DATABASE: str

    # 微信/支付相关
    WECHAT_APP_ID: str = ""
    WECHAT_APP_SECRET: str = ""
    WECHAT_PAY_MCH_ID: str = ""
    WECHAT_PAY_API_V3_KEY: str = ""
    WECHAT_PAY_API_CERT_PATH: str = ""
    WECHAT_PAY_API_KEY_PATH: str = ""
    WECHAT_PAY_PLATFORM_CERT_PATH: str = ""
    WECHAT_PAY_PUBLIC_KEY_PATH: str = ""
    WECHAT_PAY_NOTIFY_URL: str = ""

    WX_MCHID: str | None = None
    WX_CERT_SERIAL_NO: str = ""
    WX_APIV3_KEY: str = ""
    WX_PRIVATE_KEY_PATH: str = ""
    WX_PAY_BASE_URL: str = "https://api.mch.weixin.qq.com"
    WECHATPAY_CERT_PATH: str = ""
    WX_WECHATPAY_SERIAL: str = ""

    PUSH_TEMPLATE_ID_APPLYMENT: str = ""
    ENVIRONMENT: str = "development"

# 实例化设置
settings = Settings()

# ==================== JWT配置 ====================
JWT_SECRET_KEY: Final[str] = settings.JWT_SECRET_KEY.get_secret_value()
JWT_ALGORITHM: Final[str] = settings.JWT_ALGORITHM
JWT_EXPIRE_MINUTES: Final[int] = settings.JWT_EXPIRE_MINUTES

# 双认证开关
ENABLE_UUID_AUTH: Final[int] = settings.ENABLE_UUID_AUTH

# ==================== 应用配置 ====================
UVICORN_PORT: int = settings.UVICORN_PORT
DRAFT_EXPIRE_DAYS: int = settings.DRAFT_EXPIRE_DAYS
MAX_FILE_SIZE_MB: int = settings.MAX_FILE_SIZE_MB

# ==================== 数据库配置 ====================
def get_db_config():
    """获取数据库配置字典"""
    cfg = {
        'host': settings.MYSQL_HOST,
        'port': int(settings.MYSQL_PORT),
        'user': settings.MYSQL_USER,
        'password': settings.MYSQL_PASSWORD,
        'database': settings.MYSQL_DATABASE,
        'charset': 'utf8mb4',
    }
    missing = [k for k in ('user', 'password', 'database') if not cfg.get(k)]
    if missing:
        raise RuntimeError(f"缺少必要的数据库环境变量: {', '.join(missing)}\n")
    return cfg

# ==================== 平台常量 ====================
PLATFORM_MERCHANT_ID: Final[int] = 0
MEMBER_PRODUCT_PRICE: Final[Decimal] = Decimal('1980.00')

# ==================== 业务规则枚举 ====================
class AllocationKey(StrEnum):
    PUBLIC_WELFARE = 'public_welfare'
    PLATFORM = 'platform'
    SUBSIDY_POOL = 'subsidy_pool'
    HONOR_DIRECTOR = 'honor_director'
    COMMUNITY = 'community'
    CITY_CENTER = 'city_center'
    REGION_COMPANY = 'region_company'
    DEVELOPMENT = 'development'
    PLATFORM_REVENUE_POOL = 'platform_revenue_pool'
    COMPANY_POINTS = 'company_points'
    COMPANY_BALANCE = 'company_balance'

# ==================== 资金分配比例 ====================
ALLOCATIONS: Final[dict[AllocationKey, Decimal]] = {
    AllocationKey.PUBLIC_WELFARE: Decimal('0.01'),
    AllocationKey.PLATFORM: Decimal('0.01'),
    AllocationKey.SUBSIDY_POOL: Decimal('0.12'),
    AllocationKey.HONOR_DIRECTOR: Decimal('0.02'),
    AllocationKey.COMMUNITY: Decimal('0.01'),
    AllocationKey.CITY_CENTER: Decimal('0.01'),
    AllocationKey.REGION_COMPANY: Decimal('0.005'),
    AllocationKey.DEVELOPMENT: Decimal('0.015'),
}

# ==================== 其他业务常量 ====================
MAX_POINTS_VALUE: Final[Decimal] = Decimal('0.02')
TAX_RATE: Final[Decimal] = Decimal('0.06')
POINTS_DISCOUNT_RATE: Final[Decimal] = Decimal('1.0')
COUPON_VALID_DAYS: Final[int] = 30
MAX_PURCHASE_PER_DAY: Final[int] = 2
MAX_TEAM_LAYER: Final[int] = 6

# ==================== 用户状态 ====================
class UserStatus(IntEnum):
    NORMAL  = 0   # 恢复正常
    FROZEN  = 1   # 冻结
    DELETED = 2   # 注销

# ==================== 联创星级 ====================
class UnilevelLevel(IntEnum):
    ONE   = 1
    TWO   = 2
    THREE = 3


# ==================== 图片存储路径 ====================
# 用户头像存储在与 main.py 同一级的 `user_pic/avatars` 文件夹
BASE_PIC_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "user_pic"
AVATAR_UPLOAD_DIR: Final[Path] = BASE_PIC_DIR / "avatars"
AVATAR_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
# ==================== 奖励类型 ====================
class RewardType(StrEnum):
    REFERRAL = 'referral'
    TEAM = 'team'

class RewardStatus(StrEnum):
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'

# ==================== 优惠券类型 ====================
class CouponType(StrEnum):
    USER = 'user'
    MERCHANT = 'merchant'

class CouponStatus(StrEnum):
    UNUSED = 'unused'
    USED = 'used'
    EXPIRED = 'expired'

# ==================== 提现状态 ====================
class WithdrawalStatus(StrEnum):
    PENDING_AUTO = 'pending_auto'
    PENDING_MANUAL = 'pending_manual'
    APPROVED = 'approved'
    REJECTED = 'rejected'

# ==================== 退款状态 ====================
class RefundStatus(StrEnum):
    APPLIED = 'applied'
    SELLER_OK = 'seller_ok'
    SUCCESS = 'success'
    REJECTED = 'rejected'

# ==================== 订单状态 ====================
class OrderStatus(StrEnum):
    PENDING_PAY = 'pending_pay'
    PENDING_SHIP = 'pending_ship'
    PENDING_RECV = 'pending_recv'
    COMPLETED = 'completed'
    REFUND = 'refund'
    REFUNDED = 'refunded'

# ==================== 支付配置 ====================
VALID_PAY_WAYS: Final[set[str]] = {"alipay", "wechat", "card", "wx_pub", "wx_app","paid","pending_pay"}

# ==================== 日志配置 ====================
LOG_DIR: Final[Path] = Path(__file__).resolve().parent.parent / 'logs'
LOG_FILE: Final[Path] = LOG_DIR / 'api.log'
LOG_DIR.mkdir(exist_ok=True)

# ==================== 微信配置 ====================
WECHAT_APP_ID: Final[str] = settings.WECHAT_APP_ID
WECHAT_APP_SECRET: Final[str] = settings.WECHAT_APP_SECRET

# ==================== 商品图片配置 ====================
# 挂载静态文件目录（/pic -> pic_data）
# 将 `PIC_PATH` 指向存放商品图片的 `pic_data` 目录，保证 `/pic/<分类>/...` 能正确映射到磁盘文件
PIC_PATH: Final[Path] = Path(__file__).resolve().parent.parent / "pic_data"

# 向后兼容：Wechat_ID 字典
Wechat_ID: Final[dict] = {
    "wechat_app_id": WECHAT_APP_ID,
    "wechat_app_secret": WECHAT_APP_SECRET
}

# ==================== 商品管理配置 ====================
# 上传目录
BASE_PIC_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "pic_data"
BASE_PIC_DIR.mkdir(exist_ok=True)

# 分类白名单
CATEGORY_CHOICES: Final[list[str]] = [
    "服装鞋帽", "家居生活", "美妆护肤", "母婴用品",
    "食品饮料", "数码电器", "图书文具", "运动户外", "其他"
]

# 微信支付配置
WECHAT_PAY_MCH_ID = settings.WECHAT_PAY_MCH_ID
WECHAT_PAY_API_V3_KEY = settings.WECHAT_PAY_API_V3_KEY
WECHAT_PAY_API_CERT_PATH = settings.WECHAT_PAY_API_CERT_PATH
WECHAT_PAY_API_KEY_PATH = settings.WECHAT_PAY_API_KEY_PATH
WECHAT_PAY_PLATFORM_CERT_PATH = settings.WECHAT_PAY_PLATFORM_CERT_PATH
WECHAT_PAY_PUBLIC_KEY_PATH = settings.WECHAT_PAY_PUBLIC_KEY_PATH
WECHAT_PAY_NOTIFY_URL = settings.WECHAT_PAY_NOTIFY_URL

# 向后兼容：某些模块仍然使用 `WX_MCHID` 名称
from typing import Final
# 向后兼容：某些模块仍然使用 `WX_MCHID` 名称
from typing import Final
WX_MCHID: Final[str] = settings.WX_MCHID or WECHAT_PAY_MCH_ID

# 向后兼容：常用的 WX_* 命名，优先读取 WX_* 环境变量，否则回退到 WECHAT_PAY_*
# 向后兼容：常用的 WX_* 命名，优先读取 WX_* 环境变量，否则回退到 WECHAT_PAY_*
WX_CERT_SERIAL_NO: Final[str] = settings.WX_CERT_SERIAL_NO or ""
WX_APIV3_KEY: Final[str] = settings.WX_APIV3_KEY or WECHAT_PAY_API_V3_KEY
WX_PRIVATE_KEY_PATH: Final[str] = settings.WX_PRIVATE_KEY_PATH or WECHAT_PAY_API_KEY_PATH
WX_PAY_BASE_URL: Final[str] = settings.WX_PAY_BASE_URL or "https://api.mch.weixin.qq.com"
# 平台公钥/证书路径（兼容多个环境变量名）
WECHATPAY_CERT_PATH: Final[str] = settings.WECHATPAY_CERT_PATH or WECHAT_PAY_PLATFORM_CERT_PATH or WECHAT_PAY_PUBLIC_KEY_PATH
WX_WECHATPAY_SERIAL: Final[str] = settings.WX_WECHATPAY_SERIAL or ""

# 推送配置
PUSH_TEMPLATE_ID_APPLYMENT = settings.PUSH_TEMPLATE_ID_APPLYMENT        # 新增
ENVIRONMENT: Final[str] = settings.ENVIRONMENT