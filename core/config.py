# core/config.py - 统一配置管理
from decimal import Decimal
from enum import StrEnum, IntEnum
from typing import Final
import os
from dotenv import load_dotenv
from pathlib import Path
# 加载环境变量
load_dotenv()


# ==================== 数据库配置 ====================
def get_db_config():
    """获取数据库配置字典"""
    cfg = {
        'host': os.getenv('MYSQL_HOST', '127.0.0.1'),
        'port': int(os.getenv('MYSQL_PORT', 3306)),
        'user': os.getenv('MYSQL_USER'),
        'password': os.getenv('MYSQL_PASSWORD'),
        'database': os.getenv('MYSQL_DATABASE'),
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
    NORMAL = 1
    HONOR_DIRECTOR = 9

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
VALID_PAY_WAYS: Final[set[str]] = {"alipay", "wechat", "card", "wx_pub", "wx_app"}

# ==================== 日志配置 ====================
LOG_DIR: Final[Path] = Path(__file__).resolve().parent.parent / 'logs'
LOG_FILE: Final[Path] = LOG_DIR / 'api.log'
LOG_DIR.mkdir(exist_ok=True)

# ==================== 微信配置 ====================
WECHAT_APP_ID: Final[str] = os.getenv('WECHAT_APP_ID', '')
WECHAT_APP_SECRET: Final[str] = os.getenv('WECHAT_APP_SECRET', '')

# ==================== 商品图片配置 ====================
# 挂载静态文件目录（/pic -> pic_data）
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
