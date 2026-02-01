# database_setup.py - 表结构与项目2完全一致
# 注意：此文件主要用于数据库表结构定义和初始化
# 日常数据库操作请使用 core.database.get_conn()
# 已移除 SQLAlchemy ORM，完全使用 pymysql
import pymysql
from core.config import get_db_config
from core.logging import get_logger
import json

# 使用统一的日志配置
logger = get_logger(__name__)

class DatabaseManager:
    def __init__(self):
        self._ensure_database_exists()

    def _ensure_database_exists(self):
        try:
            temp_config = get_db_config().copy()
            database = temp_config.pop('database')
            import pymysql
            conn = pymysql.connect(**temp_config)
            cursor = conn.cursor()
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{database}` "
                f"DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            conn.commit()
            conn.close()
            logger.debug(f"数据库 `{database}` 已就绪")
        except Exception as e:
            logger.error(f"❌ 数据库初始化失败: {e}")
            raise

    def _ensure_table_columns(self, cursor, table_name: str, required_columns: dict):
        """
        确保表的必需字段存在，如果不存在则添加
        
        Args:
            cursor: 数据库游标
            table_name: 表名
            required_columns: 必需字段字典，格式为 {字段名: 字段定义}
        """
        try:
            # 获取表的现有字段
            cursor.execute(f"SHOW COLUMNS FROM {table_name}")
            existing_columns = {row['Field'] for row in cursor.fetchall()}
            
            # 检查并添加缺失的字段
            for column_name, column_def in required_columns.items():
                if column_name not in existing_columns:
                    try:
                        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_def}")
                        logger.info(f"✅ 已添加字段 {table_name}.{column_name}")
                    except Exception as e:
                        logger.warning(f"⚠️ 添加字段 {table_name}.{column_name} 失败: {e}")
        except Exception as e:
            # 如果表不存在，会在创建表时处理
            logger.debug(f"表 {table_name} 可能不存在，将在创建表时处理: {e}")

    def init_all_tables(self, cursor):
        logger.info("初始化数据库表结构")

        tables = {
            'users': """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    mobile VARCHAR(30) UNIQUE,
                    password_hash CHAR(60),
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(100) UNIQUE,
                    member_level TINYINT NOT NULL DEFAULT 0,
                    points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT '联创星级专用点数(用于计算总获得点数)',
                    subsidy_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT '周补贴专用点数(用于计算总获得点数)',
                    team_reward_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT '团队奖励专用点数(用于计算总获得点数)',
                    referral_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT '推荐奖励专用点数(用于计算总获得点数)',
                    true_total_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT '联创星级、周补贴、团队奖励、推荐奖励点数真实总数，发放联创星级、周补贴、团队奖励、推荐奖励点数时会额外发放一份进入这里',
                    promotion_balance DECIMAL(14,2) NOT NULL DEFAULT 0.00,
                    member_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000,
                    merchant_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000,
                    merchant_balance DECIMAL(14,2) NOT NULL DEFAULT 0.00,
                    status TINYINT NOT NULL DEFAULT 1,
                    level_changed_at DATETIME NULL,
                    referral_id BIGINT UNSIGNED NULL COMMENT '推荐人id',
                    referral_code VARCHAR(6) NULL COMMENT '推荐码',
                    withdrawable_balance DECIMAL(14,2) NOT NULL DEFAULT 0.00 COMMENT '可提现余额',
                    avatar_path VARCHAR(255) NULL DEFAULT NULL COMMENT '头像路径',
                    avatar VARCHAR(255) NULL DEFAULT NULL COMMENT '头像',
                    is_merchant TINYINT NOT NULL DEFAULT 0 COMMENT '0=普通用户,1=商家,2=第三方/平台',
                    six_director INT NULL DEFAULT 0 COMMENT '直推六星人数，用于荣誉董事晋升判定',
                    six_team INT NULL DEFAULT 0 COMMENT '团队六星人数，用于荣誉董事晋升判定',
                    wechat_sub_mchid VARCHAR(32) NULL DEFAULT NULL COMMENT '微信特约商户号',
                    openid VARCHAR(128) NULL DEFAULT NULL COMMENT '微信小程序openid',
                    token VARCHAR(256) NULL COMMENT '认证token（支持UUID/JWT/微信Token）',
                    qr_path VARCHAR(255) DEFAULT NULL COMMENT '推荐码二维码路径',
                    wx_openid VARCHAR(100) UNIQUE DEFAULT NULL COMMENT '微信openid',
                    phone VARCHAR(20) DEFAULT NULL COMMENT '手机号',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_mobile (mobile),
                    INDEX idx_email (email),
                    INDEX idx_member_level (member_level),
                    INDEX idx_wechat_sub_mchid (wechat_sub_mchid),
                    UNIQUE KEY uk_referral_code (referral_code),
                    INDEX idx_token (token)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'products': """
                CREATE TABLE IF NOT EXISTS products (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    pinyin TEXT,
                    description TEXT,
                    category VARCHAR(100),
                    cover VARCHAR(500) NULL COMMENT '商品封面图',
                    main_image VARCHAR(500),
                    detail_images TEXT,
                    is_member_product TINYINT(1) NOT NULL DEFAULT 0,
                    status TINYINT NOT NULL DEFAULT 0,
                    user_id BIGINT UNSIGNED,
                    buy_rule TEXT,
                    freight DECIMAL(12,2) DEFAULT 0.00,
                    -- ✅ 新增字段：积分抵扣上限（支持小数，精确到4位）
                    max_points_discount DECIMAL(12,4) DEFAULT NULL COMMENT '积分抵扣上限',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_is_member_product (is_member_product),
                    INDEX idx_user_id (user_id),
                    INDEX idx_status (status),
                    INDEX idx_category (category)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'orders': """
                CREATE TABLE IF NOT EXISTS orders (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    order_number VARCHAR(50) UNIQUE COMMENT '订单号（兼容订单系统）',
                    user_id BIGINT UNSIGNED NOT NULL,
                    merchant_id BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '商家ID（0=平台自营）',
                    offline_order_flag TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否线下收银订单：0线上/1线下',
                    applyment_id BIGINT UNSIGNED DEFAULT NULL COMMENT '关联微信进件单ID（线下订单必填）',
                    total_amount DECIMAL(12,2) NOT NULL,
                    original_amount DECIMAL(12,2) DEFAULT 0.00,
                    points_discount DECIMAL(12,4) NOT NULL DEFAULT 0.0000,
                    is_member_order TINYINT(1) NOT NULL DEFAULT 0,
                    is_vip_item TINYINT(1) DEFAULT 0 COMMENT '1=含会员商品（兼容订单系统）',
                    status VARCHAR(30) NOT NULL DEFAULT 'pending_pay',
                    -- 统一枚举，与 refunds.status 保持一致
                    refund_status ENUM('applied','seller_ok','refund_success','rejected','seller_rejected') DEFAULT NULL,
                    consignee_name VARCHAR(100),
                    consignee_phone VARCHAR(20),
                    province VARCHAR(20) DEFAULT '',
                    city VARCHAR(20) DEFAULT '',
                    district VARCHAR(20) DEFAULT '',
                    shipping_address TEXT,
                    pay_way ENUM('wechat') DEFAULT 'wechat',
                    refund_reason TEXT,
                    auto_recv_time DATETIME NULL COMMENT '7 天后自动收货',
                    tracking_number VARCHAR(64) NULL COMMENT '快递单号',
                    transaction_id VARCHAR(64) DEFAULT NULL COMMENT '微信/支付宝交易号',
                    pay_time DATETIME NULL COMMENT '支付成功时间',
                    paid_at DATETIME NULL COMMENT '支付时间（冗余，用于状态流转）',
                    shipped_at DATETIME NULL COMMENT '发货时间',
                    completed_at DATETIME NULL COMMENT '完成时间',
                    status_reason VARCHAR(255) NULL COMMENT '状态原因说明',
                    remark VARCHAR(255) NULL COMMENT '备注',
                    delivery_way VARCHAR(20) NOT NULL DEFAULT 'platform' COMMENT '配送方式：platform-平台配送/pickup-自提',
                    expire_at DATETIME NULL COMMENT '订单过期时间（未支付订单7天后自动过期）',
                    wechat_shipping_status TINYINT NOT NULL DEFAULT 0 COMMENT '微信发货状态：0未上传 1已上传 2上传失败 3已重新上传',
                    wechat_shipping_time DATETIME NULL COMMENT '微信发货信息上传时间',
                    wechat_shipping_msg VARCHAR(500) NULL COMMENT '微信发货接口返回错误信息',
                    wechat_last_sync_time DATETIME NULL COMMENT '最后一次同步微信状态时间',
                    wechat_shipping_retry_count TINYINT NOT NULL DEFAULT 0 COMMENT '微信发货重试次数，最多1次',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_user (user_id),
                    INDEX idx_order_number (order_number),
                    INDEX idx_trans (transaction_id),
                    INDEX idx_pay_time (pay_time),
                    INDEX idx_created_at (created_at),
                    INDEX idx_status (status),
                    INDEX idx_expire_at (expire_at),
                    INDEX idx_wechat_shipping_status (wechat_shipping_status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'wechat_shipping_logs': """
                CREATE TABLE IF NOT EXISTS wechat_shipping_logs (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    order_id BIGINT UNSIGNED NOT NULL COMMENT '关联订单ID',
                    order_number VARCHAR(50) NOT NULL COMMENT '商户订单号',
                    transaction_id VARCHAR(64) NULL COMMENT '微信支付单号',
                    action_type ENUM('upload', 'retry', 'query', 'sync') NOT NULL DEFAULT 'upload' COMMENT '操作类型：upload首次上传/retry重新上传/query查询状态/sync状态同步',
                    remark VARCHAR(500) NULL COMMENT '附加说明（例如同步、确认收货等描述）',
                    logistics_type TINYINT NULL COMMENT '物流类型：1快递/2同城/3虚拟/4自提',
                    express_company VARCHAR(50) NULL COMMENT '物流公司编码',
                    tracking_no VARCHAR(128) NULL COMMENT '运单号',
                    request_data JSON NULL COMMENT '请求微信的JSON数据',
                    response_data JSON NULL COMMENT '微信返回的JSON数据',
                    errcode INT NULL COMMENT '微信返回的错误码',
                    errmsg VARCHAR(500) NULL COMMENT '微信返回的错误信息',
                    is_success TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否成功：0失败 1成功',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_order_id (order_id),
                    INDEX idx_order_number (order_number),
                    INDEX idx_transaction_id (transaction_id),
                    INDEX idx_action_type (action_type),
                    INDEX idx_is_success (is_success),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'offline_order': """
                CREATE TABLE IF NOT EXISTS offline_order (
                    id                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    order_no            VARCHAR(50) UNIQUE NOT NULL COMMENT '线下订单号',
                    merchant_id         BIGINT UNSIGNED NOT NULL COMMENT '商家ID',
                    user_id             BIGINT UNSIGNED NULL COMMENT '付款用户ID（可空）',
                    store_name          VARCHAR(100) NOT NULL COMMENT '门店名称',
                    amount              INT NOT NULL COMMENT '订单金额（单位：分）',
                    coupon_id           INT NULL COMMENT '使用的优惠券ID',           
                    coupon_discount     INT DEFAULT 0 COMMENT '优惠券抵扣金额（分）', 
                    paid_amount         INT DEFAULT 0 COMMENT '实付金额（分，优惠后）',
                    product_name        VARCHAR(255) DEFAULT '' COMMENT '商品名称',
                    remark              TEXT COMMENT '备注',
                    status              TINYINT NOT NULL DEFAULT 1 COMMENT '1待支付 2已支付 4已退款',
                    qrcode_url          VARCHAR(500) DEFAULT NULL COMMENT '收款码',
                    qrcode_expire       DATETIME DEFAULT NULL COMMENT '码过期时间',
                    refresh_count       TINYINT NOT NULL DEFAULT 0 COMMENT '已刷新次数',
                    related_order_no    VARCHAR(50) DEFAULT NULL COMMENT '关联主订单号',
                    pay_time            DATETIME NULL COMMENT '微信/支付宝支付成功时间',
                    transaction_id      VARCHAR(64) DEFAULT NULL COMMENT '微信/支付宝交易号',
                    refund_id           VARCHAR(64) DEFAULT NULL COMMENT '微信/支付宝退款单号',
                    refund_time         DATETIME NULL COMMENT '退款完成时间',
                    openid              VARCHAR(64) DEFAULT NULL COMMENT '付款人 openid（可选）',
                    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_merchant  (merchant_id),
                    INDEX idx_status    (status),
                    INDEX idx_expire    (qrcode_expire),
                    INDEX idx_trans     (transaction_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """,
            'order_items': """
                CREATE TABLE IF NOT EXISTS order_items (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    order_id BIGINT UNSIGNED NOT NULL,
                    product_id BIGINT UNSIGNED NOT NULL,
                    sku_id BIGINT UNSIGNED NULL,
                    quantity INT NOT NULL DEFAULT 1,
                    unit_price DECIMAL(12,2) NOT NULL,
                    total_price DECIMAL(12,2) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_order (order_id),
                    INDEX idx_product (product_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'finance_accounts': """
                CREATE TABLE IF NOT EXISTS finance_accounts (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    account_name VARCHAR(100) NOT NULL,
                    account_type VARCHAR(50) UNIQUE NOT NULL,
                    balance DECIMAL(14,4) NOT NULL DEFAULT 0.0000,
                    config_params JSON DEFAULT NULL COMMENT '资金池配置参数',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uk_account_type (account_type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'account_flow': """
                CREATE TABLE IF NOT EXISTS account_flow (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    account_id BIGINT UNSIGNED,
                    related_user BIGINT UNSIGNED,
                    account_type VARCHAR(50),
                    change_amount DECIMAL(14,4) NOT NULL,
                    balance_after DECIMAL(14,4),
                    flow_type VARCHAR(50),
                    remark VARCHAR(255),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_account (account_id),
                    INDEX idx_related_user (related_user),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'points_log': """
                CREATE TABLE IF NOT EXISTS points_log (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    change_amount DECIMAL(12,4) NOT NULL,
                    balance_after DECIMAL(12,4) NOT NULL,
                    type ENUM('member','merchant') NOT NULL,
                    reason VARCHAR(255),
                    related_order BIGINT UNSIGNED,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user (user_id),
                    INDEX idx_order (related_order)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'user_referrals': """
                CREATE TABLE IF NOT EXISTS user_referrals (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED UNIQUE NOT NULL,
                    referrer_id BIGINT UNSIGNED,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_referrer (referrer_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'pending_rewards': """
                CREATE TABLE IF NOT EXISTS pending_rewards (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    reward_type ENUM('referral','team') NOT NULL,
                    amount DECIMAL(12,4) NOT NULL,
                    order_id BIGINT UNSIGNED NOT NULL,
                    layer TINYINT DEFAULT NULL,
                    status ENUM('pending','approved','rejected') DEFAULT 'pending',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user_status (user_id, status),
                    INDEX idx_order_id (order_id),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'coupons': """
                CREATE TABLE IF NOT EXISTS coupons (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    coupon_type ENUM('user','merchant') NOT NULL,
                    amount DECIMAL(14,4) NOT NULL,
                    status ENUM('unused','used','expired') NOT NULL DEFAULT 'unused',
                    applicable_product_type ENUM('all','normal_only','member_only') NOT NULL DEFAULT 'all' COMMENT '优惠券适
                    用商品范围：all=不限制，normal_only=仅普通商品，member_only=仅会员商品',
                    valid_from DATE NOT NULL,
                    valid_to DATE NOT NULL,
                    used_at DATETIME DEFAULT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user_status (user_id, status),
                    INDEX idx_valid_to (valid_to)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'withdrawals': """
                CREATE TABLE IF NOT EXISTS withdrawals (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    amount DECIMAL(14,4) NOT NULL,
                    tax_amount DECIMAL(14,4) NOT NULL DEFAULT 0.00,
                    actual_amount DECIMAL(14,4) NOT NULL DEFAULT 0.00,
                    status VARCHAR(30) NOT NULL DEFAULT 'pending_auto',
                    audit_remark VARCHAR(255) DEFAULT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    processed_at DATETIME DEFAULT NULL,
                    INDEX idx_user_status (user_id, status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'team_rewards': """
                CREATE TABLE IF NOT EXISTS team_rewards (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    from_user_id BIGINT UNSIGNED NOT NULL,
                    order_id BIGINT UNSIGNED,
                    layer TINYINT NOT NULL,
                    reward_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user_id (user_id),
                    INDEX idx_from_user_id (from_user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'weekly_subsidy_records': """
                CREATE TABLE IF NOT EXISTS weekly_subsidy_records (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    week_start DATE NOT NULL,
                    subsidy_amount DECIMAL(14,4) NOT NULL,
                    points_before DECIMAL(12,4) NOT NULL,
                    points_deducted DECIMAL(12,4) NOT NULL,
                    coupon_id BIGINT UNSIGNED,
                    remark VARCHAR(500) NULL COMMENT '备注，用于标记平台积分池发放',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user_week (user_id, week_start)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            # ========== 订单系统相关表（来自 order/database_setup1.py） ==========
            # 注意：Users 和 Products 表已整合到统一的 users 和 products 表中
            'cart': """
                CREATE TABLE IF NOT EXISTS cart (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    product_id BIGINT UNSIGNED NOT NULL,
                    sku_id BIGINT UNSIGNED NULL,
                    quantity INT DEFAULT 1,
                    specifications JSON DEFAULT NULL,
                    selected TINYINT DEFAULT 1,
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uk_user_product_sku (user_id, product_id, sku_id),
                    INDEX idx_user_id (user_id),
                    INDEX idx_product_id (product_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            # 注意：Cart 表的外键约束在表创建后单独添加，避免类型不匹配问题
            # 注意：Orders 和 Order_Items 表已整合到统一的 orders 和 order_items 表中
            'refunds': """
                CREATE TABLE IF NOT EXISTS refunds (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    order_number VARCHAR(50) NOT NULL,
                    refund_type ENUM('return','refund_only') NOT NULL COMMENT 'return=退货退款，refund_only=仅退款',
                    reason TEXT NOT NULL,
                    status ENUM('applied','seller_ok','refund_success','rejected','seller_rejected') DEFAULT 'applied',
                    reject_reason TEXT,
                    merchant_address VARCHAR(255) COMMENT '商家退货地址',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_order_number (order_number)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            # 注意：Refunds 表的外键约束在表创建后单独添加，避免类型不匹配问题
            'addresses': """
                CREATE TABLE IF NOT EXISTS addresses (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    name VARCHAR(100) NOT NULL COMMENT '收货人姓名',
                    phone VARCHAR(20) NOT NULL COMMENT '收货人电话',
                    province VARCHAR(20) NOT NULL DEFAULT '' COMMENT '省份',
                    city VARCHAR(20) NOT NULL DEFAULT '' COMMENT '城市',
                    district VARCHAR(20) NOT NULL DEFAULT '' COMMENT '区县',
                    detail TEXT NOT NULL COMMENT '详细地址',
                    is_default TINYINT(1) DEFAULT 0 COMMENT '是否默认地址',
                    addr_type ENUM('shipping','return') NOT NULL DEFAULT 'shipping' COMMENT '地址类型（分为购物地址和退货地址）',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_user (user_id),
                    INDEX idx_user_default (user_id, is_default)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            # 注意：Addresses 表的外键约束在表创建后单独添加
            'merchant_statement': """
                CREATE TABLE IF NOT EXISTS merchant_statement (
                    merchant_id BIGINT UNSIGNED NOT NULL,
                    date DATE NOT NULL,
                    opening_balance DECIMAL(10,2) NOT NULL,
                    income DECIMAL(10,2) NOT NULL,
                    withdraw DECIMAL(10,2) NOT NULL,
                    closing_balance DECIMAL(10,2) NOT NULL,
                    PRIMARY KEY (merchant_id, date)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'alert_order': """
                CREATE TABLE IF NOT EXISTS alert_order (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    order_number VARCHAR(50) NOT NULL,
                    alert_type VARCHAR(50) NOT NULL,
                    detail TEXT NOT NULL,
                    is_handled TINYINT(1) DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'banner': """
                CREATE TABLE IF NOT EXISTS banner (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    product_id BIGINT UNSIGNED NOT NULL COMMENT '外键→products.id',
                    image_url VARCHAR(500) NOT NULL COMMENT '图片URL',
                    link_url VARCHAR(500) NULL COMMENT '跳转链接',
                    sort_order INT NULL COMMENT '排序值',
                    status INT NULL DEFAULT 1 COMMENT '状态（0隐藏/1显示）',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    INDEX idx_product_id (product_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'product_attributes': """
                CREATE TABLE IF NOT EXISTS product_attributes (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    product_id BIGINT UNSIGNED NOT NULL COMMENT '外键→products.id',
                    name VARCHAR(100) NOT NULL COMMENT '属性名',
                    value VARCHAR(100) NOT NULL COMMENT '属性值',
                    INDEX idx_product_id (product_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'product_skus': """
                CREATE TABLE IF NOT EXISTS product_skus (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    product_id BIGINT UNSIGNED NOT NULL COMMENT '外键→products.id',
                    sku_code VARCHAR(64) NOT NULL UNIQUE COMMENT '唯一SKU编码',
                     price DECIMAL(12,2) NULL COMMENT '商品现价（实际售价）',
                    -- ✅ 新增字段：商品原价（市场价/划线价）
                    original_price DECIMAL(12,2) NULL COMMENT '商品原价',
                    stock INT NULL DEFAULT 0 COMMENT '库存数量',
                    -- ✅ 新增字段：商品规格（存储颜色、尺码等）
                    specifications JSON DEFAULT NULL COMMENT '商品规格（如：{"颜色": "红色", "尺码": "XL"}）',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                    INDEX idx_product_id (product_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'system_sentence': """
                CREATE TABLE IF NOT EXISTS system_sentence (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    banner_sentence VARCHAR(128) NULL COMMENT '轮播图标语',
                    system_sentence VARCHAR(128) NULL COMMENT '系统标语',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'user_unilevel': """
                CREATE TABLE IF NOT EXISTS user_unilevel (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    level TINYINT NOT NULL COMMENT '1-一星联创 2-二星 3-三星',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uk_uid (user_id),
                    INDEX idx_user_id (user_id),
                    INDEX idx_level (level)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'directors': """
                CREATE TABLE IF NOT EXISTS directors (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL UNIQUE COMMENT '用户ID，唯一',
                    status VARCHAR(20) NOT NULL DEFAULT 'active' COMMENT '状态：active=活跃',
                    dividend_amount DECIMAL(14,2) NOT NULL DEFAULT 0.00 COMMENT '累计分红金额',
                    activated_at DATETIME NULL COMMENT '激活时间',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    INDEX idx_user_id (user_id),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'director_dividends': """
                CREATE TABLE IF NOT EXISTS director_dividends (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL COMMENT '用户ID',
                    period_date DATE NOT NULL COMMENT '分红周期日期',
                    dividend_amount DECIMAL(14,4) NOT NULL COMMENT '分红金额',
                    new_sales DECIMAL(14,4) NOT NULL DEFAULT 0.00 COMMENT '本期新业绩',
                    weight INT NOT NULL DEFAULT 1 COMMENT '权重，基于团队六星人数',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    INDEX idx_user_id (user_id),
                    INDEX idx_period_date (period_date)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'user_bankcards': """
                CREATE TABLE IF NOT EXISTS user_bankcards (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL,
                    bank_name VARCHAR(50) NOT NULL,
                    bank_account VARCHAR(30) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user_card (user_id, bank_account),
                    CONSTRAINT fk_user_bankcard FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'wx_applyment': """
                CREATE TABLE IF NOT EXISTS wx_applyment (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY COMMENT '主键ID',
                    user_id BIGINT UNSIGNED NOT NULL COMMENT '商家用户ID，关联 users.id',
                    business_code VARCHAR(124) NOT NULL COMMENT '业务申请编号（唯一，服务商自定义）',
                    applyment_id BIGINT UNSIGNED NULL COMMENT '微信支付申请单号',
                    sub_mchid VARCHAR(32) NULL COMMENT '特约商户号',
                    subject_type ENUM(
                        'SUBJECT_TYPE_INDIVIDUAL',
                        'SUBJECT_TYPE_ENTERPRISE',
                        'SUBJECT_TYPE_INSTITUTIONS',
                        'SUBJECT_TYPE_OTHERS'
                    ) NOT NULL COMMENT '主体类型',
                    subject_info JSON NOT NULL COMMENT '主体资料（营业执照、法人信息等）',
                    contact_info JSON NOT NULL COMMENT '超级管理员信息',
                    bank_account_info JSON NOT NULL COMMENT '结算账户信息',
                    applyment_state ENUM(
                        'APPLYMENT_STATE_EDITTING',
                        'APPLYMENT_STATE_AUDITING',
                        'APPLYMENT_STATE_REJECTED',
                        'APPLYMENT_STATE_TO_BE_CONFIRMED',
                        'APPLYMENT_STATE_TO_BE_SIGNED',
                        'APPLYMENT_STATE_SIGNING',
                        'APPLYMENT_STATE_FINISHED',
                        'APPLYMENT_STATE_CANCELED'
                    ) NOT NULL DEFAULT 'APPLYMENT_STATE_EDITTING' COMMENT '申请单状态',
                    applyment_state_msg VARCHAR(1024) NULL COMMENT '状态描述',
                    sign_url VARCHAR(512) NULL COMMENT '超管签约链接',
                    audit_detail JSON NULL COMMENT '驳回详情（字段级错误数组）',
                    is_draft TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否为草稿：1草稿/0已提交',
                    draft_expired_at DATETIME NULL COMMENT '草稿过期时间（创建+7天）',
                    is_core_info_modified TINYINT(1) NOT NULL DEFAULT 0 COMMENT '核心信息修改标记',
                    submitted_at DATETIME NULL COMMENT '正式提交时间',
                    is_timeout_alerted TINYINT(1) NOT NULL DEFAULT 0 COMMENT '审核超时提醒是否已发送',
                    finished_at DATETIME NULL COMMENT '完成时间',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uk_business_code (business_code),
                    INDEX idx_user_id (user_id),
                    INDEX idx_applyment_id (applyment_id),
                    INDEX idx_sub_mchid (sub_mchid),
                    INDEX idx_applyment_state (applyment_state)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'wx_applyment_log': """
                CREATE TABLE IF NOT EXISTS wx_applyment_log (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    applyment_id BIGINT UNSIGNED NOT NULL COMMENT '关联微信申请单号',
                    business_code VARCHAR(124) NOT NULL COMMENT '业务申请编号',
                    old_state VARCHAR(50) NOT NULL COMMENT '变更前状态',
                    new_state VARCHAR(50) NOT NULL COMMENT '变更后状态',
                    state_msg VARCHAR(1024) NULL COMMENT '状态描述',
                    reject_detail JSON NULL COMMENT '驳回详情',
                    operator VARCHAR(50) NULL COMMENT '操作来源：SYSTEM/USER/WECHAT',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_applyment_id (applyment_id),
                    INDEX idx_business_code (business_code),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'wx_applyment_media': """
                CREATE TABLE IF NOT EXISTS wx_applyment_media (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    applyment_id BIGINT UNSIGNED NULL COMMENT '关联申请单ID，草稿时可为空',
                    user_id BIGINT UNSIGNED NOT NULL COMMENT '上传用户ID，关联 users.id',
                    media_id VARCHAR(512) NULL COMMENT '微信媒体ID（24小时有效）',
                    media_type ENUM(
                        'id_card_front',
                        'id_card_back',
                        'business_license',
                        'bank_card',
                        'authorization_letter',
                        'store_entrance',
                        'indoor_pic',
                        'other'
                    ) NOT NULL COMMENT '材料类型',
                    file_path VARCHAR(500) NOT NULL COMMENT '本地存储路径',
                    file_name VARCHAR(255) NOT NULL COMMENT '原始文件名',
                    file_size INT NOT NULL COMMENT '文件大小（字节）',
                    sha256 CHAR(64) NOT NULL COMMENT '文件SHA256哈希',
                    mime_type VARCHAR(50) NOT NULL COMMENT 'MIME类型',
                    upload_status ENUM('local','uploaded','expired','rejected')
                        NOT NULL DEFAULT 'local' COMMENT '上传状态',
                    expires_at DATETIME NULL COMMENT 'media_id过期时间',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_applyment_id (applyment_id),
                    INDEX idx_user_id (user_id),
                    INDEX idx_media_id (media_id),
                    INDEX idx_media_type (media_type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'merchant_settlement_accounts': """
                CREATE TABLE IF NOT EXISTS merchant_settlement_accounts (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL COMMENT '商家用户ID，关联 users.id',
                    sub_mchid VARCHAR(32) NULL COMMENT '特约商户号',
                    account_type ENUM('BANK_ACCOUNT_TYPE_PERSONAL','BANK_ACCOUNT_TYPE_CORPORATE')
                        NOT NULL COMMENT '账户类型',
                    account_bank VARCHAR(128) NOT NULL COMMENT '开户银行',
                    bank_name VARCHAR(128) NULL COMMENT '开户行全称（含支行）',
                    bank_branch_id VARCHAR(128) NULL COMMENT '开户行联行号',
                    bank_address_code VARCHAR(20) NOT NULL COMMENT '开户银行地区码（6位数字码）',
                    account_name_encrypted TEXT NOT NULL COMMENT '开户名称（加密，RSA+Base64）',
                    account_number_encrypted TEXT NOT NULL COMMENT '银行账号（加密，RSA+Base64）',
                    card_hash VARCHAR(64) NULL COMMENT '卡号哈希（用于判重，加盐SHA256）',
                    verify_result ENUM('VERIFY_SUCCESS','VERIFY_FAIL','VERIFYING')
                        NOT NULL DEFAULT 'VERIFYING' COMMENT '验证结果',
                    verify_fail_reason VARCHAR(1024) NULL COMMENT '验证失败原因',
                    modify_application_no VARCHAR(64) DEFAULT NULL COMMENT '改绑申请单号',
                    modify_fail_reason VARCHAR(255) DEFAULT NULL COMMENT '改绑失败原因',
                            -- ✅ 新增字段：改绑临时存储
                    new_account_number_encrypted TEXT NULL COMMENT '改绑-新卡号(加密)',
                    new_account_name_encrypted TEXT NULL COMMENT '改绑-新户名(加密)',
                    new_bank_name VARCHAR(128) NULL COMMENT '改绑-新开户行',
                    old_account_backup JSON NULL COMMENT '改绑-旧卡备份{number,name,bank}',
                    is_default TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否默认账户：1默认',
                    status TINYINT(1) NOT NULL DEFAULT 1 COMMENT '账户状态：1启用/0禁用',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    bind_at DATETIME NULL COMMENT '绑定成功时间',
                    INDEX idx_user_id (user_id),
                    INDEX idx_sub_mchid (sub_mchid),
                    INDEX idx_verify_result (verify_result),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'merchant_realname_verification': """
                CREATE TABLE IF NOT EXISTS merchant_realname_verification (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL UNIQUE COMMENT '商家用户ID，一个用户一条记录',
                    verification_type ENUM('individual','enterprise') NOT NULL COMMENT '认证类型',
                    status ENUM('pending','auditing','approved','rejected')
                        NOT NULL DEFAULT 'pending' COMMENT '认证状态',
                    audit_remark TEXT NULL COMMENT '审核备注/驳回原因',
                    real_name VARCHAR(100) NOT NULL COMMENT '姓名/企业名称',
                    id_card_no_encrypted TEXT NULL COMMENT '身份证号/统一社会信用代码（加密）',
                    id_card_front_media_id VARCHAR(512) NULL COMMENT '身份证正面media_id',
                    id_card_back_media_id VARCHAR(512) NULL COMMENT '身份证反面media_id',
                    business_license_no VARCHAR(100) NULL COMMENT '营业执照号（企业必填）',
                    business_license_media_id VARCHAR(512) NULL COMMENT '营业执照media_id',
                    legal_person_name VARCHAR(100) NULL COMMENT '法人姓名（企业必填）',
                    legal_person_id_no_encrypted TEXT NULL COMMENT '法人身份证号(加密)',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    audited_at DATETIME NULL COMMENT '审核时间',
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'user_bankcard_operations': """
                CREATE TABLE IF NOT EXISTS user_bankcard_operations (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id BIGINT UNSIGNED NOT NULL COMMENT '用户ID',
                    operation_type VARCHAR(50) NOT NULL COMMENT '操作类型：bind/unbind/set_default/verify',
                    target_id BIGINT UNSIGNED NULL COMMENT '关联的结算账户ID(merchant_settlement_accounts.id)',
                    old_val JSON NULL COMMENT '旧值（JSON）',
                    new_val JSON NULL COMMENT '新值（JSON）',
                    remark TEXT NULL COMMENT '操作详情',
                    admin_key VARCHAR(100) NULL COMMENT '管理员标识(SYSTEM表示系统操作)',
                    ip_address VARCHAR(45) NULL COMMENT 'IP地址',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user_id (user_id),
                    INDEX idx_operation_type (operation_type),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'merchant_stores': """
            CREATE TABLE IF NOT EXISTS merchant_stores (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY COMMENT '店铺ID',
                user_id BIGINT UNSIGNED NOT NULL UNIQUE COMMENT '商家用户ID（唯一）',
                store_name VARCHAR(100) NOT NULL COMMENT '店铺名称',
                store_logo_image_id VARCHAR(100) COMMENT '店铺LOGO图片ID',
                store_description VARCHAR(500) COMMENT '店铺简介',
                contact_name VARCHAR(20) NOT NULL COMMENT '联系人姓名',
                contact_phone VARCHAR(11) NOT NULL COMMENT '联系人手机号',
                contact_email VARCHAR(100) COMMENT '联系人邮箱',
                business_hours VARCHAR(100) COMMENT '营业时间',
                store_address VARCHAR(200) COMMENT '店铺地址',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                INDEX idx_user_id (user_id),
                INDEX idx_store_name (store_name),
                CONSTRAINT fk_merchant_stores_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,

            'store_logos': """
            CREATE TABLE IF NOT EXISTS store_logos (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY COMMENT 'LOGO ID',
                image_id VARCHAR(100) NOT NULL UNIQUE COMMENT '图片ID（唯一）',
                user_id BIGINT UNSIGNED NOT NULL COMMENT '商家用户ID',
                file_path VARCHAR(500) NOT NULL COMMENT '文件存储路径',
                file_size INT NOT NULL COMMENT '文件大小（字节）',
                upload_time DATETIME NOT NULL COMMENT '上传时间',
                INDEX idx_user_id (user_id),
                INDEX idx_image_id (image_id),
                CONSTRAINT fk_store_logos_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        }

        # 定义必需字段（用于检查和更新已存在的表）
        required_columns = {
            'users': {
                'member_points': 'member_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000',
                'merchant_points': 'merchant_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000',
                'withdrawable_balance': 'withdrawable_balance DECIMAL(14,2) NOT NULL DEFAULT 0.00 COMMENT \'可提现余额\'',
                'is_merchant': 'is_merchant TINYINT(1) NOT NULL DEFAULT 0 COMMENT \'判断是不是商家\'',
                'status': 'status TINYINT NOT NULL DEFAULT 1',
                'avatar_path': 'avatar_path VARCHAR(255) NULL DEFAULT NULL COMMENT \'头像路径\'',
                'avatar': 'avatar VARCHAR(255) NULL DEFAULT NULL COMMENT \'头像\'',
                'six_director': 'six_director INT NULL DEFAULT 0 COMMENT \'直推六星人数，用于荣誉董事晋升判定\'',
                'six_team': 'six_team INT NULL DEFAULT 0 COMMENT \'团队六星人数，用于荣誉董事晋升判定\'',
                'subsidy_points': 'subsidy_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT \'周补贴专用点数\'',
                'team_reward_points': 'team_reward_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT \'团队奖励专用点数\'',
                'referral_points': 'referral_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000 COMMENT \'推荐奖励专用点数\'',
                'wechat_sub_mchid': 'wechat_sub_mchid VARCHAR(32) NULL DEFAULT NULL COMMENT \'微信特约商户号\'',
                'has_store_permission': 'has_store_permission TINYINT(1) NOT NULL DEFAULT 0 COMMENT \'是否开通开店权限（支付进件成功后置为1）\'',
            },
            'orders': {
                'tracking_number': 'tracking_number VARCHAR(64) NULL COMMENT \'快递单号\'',
                'delivery_way': 'delivery_way VARCHAR(20) NOT NULL DEFAULT \'platform\' COMMENT \'配送方式：platform-平台配送/pickup-自提\'',
                'expire_at': 'expire_at DATETIME NULL COMMENT \'订单过期时间（未支付订单7天后自动过期）\'',
                'offline_order_flag': 'offline_order_flag TINYINT(1) NOT NULL DEFAULT 0 COMMENT \'是否线下收银订单：0线上/1线下\'',
                'applyment_id': 'applyment_id BIGINT UNSIGNED DEFAULT NULL COMMENT \'关联微信进件单ID（线下订单必填）\'',
                'wechat_shipping_status': 'wechat_shipping_status TINYINT NOT NULL DEFAULT 0 COMMENT \'微信发货状态：0未上传 1已上传 2上传失败 3已重新上传\'',
                'wechat_shipping_time': 'wechat_shipping_time DATETIME NULL COMMENT \'微信发货信息上传时间\'',
                'wechat_shipping_msg': 'wechat_shipping_msg VARCHAR(500) NULL COMMENT \'微信发货接口返回错误信息\'',
                'wechat_last_sync_time': 'wechat_last_sync_time DATETIME NULL COMMENT \'最后一次同步微信状态时间\'',
                'wechat_shipping_retry_count': 'wechat_shipping_retry_count TINYINT NOT NULL DEFAULT 0 COMMENT \'微信发货重试次数，最多1次\'',
            },
            'order_items': {
                'sku_id': 'sku_id BIGINT UNSIGNED NULL',
            },
            'cart': {
                'specifications': 'specifications JSON DEFAULT NULL',
                'sku_id': 'sku_id BIGINT UNSIGNED NULL',
            },
            # 联创星级分红手动调整配置字段
            'finance_accounts': {
                'config_params': "config_params JSON DEFAULT NULL COMMENT '资金池配置参数（如：fixed_amount_per_weight）'"
            },
            'merchant_settlement_accounts': {
                # ✅ 新增改绑相关字段
                'new_account_number_encrypted': "new_account_number_encrypted TEXT NULL COMMENT '改绑-新卡号(加密)'",
                'new_account_name_encrypted': "new_account_name_encrypted TEXT NULL COMMENT '改绑-新户名(加密)'",
                'new_bank_name': "new_bank_name VARCHAR(128) NULL COMMENT '改绑-新开户行'",
                'old_account_backup': "old_account_backup JSON NULL COMMENT '改绑-旧卡备份{number,name,bank}'",
            },
            'coupons': {
                # 检查并添加 applicable_product_type 字段
                'applicable_product_type': "applicable_product_type ENUM('all','normal_only','member_only') NOT NULL DEFAULT 'all' COMMENT '优惠券适用商品范围：all=不限制，normal_only=仅普通商品，member_only=仅会员商品'",
            },
            'products': {
                'cover': "cover VARCHAR(500) NULL COMMENT '商品封面图'",
            },
            'wx_applyment': {
                'is_timeout_alerted': "is_timeout_alerted TINYINT(1) NOT NULL DEFAULT 0 COMMENT '审核超时提醒是否已发送'",
            }
        }
        
        for table_name, sql in tables.items():
            cursor.execute(sql)
            logger.debug(f"表 `{table_name}` 已创建/确认")
            
            # 检查并更新表结构（添加缺失的字段）
            if table_name in required_columns:
                self._ensure_table_columns(cursor, table_name, required_columns[table_name])

        # 在表创建后添加外键约束（避免类型不匹配问题）
        self._add_cart_foreign_keys(cursor)
        self._add_refunds_foreign_keys(cursor)
        self._add_orders_foreign_keys(cursor)
        self._add_order_items_foreign_keys(cursor)
        self._add_addresses_foreign_keys(cursor)
        self._add_banner_foreign_keys(cursor)
        self._add_product_attributes_foreign_keys(cursor)
        self._add_product_skus_foreign_keys(cursor)
        self._add_user_unilevel_foreign_keys(cursor)
        self._add_directors_foreign_keys(cursor)
        self._add_director_dividends_foreign_keys(cursor)

        # ========== 微信进件模块外键约束 ==========
        self._add_wx_applyment_foreign_keys(cursor)
        self._add_wx_applyment_media_foreign_keys(cursor)
        self._add_merchant_settlement_accounts_foreign_keys(cursor)
        self._add_merchant_realname_verification_foreign_keys(cursor)
        self._add_user_bankcard_operations_foreign_keys(cursor)

        try:
            # 创建普通索引（提升查询性能）
            cursor.execute("CREATE INDEX idx_card_hash ON merchant_settlement_accounts (card_hash)")
            cursor.execute("CREATE INDEX idx_status ON merchant_settlement_accounts (status)")
            cursor.execute("CREATE INDEX idx_user_status ON merchant_settlement_accounts (user_id, status)")
            logger.info("✅ 已创建普通索引 idx_card_hash, idx_status, idx_user_status")
        except pymysql.MySQLError as e:
            if e.args[0] == 1061:  # Duplicate key name
                logger.debug("ℹ️ 索引已存在，跳过创建")
            else:
                logger.warning(f"⚠️ 创建索引失败: {e}")

        self._init_finance_accounts(cursor)
        logger.info("数据库表结构初始化完成")

    def _add_cart_foreign_keys(self, cursor):
        """为 cart 表添加外键约束（如果不存在）"""
        try:
            # 检查 cart 表和被引用表是否存在
            cursor.execute("""
                SELECT TABLE_NAME 
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME IN ('cart', 'users', 'products')
            """)
            existing_tables = {row['TABLE_NAME'] for row in cursor.fetchall()}
            
            if 'cart' not in existing_tables or 'users' not in existing_tables or 'products' not in existing_tables:
                logger.debug("⚠️ cart 表或引用表不存在，跳过外键添加")
                return
            
            # 检查外键是否已存在
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'cart' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'cart_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE cart 
                    ADD CONSTRAINT cart_ibfk_1 
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                """)
                logger.debug("cart 表外键约束 cart_ibfk_1 已添加")
            
            if 'cart_ibfk_2' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE cart 
                    ADD CONSTRAINT cart_ibfk_2 
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
                """)
                logger.debug("cart 表外键约束 cart_ibfk_2 已添加")
        except Exception as e:
            # 如果添加外键失败（可能是类型不匹配或表不存在），静默忽略
            logger.debug(f"⚠️ cart 表外键约束添加失败（已忽略）: {e}")

    def _add_refunds_foreign_keys(self, cursor):
        """为 refunds 表添加外键约束（如果不存在）"""
        try:
            # 检查 refunds 表和 orders 表是否存在，以及 orders 表是否有 order_number 列
            cursor.execute("""
                SELECT TABLE_NAME 
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME IN ('refunds', 'orders')
            """)
            existing_tables = {row['TABLE_NAME'] for row in cursor.fetchall()}
            
            if 'refunds' not in existing_tables or 'orders' not in existing_tables:
                logger.debug("⚠️ refunds 表或 orders 表不存在，跳过外键添加")
                return
            
            # 检查 orders 表是否有 order_number 列
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM information_schema.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'orders' 
                AND COLUMN_NAME = 'order_number'
            """)
            if cursor.fetchone() is None:
                logger.debug("⚠️ orders 表缺少 order_number 列，跳过外键添加")
                return
            
            # 检查外键是否已存在
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'refunds' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'refunds_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE refunds 
                    ADD CONSTRAINT refunds_ibfk_1 
                    FOREIGN KEY (order_number) REFERENCES orders(order_number) ON DELETE CASCADE
                """)
                logger.debug("refunds 表外键约束 refunds_ibfk_1 已添加")
        except Exception as e:
            # 如果添加外键失败（可能是类型不匹配或表不存在），静默忽略
            logger.debug(f"⚠️ refunds 表外键约束添加失败（已忽略）: {e}")

    def _add_orders_foreign_keys(self, cursor):
        """为 orders 表添加外键约束（如果不存在）"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'orders' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'orders_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE orders 
                    ADD CONSTRAINT orders_ibfk_1 
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                """)
                logger.debug("orders 表外键约束 orders_ibfk_1 已添加")
        except Exception as e:
            logger.warning(f"⚠️ orders 表外键约束添加失败（可忽略）: {e}")

    def _add_order_items_foreign_keys(self, cursor):
        """为 order_items 表添加外键约束（如果不存在）"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'order_items' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'order_items_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE order_items 
                    ADD CONSTRAINT order_items_ibfk_1 
                    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
                """)
                logger.debug("order_items 表外键约束 order_items_ibfk_1 已添加")
            
            if 'order_items_ibfk_2' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE order_items 
                    ADD CONSTRAINT order_items_ibfk_2 
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
                """)
                logger.debug("order_items 表外键约束 order_items_ibfk_2 已添加")
        except Exception as e:
            logger.warning(f"⚠️ order_items 表外键约束添加失败（可忽略）: {e}")

    def _add_addresses_foreign_keys(self, cursor):
        """为 addresses 表添加外键约束（如果不存在）"""
        try:
            # 检查 addresses 表和 users 表是否存在
            cursor.execute("""
                SELECT TABLE_NAME 
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME IN ('addresses', 'users')
            """)
            existing_tables = {row['TABLE_NAME'] for row in cursor.fetchall()}
            
            if 'addresses' not in existing_tables or 'users' not in existing_tables:
                logger.debug("⚠️ addresses 表或 users 表不存在，跳过外键添加")
                return
            
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'addresses' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'addresses_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE addresses 
                    ADD CONSTRAINT addresses_ibfk_1 
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                """)
                logger.debug("addresses 表外键约束 addresses_ibfk_1 已添加")
        except Exception as e:
            # 如果添加外键失败（可能是类型不匹配或表不存在），静默忽略
            logger.debug(f"⚠️ addresses 表外键约束添加失败（已忽略）: {e}")

    def _add_banner_foreign_keys(self, cursor):
        """为 banner 表添加外键约束（如果不存在）"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'banner' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'banner_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE banner 
                    ADD CONSTRAINT banner_ibfk_1 
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
                """)
                logger.debug("banner 表外键约束 banner_ibfk_1 已添加")
        except Exception as e:
            logger.debug(f"⚠️ banner 表外键约束添加失败（已忽略）: {e}")

    def _add_product_attributes_foreign_keys(self, cursor):
        """为 product_attributes 表添加外键约束（如果不存在）"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'product_attributes' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'product_attributes_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE product_attributes 
                    ADD CONSTRAINT product_attributes_ibfk_1 
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
                """)
                logger.debug("product_attributes 表外键约束 product_attributes_ibfk_1 已添加")
        except Exception as e:
            logger.debug(f"⚠️ product_attributes 表外键约束添加失败（已忽略）: {e}")

    def _add_product_skus_foreign_keys(self, cursor):
        """为 product_skus 表添加外键约束（如果不存在）"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'product_skus' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'product_skus_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE product_skus 
                    ADD CONSTRAINT product_skus_ibfk_1 
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
                """)
                logger.debug("product_skus 表外键约束 product_skus_ibfk_1 已添加")
        except Exception as e:
            logger.debug(f"⚠️ product_skus 表外键约束添加失败（已忽略）: {e}")

    def _add_user_unilevel_foreign_keys(self, cursor):
        """为 user_unilevel 表添加外键约束（如果不存在）"""
        try:
            # 检查 user_unilevel 表和 users 表是否存在
            cursor.execute("""
                SELECT TABLE_NAME 
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME IN ('user_unilevel', 'users')
            """)
            existing_tables = {row['TABLE_NAME'] for row in cursor.fetchall()}
            
            if 'user_unilevel' not in existing_tables or 'users' not in existing_tables:
                logger.debug("⚠️ user_unilevel 表或 users 表不存在，跳过外键添加")
                return
            
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'user_unilevel' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'user_unilevel_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE user_unilevel 
                    ADD CONSTRAINT user_unilevel_ibfk_1 
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                """)
                logger.debug("user_unilevel 表外键约束 user_unilevel_ibfk_1 已添加")
        except Exception as e:
            logger.debug(f"⚠️ user_unilevel 表外键约束添加失败（已忽略）: {e}")

    def _add_directors_foreign_keys(self, cursor):
        """为 directors 表添加外键约束（如果不存在）"""
        try:
            # 检查 directors 表和 users 表是否存在
            cursor.execute("""
                SELECT TABLE_NAME 
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME IN ('directors', 'users')
            """)
            existing_tables = {row['TABLE_NAME'] for row in cursor.fetchall()}
            
            if 'directors' not in existing_tables or 'users' not in existing_tables:
                logger.debug("⚠️ directors 表或 users 表不存在，跳过外键添加")
                return
            
            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'directors' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]
            
            if 'directors_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE directors 
                    ADD CONSTRAINT directors_ibfk_1 
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                """)
                logger.debug("directors 表外键约束 directors_ibfk_1 已添加")
        except Exception as e:
            logger.debug(f"⚠️ directors 表外键约束添加失败（已忽略）: {e}")

    def _add_director_dividends_foreign_keys(self, cursor):
        """为 director_dividends 表添加外键约束（如果不存在）"""
        try:
            # 检查 director_dividends 表和 users 表是否存在
            cursor.execute("""
                SELECT TABLE_NAME 
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME IN ('director_dividends', 'users')
            """)
            existing_tables = {row['TABLE_NAME'] for row in cursor.fetchall()}

            if 'director_dividends' not in existing_tables or 'users' not in existing_tables:
                logger.debug("⚠️ director_dividends 表或 users 表不存在，跳过外键添加")
                return

            cursor.execute("""
                SELECT CONSTRAINT_NAME 
                FROM information_schema.TABLE_CONSTRAINTS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'director_dividends' 
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing_fks = [row['CONSTRAINT_NAME'] for row in cursor.fetchall()]

            if 'director_dividends_ibfk_1' not in existing_fks:
                cursor.execute("""
                    ALTER TABLE director_dividends 
                    ADD CONSTRAINT director_dividends_ibfk_1 
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                """)
                logger.debug("director_dividends 表外键约束 director_dividends_ibfk_1 已添加")
        except Exception as e:
            logger.debug(f"⚠️ director_dividends 表外键约束添加失败（已忽略）: {e}")

    def _add_wx_applyment_foreign_keys(self, cursor):
        """微信进件主表外键"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME
                FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'wx_applyment'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing = [r['CONSTRAINT_NAME'] for r in cursor.fetchall()]
            if 'fk_wx_applyment_user' not in existing:
                cursor.execute("ALTER TABLE wx_applyment ADD CONSTRAINT fk_wx_applyment_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
                logger.debug("✅ wx_applyment 外键已添加")
            else:
                logger.debug("✅ wx_applyment 外键已存在，跳过添加")
        except Exception as e:
            logger.warning(f"⚠️ wx_applyment 外键添加失败: {e}")

    def _add_wx_applyment_media_foreign_keys(self, cursor):
        """进件材料表外键"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME
                FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'wx_applyment_media'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing = [r['CONSTRAINT_NAME'] for r in cursor.fetchall()]
            if 'fk_media_user' not in existing:
                cursor.execute("ALTER TABLE wx_applyment_media ADD CONSTRAINT fk_media_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
                logger.debug("✅ wx_applyment_media 外键已添加")
            else:
                logger.debug("✅ wx_applyment_media 外键已存在，跳过添加")
        except Exception as e:
            logger.warning(f"⚠️ wx_applyment_media 外键添加失败: {e}")

    def _add_merchant_settlement_accounts_foreign_keys(self, cursor):
        """结算账户表外键"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME
                FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'merchant_settlement_accounts'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing = [r['CONSTRAINT_NAME'] for r in cursor.fetchall()]
            if 'fk_merchant_account_user' not in existing:
                cursor.execute("ALTER TABLE merchant_settlement_accounts ADD CONSTRAINT fk_merchant_account_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
                logger.debug("✅ merchant_settlement_accounts 外键已添加")
            else:
                logger.debug("✅ merchant_settlement_accounts 外键已存在，跳过添加")
        except Exception as e:
            logger.warning(f"⚠️ merchant_settlement_accounts 外键添加失败: {e}")

    def _add_merchant_realname_verification_foreign_keys(self, cursor):
        """实名认证表外键"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME
                FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'merchant_realname_verification'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing = [r['CONSTRAINT_NAME'] for r in cursor.fetchall()]
            if 'fk_realname_user' not in existing:
                cursor.execute("ALTER TABLE merchant_realname_verification ADD CONSTRAINT fk_realname_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
                logger.debug("✅ merchant_realname_verification 外键已添加")
            else:
                logger.debug("✅ merchant_realname_verification 外键已存在，跳过添加")
        except Exception as e:
            logger.warning(f"⚠️ merchant_realname_verification 外键添加失败: {e}")

    def _add_user_bankcard_operations_foreign_keys(self, cursor):
        """银行卡操作日志表外键"""
        try:
            cursor.execute("""
                SELECT CONSTRAINT_NAME
                FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'user_bankcard_operations'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
            """)
            existing = [r['CONSTRAINT_NAME'] for r in cursor.fetchall()]
            if 'fk_bankcard_op_user' not in existing:
                cursor.execute("ALTER TABLE user_bankcard_operations ADD CONSTRAINT fk_bankcard_op_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
            else:
                logger.debug("✅ user_bankcard_operations: fk_bankcard_op_user 已存在，跳过添加")

            if 'fk_bankcard_op_target' not in existing:
                cursor.execute("ALTER TABLE user_bankcard_operations ADD CONSTRAINT fk_bankcard_op_target FOREIGN KEY (target_id) REFERENCES merchant_settlement_accounts(id) ON DELETE CASCADE")
            else:
                logger.debug("✅ user_bankcard_operations: fk_bankcard_op_target 已存在，跳过添加")

            logger.debug("✅ user_bankcard_operations 外键处理完成")
        except Exception as e:
            logger.warning(f"⚠️ user_bankcard_operations 外键添加失败: {e}")

    def _init_finance_accounts(self, cursor):
        accounts = [
            ('周补贴池', 'subsidy_pool'),
            ('公益基金', 'public_welfare'),
            ('平台维护', 'platform'),
            ('荣誉董事分红', 'honor_director'),
            ('社区店', 'community'),
            ('城市运营中心', 'city_center'),
            ('大区分公司', 'region_company'),
            ('事业发展基金', 'development'),
            ('公司积分账户', 'company_points'),
            ('公司余额账户', 'company_balance'),
            ('平台收入池（会员商品）', 'platform_revenue_pool'),
            ('微信进件手续费', 'wx_applyment_fee'),
        ]

        # 检查是否已存在账户，如果存在则不删除重新初始化
        cursor.execute("SELECT COUNT(*) as count FROM finance_accounts")
        count = cursor.fetchone()['count']

        if count == 0:
            # 只有表为空时才初始化
            for name, acc_type in accounts:
                cursor.execute(
                    "INSERT INTO finance_accounts (account_name, account_type, balance) VALUES (%s, %s, 0)",
                    (name, acc_type)
                )
            logger.info(f"✅ 初始化 {len(accounts)} 个资金池账户")
        else:
            logger.info(f"⚠️ finance_accounts 表已存在 {count} 条记录，跳过初始化（保留现有余额）")

        # 确保存在 config_params 列（JSON），兼容旧表结构
        try:
            cursor.execute("SHOW COLUMNS FROM finance_accounts LIKE 'config_params'")
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE finance_accounts ADD COLUMN config_params JSON DEFAULT NULL")
                logger.info("已为 finance_accounts 添加 config_params 列")
        except Exception as e:
            logger.debug(f"⚠️ 添加 config_params 列失败（已忽略）: {e}")

        # 确保每个子资金池的行存在且其 config_params 中包含 allocation 字段（幂等）
        try:
            defaults = {
                'merchant_balance': '0.80',
                'public_welfare': '0.01',
                'maintain_pool': '0.01',
                'subsidy_pool': '0.12',
                'director_pool': '0.02',
                'shop_pool': '0.01',
                'city_pool': '0.01',
                'branch_pool': '0.005',
                'fund_pool': '0.015'
            }
            for atype, aval in defaults.items():
                cursor.execute("SELECT id, config_params FROM finance_accounts WHERE account_type=%s LIMIT 1", (atype,))
                row = cursor.fetchone()
                if row:
                    cp = row.get('config_params')
                    need_update = False
                    try:
                        if cp:
                            parsed = json.loads(cp) if isinstance(cp, str) else cp
                        else:
                            parsed = {}
                        if not isinstance(parsed, dict):
                            parsed = {}
                        # 如果没有 allocation 字段或 allocation 不等于默认，则更新
                        if parsed.get('allocation') != str(aval):
                            parsed['allocation'] = str(aval)
                            need_update = True
                    except Exception:
                        parsed = {'allocation': str(aval)}
                        need_update = True

                    if need_update:
                        cursor.execute("UPDATE finance_accounts SET config_params=%s WHERE id=%s", (json.dumps(parsed, ensure_ascii=False), row['id']))
                else:
                    # 插入新的账户行
                    parsed = {'allocation': str(aval)}
                    cursor.execute(
                        "INSERT INTO finance_accounts(account_name, account_type, balance, config_params) VALUES (%s,%s,%s,%s)",
                        (atype, atype, 0, json.dumps(parsed, ensure_ascii=False))
                    )
            logger.info("已确保各资金池行存在且写入默认 allocation 到 config_params")
        except Exception as e:
            logger.debug(f"⚠️ 确保各资金池 config_params 写入失败（已忽略）: {e}")

    def create_test_data(self, cursor, conn) -> int:
        logger.info("\n--- 创建测试数据 ---")

        pwd_hash = '$2b$12$9LjsHS5r4u1M9K4nG5KZ7e6zZxZn7qZ'

        mobile = '13800138004'
        # 幂等处理：如果手机号已存在则复用该用户，否则插入新用户
        cursor.execute("SELECT id FROM users WHERE mobile = %s", (mobile,))
        existing = cursor.fetchone()
        if existing:
            user_id = existing['id']
            logger.debug(f"测试用户手机号已存在，复用用户ID: {user_id}")
        else:
            cursor.execute(
                "INSERT INTO users (mobile, password_hash, name, status) VALUES (%s, %s, %s, 1)",
                (mobile, pwd_hash, '测试用户')
            )
            user_id = cursor.lastrowid

        # 创建会员商品（若名称已存在则跳过）
        product_name_member = '会员星卡'
        cursor.execute("SELECT id FROM products WHERE name = %s", (product_name_member,))
        existing_prod = cursor.fetchone()
        if existing_prod:
            logger.debug(f"会员商品已存在，跳过插入，product_id={existing_prod['id']}")
        else:
            cursor.execute(
                """INSERT INTO products (name, is_member_product, user_id, status)
                   VALUES (%s, 1, %s, 1)""",
                (product_name_member, user_id)
            )

        # 创建普通商品（若名称已存在则跳过）
        product_name_normal = '普通商品'
        cursor.execute("SELECT id FROM products WHERE name = %s", (product_name_normal,))
        existing_normal = cursor.fetchone()
        if existing_normal:
            logger.debug(f"普通商品已存在，跳过插入，product_id={existing_normal['id']}")
        else:
            cursor.execute(
                """INSERT INTO products (name, is_member_product, user_id, status)
                   VALUES (%s, 0, %s, 1)""",
                (product_name_normal, user_id)
            )

        conn.commit()
        logger.debug(f"测试数据创建完成 | 用户ID: {user_id}")
        return user_id


# ==================== 数据库初始化函数 ====================

def create_database():
    """根据 `.env` 中的配置，创建 MySQL 数据库（如果不存在）。

    该函数会加载环境变量，然后以不指定数据库的方式连接 MySQL，执行
    `CREATE DATABASE IF NOT EXISTS ...`。调用者可在程序启动时先调用此函数。
    """
    import pymysql
    cfg = get_db_config()
    host = cfg['host']
    port = cfg['port']
    user = cfg['user']
    password = cfg['password']
    dbname = cfg['database']

    conn = pymysql.connect(host=host, port=port, user=user, password=password, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{dbname}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
            )
    finally:
        conn.close()

    print("数据库创建完成（若不存在）。")


def initialize_database():
    """初始化数据库表结构（如果尚未创建）。

    先确保数据库存在（调用 `create_database()`），再通过 pymysql 创建表结构。
    """
    print("正在检查数据库表结构...")
    # 确保数据库已创建
    create_database()

    cfg = get_db_config()
    conn = pymysql.connect(**cfg, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cursor:
            db_manager = DatabaseManager()
            db_manager.init_all_tables(cursor)
        conn.commit()
    finally:
        conn.close()

    print("数据库表结构初始化完成。")


def create_test_data():
    """创建测试数据（可选）"""
    print("正在创建测试数据...")
    cfg = get_db_config()
    conn = pymysql.connect(**cfg, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cursor:
            db_manager = DatabaseManager()
            db_manager.create_test_data(cursor, conn)
    finally:
        conn.close()
    print("测试数据创建完成。")


# ==================== 订单系统相关函数（来自 order/database_setup1.py） ====================

def init_db():
    """一键初始化数据库（兼容 order 模块的接口）
    
    这是 initialize_database() 的别名，用于保持与 order 模块的兼容性。
    """
    initialize_database()
    print("[database_setup] 初始化完成！")


def auto_receive_task(db_cfg: dict = None):
    """自动收货和结算守护进程
    
    该函数会启动一个后台线程，每小时检查一次待收货订单，
    如果订单超过自动收货时间，则自动完成订单并结算给商家。
    
    参数:
        db_cfg: 数据库配置字典（可选，默认使用 get_db_config()）
    
    注意:
        这是一个守护进程，会在后台持续运行。
        需要在应用启动时调用此函数。
    """
    import threading
    import time
    from datetime import datetime
    
    def run():
        while True:
            try:
                from core.database import get_conn
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        now = datetime.now()
                        cur.execute(
                            "SELECT id, order_number, total_amount FROM orders "
                            "WHERE status='pending_recv' AND auto_recv_time<=%s",
                            (now,)
                        )
                        for row in cur.fetchall():
                            cur.execute(
                                "UPDATE orders SET status='completed' WHERE id=%s",
                                (row["id"],)
                            )
                            # 注意：settle_to_merchant 函数需要从 order 模块导入
                            # 这里只做订单状态更新，结算逻辑需要单独处理
                            conn.commit()
                            logger.debug(f"[auto_receive] 订单 {row['order_number']} 已自动完成。")
            except Exception as e:
                logger.error(f"[auto_receive] 异常: {e}")
            time.sleep(3600)  # 每小时检查一次
    
    t = threading.Thread(target=run, daemon=True)
    t.start()
    logger.info("自动收货守护进程已启动")


# ==================== Product 模块相关功能（已移除 SQLAlchemy ORM） ====================

def _fix_pinyin():
    """补全商品拼音
    
    该函数会检查所有商品，如果 pinyin 字段为空，则自动生成拼音。
    可重复执行，幂等操作。
    """
    try:
        from pypinyin import lazy_pinyin, Style
        from core.database import get_conn
        
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询所有商品
                cur.execute("SELECT id, name, pinyin FROM products")
                products = cur.fetchall()
                
                updated_count = 0
                for product in products:
                    if not product.get('pinyin'):
                        pinyin = ' '.join(lazy_pinyin(product['name'], style=Style.NORMAL)).upper()
                        cur.execute("UPDATE products SET pinyin = %s WHERE id = %s", (pinyin, product['id']))
                        updated_count += 1
                
                conn.commit()
                logger.debug(f"商品拼音补全完成，更新了 {updated_count} 条记录")
    except ImportError:
        logger.warning("⚠️ pypinyin 未安装，跳过拼音补全功能")
    except Exception as e:
        logger.error(f"❌ 拼音补全失败: {e}")



# 在文件末尾添加
def start_background_tasks():
    """启动后台任务"""
    from core.scheduler import scheduler
    scheduler.start()

# 在 initialize_database 函数后调用
def initialize_database():
    """初始化数据库表结构（如果尚未创建）"""
    print("正在检查数据库表结构...")
    create_database()

    cfg = get_db_config()
    conn = pymysql.connect(**cfg, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cursor:
            db_manager = DatabaseManager()
            db_manager.init_all_tables(cursor)
        conn.commit()
    finally:
        conn.close()

    print("数据库表结构初始化完成。")
    print("启动后台任务...")
    start_background_tasks()