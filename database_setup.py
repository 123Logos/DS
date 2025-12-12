# database_setup.py - 表结构与项目2完全一致
# 注意：此文件主要用于数据库表结构定义和初始化
# 日常数据库操作请使用 core.database.get_conn()
# 已移除 SQLAlchemy ORM，完全使用 pymysql
import pymysql
from core.config import get_db_config
from core.logging import get_logger

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
                    points DECIMAL(12,4) NOT NULL DEFAULT 0.0000,
                    promotion_balance DECIMAL(14,2) NOT NULL DEFAULT 0.00,
                    member_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000,
                    merchant_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000,
                    merchant_balance DECIMAL(14,2) NOT NULL DEFAULT 0.00,
                    status TINYINT NOT NULL DEFAULT 1,
                    level_changed_at DATETIME NULL,
                    referral_id BIGINT UNSIGNED NULL COMMENT '推荐人id',
                    referral_code VARCHAR(6) NULL COMMENT '推荐码',
                    withdrawable_balance BIGINT NOT NULL DEFAULT 0 COMMENT '可提现余额',
                    avatar_path VARCHAR(255) NULL DEFAULT NULL COMMENT '头像路径',
                    is_merchant TINYINT(1) NOT NULL DEFAULT 0 COMMENT '判断是不是商家',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_mobile (mobile),
                    INDEX idx_email (email),
                    INDEX idx_member_level (member_level),
                    UNIQUE KEY uk_referral_code (referral_code)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'products': """
                CREATE TABLE IF NOT EXISTS products (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    pinyin TEXT,
                    description TEXT,
                    category VARCHAR(100),
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
                    total_amount DECIMAL(12,2) NOT NULL,
                    original_amount DECIMAL(12,2) DEFAULT 0.00,
                    points_discount DECIMAL(12,4) NOT NULL DEFAULT 0.0000,
                    is_member_order TINYINT(1) NOT NULL DEFAULT 0,
                    is_vip_item TINYINT(1) DEFAULT 0 COMMENT '1=含会员商品（兼容订单系统）',
                    status VARCHAR(30) NOT NULL DEFAULT 'pending_pay',
                    refund_status VARCHAR(30) DEFAULT NULL,
                    consignee_name VARCHAR(100),
                    consignee_phone VARCHAR(20),
                    province VARCHAR(20) DEFAULT '',
                    city VARCHAR(20) DEFAULT '',
                    district VARCHAR(20) DEFAULT '',
                    shipping_address TEXT,
                    pay_way ENUM('wechat') DEFAULT 'wechat',
                    refund_reason TEXT,
                    auto_recv_time DATETIME NULL COMMENT '7 天后自动收货',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_user (user_id),
                    INDEX idx_order_number (order_number),
                    INDEX idx_created_at (created_at),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            'order_items': """
                CREATE TABLE IF NOT EXISTS order_items (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    order_id BIGINT UNSIGNED NOT NULL,
                    product_id BIGINT UNSIGNED NOT NULL,
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
                    balance DECIMAL(14,2) NOT NULL DEFAULT 0.00,
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
                    change_amount DECIMAL(14,2) NOT NULL,
                    balance_after DECIMAL(14,2),
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
                    amount DECIMAL(12,2) NOT NULL,
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
                    amount DECIMAL(14,2) NOT NULL,
                    tax_amount DECIMAL(14,2) NOT NULL DEFAULT 0.00,
                    actual_amount DECIMAL(14,2) NOT NULL DEFAULT 0.00,
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
                    quantity INT DEFAULT 1,
                    selected TINYINT DEFAULT 1,
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uk_user_product (user_id, product_id),
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
                    status ENUM('applied','seller_ok','success','rejected') DEFAULT 'applied',
                    reject_reason TEXT,
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
        }

        # 定义必需字段（用于检查和更新已存在的表）
        required_columns = {
            'users': {
                'member_points': 'member_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000',
                'merchant_points': 'merchant_points DECIMAL(12,4) NOT NULL DEFAULT 0.0000',
                'withdrawable_balance': 'withdrawable_balance BIGINT NOT NULL DEFAULT 0 COMMENT \'可提现余额\'',
                'is_merchant': 'is_merchant TINYINT(1) NOT NULL DEFAULT 0 COMMENT \'判断是不是商家\'',
                'status': 'status TINYINT NOT NULL DEFAULT 1',
                'avatar_path': 'avatar_path VARCHAR(255) NULL DEFAULT NULL COMMENT \'头像路径\'',
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
        ]

        cursor.execute("DELETE FROM finance_accounts")
        for name, acc_type in accounts:
            cursor.execute(
                "INSERT INTO finance_accounts (account_name, account_type, balance) VALUES (%s, %s, 0)",
                (name, acc_type)
            )
        logger.debug(f"初始化 {len(accounts)} 个资金池账户")

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