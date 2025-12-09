"""
统一的数据库连接管理模块
使用 pymysql 作为统一的数据库连接方式
"""
import pymysql
from contextlib import contextmanager
from typing import Optional
from core.config import get_db_config

# 全局连接配置缓存
_db_config = None


def get_db_config_cached():
    """获取缓存的数据库配置"""
    global _db_config
    if _db_config is None:
        _db_config = get_db_config()
    return _db_config


@contextmanager
def get_conn():
    """
    获取数据库连接的上下文管理器（统一入口）
    
    使用示例:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                result = cur.fetchone()
    """
    cfg = get_db_config_cached()
    conn = pymysql.connect(
        host=cfg['host'],
        port=cfg['port'],
        user=cfg['user'],
        password=cfg['password'],
        database=cfg['database'],
        charset=cfg['charset'],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False  # 统一使用事务管理
    )
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def get_cursor():
    """
    获取数据库游标的上下文管理器（便捷方法）
    
    使用示例:
        with get_cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            result = cur.fetchone()
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            yield cur
            conn.commit()


def execute_query(sql: str, params: Optional[tuple] = None) -> list:
    """
    执行查询并返回结果列表
    
    Args:
        sql: SQL 查询语句
        params: 查询参数（元组或字典）
    
    Returns:
        查询结果列表（字典格式）
    """
    with get_cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def execute_one(sql: str, params: Optional[tuple] = None) -> Optional[dict]:
    """
    执行查询并返回单条结果
    
    Args:
        sql: SQL 查询语句
        params: 查询参数（元组或字典）
    
    Returns:
        查询结果（字典格式），如果没有结果返回 None
    """
    with get_cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute_update(sql: str, params: Optional[tuple] = None) -> int:
    """
    执行更新/插入/删除操作
    
    Args:
        sql: SQL 语句
        params: 参数（元组或字典）
    
    Returns:
        受影响的行数
    """
    with get_cursor() as cur:
        affected_rows = cur.execute(sql, params)
        return affected_rows


def execute_insert(sql: str, params: Optional[tuple] = None) -> int:
    """
    执行插入操作并返回插入的 ID
    
    Args:
        sql: INSERT SQL 语句
        params: 参数（元组或字典）
    
    Returns:
        插入记录的 ID
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            conn.commit()
            return cur.lastrowid


def execute_transaction(operations: list) -> bool:
    """
    执行事务操作（多个 SQL 操作）
    
    Args:
        operations: 操作列表，每个元素是 (sql, params) 元组
    
    Returns:
        是否成功
    """
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                for sql, params in operations:
                    cur.execute(sql, params)
                conn.commit()
                return True
    except Exception:
        return False
