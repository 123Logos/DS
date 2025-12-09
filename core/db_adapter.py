"""
数据库适配器 - 将 SQLAlchemy Session 接口适配为 pymysql 接口
用于逐步迁移从 SQLAlchemy 到 pymysql
"""
from contextlib import contextmanager
from typing import Optional, Any, Dict, List
from core.database import get_conn
import pymysql


class PyMySQLAdapter:
    """
    pymysql 适配器，模拟 SQLAlchemy Session 的部分接口
    用于简化从 SQLAlchemy 到 pymysql 的迁移
    """
    
    def __init__(self):
        self._conn = None
        self._cursor = None
    
    @contextmanager
    def begin(self):
        """开始事务（上下文管理器）"""
        if self._conn is None:
            self._conn = get_conn().__enter__()
            self._cursor = self._conn.cursor()
        try:
            yield self
            self._conn.commit()
        except Exception:
            if self._conn:
                self._conn.rollback()
            raise
    
    def execute(self, sql: str, params: Optional[Dict[str, Any]] = None):
        """
        执行 SQL 语句
        
        Args:
            sql: SQL 语句（支持 :param 格式，会自动转换为 %s）
            params: 参数字典
        
        Returns:
            结果对象（模拟 SQLAlchemy Result）
        """
        if self._conn is None:
            self._conn = get_conn().__enter__()
            self._cursor = self._conn.cursor()
        
        # 将 :param 格式转换为 %s 格式
        if params:
            sql, values = self._convert_sql_params(sql, params)
        else:
            values = None
        
        self._cursor.execute(sql, values)
        return ResultProxy(self._cursor)
    
    def _convert_sql_params(self, sql: str, params: Dict[str, Any]) -> tuple:
        """将 SQLAlchemy 的 :param 格式转换为 pymysql 的 %s 格式，并返回转换后的 SQL 和参数元组"""
        result_sql = sql
        param_list = []
        # 按顺序替换参数
        for key, value in params.items():
            result_sql = result_sql.replace(f":{key}", "%s", 1)  # 只替换第一个
            param_list.append(value)
        return result_sql, tuple(param_list)
    
    def commit(self):
        """提交事务"""
        if self._conn:
            self._conn.commit()
    
    def rollback(self):
        """回滚事务"""
        if self._conn:
            self._conn.rollback()
    
    def close(self):
        """关闭连接"""
        if self._cursor:
            self._cursor.close()
        if self._conn:
            self._conn.close()
            self._conn = None
            self._cursor = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


class ResultProxy:
    """模拟 SQLAlchemy Result 对象"""
    
    def __init__(self, cursor: pymysql.cursors.DictCursor):
        self._cursor = cursor
        self._rows = None
    
    def fetchone(self):
        """获取单行结果"""
        if self._rows is None:
            self._rows = self._cursor.fetchall()
        if self._rows:
            row = self._rows[0]
            self._rows = self._rows[1:]
            return RowProxy(row)
        return None
    
    def fetchall(self):
        """获取所有结果"""
        if self._rows is None:
            self._rows = self._cursor.fetchall()
        return [RowProxy(row) for row in self._rows]
    
    @property
    def lastrowid(self):
        """获取最后插入的 ID"""
        return self._cursor.lastrowid
    
    @property
    def rowcount(self):
        """获取受影响的行数"""
        return self._cursor.rowcount


class RowProxy:
    """模拟 SQLAlchemy Row 对象，支持属性访问和字典访问"""
    
    def __init__(self, row: Dict):
        self._row = row
    
    def __getattr__(self, name: str):
        """支持属性访问，如 row.balance"""
        if name in self._row:
            return self._row[name]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
    
    def __getitem__(self, key: str):
        """支持字典访问，如 row['balance']"""
        return self._row[key]
    
    def __contains__(self, key: str):
        """支持 in 操作"""
        return key in self._row
    
    def get(self, key: str, default=None):
        """字典风格的 get 方法"""
        return self._row.get(key, default)
