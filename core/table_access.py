"""
动态表访问工具模块
提供动态获取表结构并构造 SQL 查询的功能
"""
from typing import Dict, List, Optional, Tuple
from decimal import Decimal


# 缓存表结构信息，避免重复查询
_table_structure_cache: Dict[str, Dict[str, any]] = {}


def get_table_structure(cursor, table_name: str, use_cache: bool = True) -> Dict[str, any]:
    """
    获取表结构信息
    
    Args:
        cursor: 数据库游标
        table_name: 表名
        use_cache: 是否使用缓存
    
    Returns:
        包含字段信息的字典：{
            'fields': [字段名列表],
            'asset_fields': [资产字段名列表],
            'field_types': {字段名: 字段类型}
        }
    """
    cache_key = table_name
    
    # 如果使用缓存且缓存存在，直接返回
    if use_cache and cache_key in _table_structure_cache:
        return _table_structure_cache[cache_key]
    
    # 查询表结构
    cursor.execute(f"SHOW COLUMNS FROM {table_name}")
    columns = cursor.fetchall()
    
    fields = []
    asset_fields = []
    field_types = {}
    
    for col in columns:
        field_name = col['Field']
        field_type = col['Type'].upper()
        
        fields.append(field_name)
        field_types[field_name] = field_type
        
        # 判断是否为资产字段（数值类型）
        if any(num_type in field_type for num_type in ['DECIMAL', 'NUMERIC', 'FLOAT', 'DOUBLE', 'INT', 'BIGINT', 'TINYINT', 'SMALLINT', 'MEDIUMINT']):
            asset_fields.append(field_name)
    
    result = {
        'fields': fields,
        'asset_fields': asset_fields,
        'field_types': field_types
    }
    
    # 缓存结果
    if use_cache:
        _table_structure_cache[cache_key] = result
    
    return result


def build_select_sql(table_name: str, structure: Dict[str, any], 
                     where_clause: Optional[str] = None,
                     order_by: Optional[str] = None,
                     limit: Optional[str] = None,
                     select_fields: Optional[List[str]] = None) -> str:
    """
    动态构造 SELECT 语句
    
    Args:
        table_name: 表名
        structure: 表结构信息（从 get_table_structure 获取）
        where_clause: WHERE 子句（不包含 WHERE 关键字）
        order_by: ORDER BY 子句（不包含 ORDER BY 关键字）
        limit: LIMIT 子句（不包含 LIMIT 关键字）
        select_fields: 指定要选择的字段列表，如果为 None 则选择所有字段
    
    Returns:
        构造的 SQL 语句
    """
    fields = select_fields if select_fields else structure['fields']
    asset_fields = structure['asset_fields']
    
    # 构造 SELECT 字段列表，对资产字段设置默认值
    select_parts = []
    for field in fields:
        if field in asset_fields:
            # 资产字段：如果不存在则默认为 0
            select_parts.append(f"COALESCE({field}, 0) AS {field}")
        else:
            # 非资产字段：直接选择
            select_parts.append(field)
    
    sql = f"SELECT {', '.join(select_parts)} FROM {table_name}"
    
    if where_clause:
        sql += f" WHERE {where_clause}"
    
    if order_by:
        sql += f" ORDER BY {order_by}"
    
    if limit:
        sql += f" LIMIT {limit}"
    
    return sql


def build_dynamic_select(cursor, table_name: str, 
                        where_clause: Optional[str] = None,
                        order_by: Optional[str] = None,
                        limit: Optional[str] = None,
                        select_fields: Optional[List[str]] = None) -> str:
    """
    动态构造并返回 SELECT 语句（便捷方法）
    
    Args:
        cursor: 数据库游标
        table_name: 表名
        where_clause: WHERE 子句
        order_by: ORDER BY 子句
        limit: LIMIT 子句
        select_fields: 指定要选择的字段列表
    
    Returns:
        构造的 SQL 语句
    """
    structure = get_table_structure(cursor, table_name)
    return build_select_sql(table_name, structure, where_clause, order_by, limit, select_fields)


def clear_table_cache(table_name: Optional[str] = None):
    """
    清除表结构缓存
    
    Args:
        table_name: 表名，如果为 None 则清除所有缓存
    """
    global _table_structure_cache
    if table_name:
        _table_structure_cache.pop(table_name, None)
    else:
        _table_structure_cache.clear()

