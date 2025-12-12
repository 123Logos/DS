# product_ext.py - 商品扩展（中文）
from fastapi import APIRouter, HTTPException
from typing import Optional, Dict, Any
from core.database import get_conn
from core.table_access import build_dynamic_select

router = APIRouter(tags=["商品管理"], responses={404: {"description": "未找到"}})

@router.get(
    "/products/{id}/rules",
    summary="📋 商品购买规则",
    description="查询指定商品的会员价、购买规则及权益说明"
)
def get_product_rules(id: int):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "products",
                where_clause="id = %s",
                select_fields=["id", "is_member_product", "buy_rule"]
            )
            cur.execute(select_sql, (id,))
            prod = cur.fetchone()
            if not prod:
                raise HTTPException(status_code=404, detail="商品不存在")
            return {
                "product_id": prod['id'],
                "is_member_product": bool(prod['is_member_product']),
                "price_fixed": 1980 if prod['is_member_product'] else None,
                "buy_rule": prod['buy_rule'],
                "rule_desc": "购买1份即可解锁对应星级权益" if prod['is_member_product'] else "普通商品，无等级限制"
            }
