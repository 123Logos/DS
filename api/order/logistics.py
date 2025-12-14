from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import requests
import json

router = APIRouter()

class LogisticsManager:
    @staticmethod
    def query(tracking_number: str, company_code: str = "auto") -> Dict[str, Any]:
        url = "https://poll.kuaidi100.com/poll/query.do"
        param = {
            "com": company_code,
            "num": tracking_number,
            "phone": "",
            "from": "",
            "to": "",
            "resultv2": "0",
            "show": "0",
            "order": "desc"
        }
        payload = {
            "customer": "50592E1BA860467BD205A6A3D65D83EB",
            "sign": "5F637F5A2A0BC7C1C398A0FF6F904817",
            "param": json.dumps(param)
        }
        try:
            resp = requests.post(url, data=payload, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            raise HTTPException(status_code=500, detail=f"物流查询失败: {str(e)}")

class LogisticsQuery(BaseModel):
    tracking_number: str
    company_code: Optional[str] = "auto"

@router.post("/query", summary="查询物流信息")
def logistics_query(body: LogisticsQuery) -> Dict[str, Any]:
    data = LogisticsManager.query(body.tracking_number, body.company_code)
    return {"ok": True, "data": data}

# —— 与项目同构的注册函数 ——
def register_logistics_routes(app):
    app.include_router(router, prefix="/logistics", tags=["订单系统"])