from fastapi import APIRouter
import threading
import time
from datetime import datetime
from core.database import get_conn
from services.finance_service import settle_to_merchant
from decimal import Decimal

def auto_receive_task():
    def run():
        while True:
            try:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        now = datetime.now()
                        cur.execute("SELECT id,order_number,total_amount FROM orders WHERE status='pending_recv' AND auto_recv_time<=%s", (now,))
                        for row in cur.fetchall():
                            cur.execute("UPDATE orders SET status='completed' WHERE id=%s", (row["id"],))
                            settle_to_merchant(row["total_amount"])
                            conn.commit()
                            print(f"[auto_receive] 订单 {row['order_number']} 已自动完成并结算。")
            except Exception as e:
                print("[auto_receive] 异常:", e)
            time.sleep(3600)
    t = threading.Thread(target=run, daemon=True)
    t.start()
