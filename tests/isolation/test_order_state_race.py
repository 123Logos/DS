import json
import os
from concurrent.futures import ThreadPoolExecutor

import httpx


def _post(url: str, payload: dict) -> httpx.Response:
    with httpx.Client(timeout=15) as client:
        return client.post(url, json=payload)


def test_payment_and_cancel_have_one_legal_terminal_state(seed_order, isolated_mysql):
    payment = json.loads(os.environ["ISOLATED_PAYMENT_CALLBACK_BODY"])
    cancel = json.loads(os.environ["ISOLATED_CANCEL_BODY"])
    payment_url = os.environ["ISOLATED_PAYMENT_CALLBACK_URL"]
    cancel_url = os.environ["ISOLATED_CANCEL_URL"]
    requests = [(payment_url, payment)] * 10 + [(cancel_url, cancel)] * 10

    with ThreadPoolExecutor(max_workers=20) as pool:
        responses = list(pool.map(lambda item: _post(*item), requests))
    assert all(response.status_code < 500 for response in responses)

    with isolated_mysql.cursor() as cursor:
        cursor.execute(os.environ["ISOLATED_ORDER_STATE_QUERY"], ("test_219_",))
        state, stock, balance = cursor.fetchone()
    assert state in {"paid", "cancelled"}
    assert stock >= 0
    assert balance >= 0

    with isolated_mysql.cursor() as cursor:
        cursor.execute(os.environ["ISOLATED_ORDER_SIDE_EFFECT_QUERY"], ("test_219_",))
        assert cursor.fetchone()[0] == 1
