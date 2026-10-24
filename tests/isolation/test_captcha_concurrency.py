import json
import os
from concurrent.futures import ThreadPoolExecutor

import httpx


def _request() -> httpx.Response:
    endpoint = os.environ["ISOLATED_CAPTCHA_VERIFY_URL"]
    payload = json.loads(os.environ["ISOLATED_CAPTCHA_VERIFY_BODY"])
    with httpx.Client(timeout=15) as client:
        return client.post(endpoint, json=payload)


def test_same_captcha_is_consumed_once(seed_user, isolated_mysql, isolated_redis):
    with ThreadPoolExecutor(max_workers=30) as pool:
        responses = list(pool.map(lambda _: _request(), range(30)))

    successful = [
        response for response in responses
        if response.is_success and response.json().get("success") is True
    ]
    assert len(successful) == 1
    assert sum(response.status_code >= 400 for response in responses) == 29

    query = os.environ["ISOLATED_CAPTCHA_REDEEM_QUERY"]
    with isolated_mysql.cursor() as cursor:
        cursor.execute(query, ("test_219_",))
        assert cursor.fetchone()[0] == 1
