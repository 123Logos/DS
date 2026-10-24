import json
import os
from concurrent.futures import ThreadPoolExecutor

import httpx


def _post(url: str, payload: dict, token: str) -> httpx.Response:
    with httpx.Client(timeout=15) as client:
        return client.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})


def test_revoked_token_is_rejected_concurrently(seed_user, isolated_redis):
    with httpx.Client(timeout=15) as client:
        login = client.post(
            os.environ["ISOLATED_LOGIN_URL"],
            json=json.loads(os.environ["ISOLATED_LOGIN_BODY"]),
        )
    assert login.is_success
    token = login.json()["token"]

    revoke_url = os.environ["ISOLATED_REVOKE_URL"]
    revoke_body = json.loads(os.environ.get("ISOLATED_REVOKE_BODY", "{}"))
    with ThreadPoolExecutor(max_workers=10) as pool:
        revoke_results = list(
            pool.map(lambda _: _post(revoke_url, revoke_body, token), range(10))
        )
    assert all(response.status_code in {200, 204, 401, 403} for response in revoke_results)

    protected_url = os.environ["ISOLATED_PROTECTED_URL"]
    with ThreadPoolExecutor(max_workers=10) as pool:
        protected_results = list(
            pool.map(
                lambda _: _post(protected_url, {}, token),
                range(10),
            )
        )
    assert all(response.status_code in {401, 403} for response in protected_results)

    deny_prefix = os.environ["ISOLATED_JWT_DENYLIST_PREFIX"]
    assert list(isolated_redis.scan_iter(match=f"{deny_prefix}*"))
