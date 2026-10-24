import json
import os
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx


def _refund() -> httpx.Response:
    with httpx.Client(timeout=15) as client:
        return client.post(
            os.environ["ISOLATED_REFUND_URL"],
            json=json.loads(os.environ["ISOLATED_REFUND_BODY"]),
        )


def test_external_refund_success_local_commit_failure_is_recoverable(
    seed_order, isolated_mysql
):
    target = os.environ["ISOLATED_REFUND_COMMIT_PATCH_TARGET"]
    with patch(target, side_effect=RuntimeError("test_219 local commit failure")):
        response = _refund()
    assert response.status_code >= 400

    with isolated_mysql.cursor() as cursor:
        cursor.execute(os.environ["ISOLATED_REFUND_RECONCILIATION_QUERY"], ("test_219_",))
        pending_count, external_reference_count = cursor.fetchone()
    assert pending_count >= 1
    assert external_reference_count == 1

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: _refund(), range(2)))
    assert all(response.status_code >= 400 for response in responses)

    with isolated_mysql.cursor() as cursor:
        cursor.execute(os.environ["ISOLATED_REFUND_EXTERNAL_COUNT_QUERY"], ("test_219_",))
        assert cursor.fetchone()[0] == 1
