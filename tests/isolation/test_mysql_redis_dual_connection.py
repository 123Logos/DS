import os
from unittest.mock import patch

import httpx


def test_security_check_fails_closed_when_dependency_fault_is_injected(
    isolated_mysql, isolated_redis
):
    target = os.environ["ISOLATED_SECURITY_FAULT_PATCH_TARGET"]
    endpoint = os.environ["ISOLATED_SECURITY_URL"]
    body = {
        "content": os.environ.get("ISOLATED_SECURITY_CONTENT", "test_219_security_probe"),
        "scene": 1,
    }

    with patch(target, side_effect=TimeoutError("test_219 injected dependency timeout")):
        with httpx.Client(timeout=15) as client:
            response = client.post(endpoint, json=body)

    assert response.status_code in {400, 401, 403, 503}
    assert not (response.status_code == 200 and response.json().get("pass") is True)

    query = os.environ["ISOLATED_SECURITY_DIRTY_WRITE_QUERY"]
    with isolated_mysql.cursor() as cursor:
        cursor.execute(query, ("test_219_",))
        assert cursor.fetchone()[0] == 0
