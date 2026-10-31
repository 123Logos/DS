"""Actual app HTTP/business path with provider call intercepted at its boundary."""
import json


def test_product_content_review_fails_closed_without_partial_writes(http, db, users, token, monkeypatch, evidence):
    from api.product import routes

    calls = []

    async def provider_boundary(text, *, openid, scene=1):
        calls.append(text)
        if text == "UNSAFE-CANARY":
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="内容未通过安全审核，请修改后重试")

    monkeypatch.setattr(routes, "require_safe_text", provider_boundary)
    owner = users[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_merchant=1, openid=%s WHERE id=%s", ("test-openid", owner))
        conn.commit()

    headers = {"Authorization": f"Bearer {token(owner, 'jwt')}"}
    body = {
        "name": "HTTP-CONTENT-CANARY",
        "category": "服装鞋帽",
        "skus": [{"sku_code": "sku-safe", "price": 10, "stock": 1,
                  "specifications": {"nested": [{"material": "棉"}, {"unsafe": "UNSAFE-CANARY"}]}}],
        "attributes": [{"name": "材质", "value": "棉"}],
    }
    response = http.post("/api/products", headers=headers, json=body)
    assert response.status_code == 400
    assert "UNSAFE-CANARY" in calls
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM products WHERE name=%s", (body["name"],))
            assert cur.fetchone() is None
    evidence({"scenario": "product nested-field moderation rejection", "status": response.status_code,
              "reviewed_fields": calls, "no_product_row": True,
              "provider": "in-process boundary interception; no real WeChat validation"})


def test_product_individual_limits_and_aggregate_size_through_http(http, db, users, token, monkeypatch, evidence):
    from services import wechat_api
    from api.product import routes
    reviewed = []
    async def pass_boundary(text, *, openid, scene=1):
        reviewed.append(text)

    monkeypatch.setattr(routes, "require_safe_text", pass_boundary)
    owner = users[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_merchant=1, openid=%s WHERE id=%s", ("test-openid", owner))
        conn.commit()
    headers = {"Authorization": f"Bearer {token(owner, 'jwt')}"}
    body = {
        "name": "AGGREGATE-CANARY",
        "description": "B" * 2500,
        "category": "服装鞋帽",
        "skus": [{"sku_code": "sku-boundary", "price": 10, "stock": 1,
                  "specifications": {"颜色": "蓝" * 2500}}],
        "attributes": [{"name": "材质", "value": "棉" * 100}],
        "buy_rule": "C" * 2500,
    }
    response = http.post("/api/products", headers=headers, json=body)
    assert response.status_code == 200, response.text
    assert len(reviewed) >= 7
    assert all(len(text) <= 2500 for text in reviewed)
    product_id = response.json()["data"]["id"]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT name, description, buy_rule FROM products WHERE id=%s", (product_id,))
            row = cur.fetchone()
            assert row["name"] == body["name"] and row["description"] == body["description"] and row["buy_rule"] == body["buy_rule"]
            cur.execute("SELECT sku_code, specifications FROM product_skus WHERE product_id=%s", (product_id,))
            sku_row = cur.fetchone()
            assert sku_row["sku_code"] == "sku-boundary"
            assert json.loads(sku_row["specifications"]) == body["skus"][0]["specifications"]
            cur.execute("SELECT name, value FROM product_attributes WHERE product_id=%s", (product_id,))
            attribute_row = cur.fetchone()
            assert attribute_row["name"] == "材质" and attribute_row["value"] == body["attributes"][0]["value"]
    evidence({"scenario": "per-field boundary and aggregate length", "status": response.status_code,
              "reviewed_field_count": len(reviewed), "max_reviewed_length": max(map(len, reviewed)),
              "provider": "in-process pass seam; no real WeChat validation"})


def test_product_update_reviews_existing_final_snapshot(http, db, users, token, monkeypatch, evidence):
    from api.product import routes
    reviewed = []

    async def boundary(text, *, openid, scene=1):
        reviewed.append(text)
        if text == "UNSAFE-EXISTING":
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="内容未通过安全审核，请修改后重试")

    monkeypatch.setattr(routes, "require_safe_text", boundary)
    owner = users[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_merchant=1, openid=%s WHERE id=%s", ("test-openid", owner))
            cur.execute("INSERT INTO products(name,pinyin,category,status,user_id) VALUES(%s,%s,%s,%s,%s)",
                        ("existing-canary", "EXISTING-CANARY", "服装鞋帽", 0, owner))
            product_id = cur.lastrowid
            cur.execute("INSERT INTO product_skus(product_id,sku_code,price,stock,specifications) VALUES(%s,%s,%s,%s,%s)",
                        (product_id, "sku-existing", 10, 1, json.dumps({"hidden": ["UNSAFE-EXISTING"]})))
            cur.execute("INSERT INTO product_attributes(product_id,name,value) VALUES(%s,%s,%s)",
                        (product_id, "原属性", "原值"))
        conn.commit()
    response = http.put(f"/api/products/{product_id}", headers={"Authorization": f"Bearer {token(owner, 'jwt')}"},
                        json={"description": "new description"})
    assert response.status_code == 400
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT description FROM products WHERE id=%s", (product_id,))
            assert cur.fetchone()["description"] is None
            cur.execute("SELECT specifications FROM product_skus WHERE product_id=%s", (product_id,))
            assert "UNSAFE-EXISTING" in cur.fetchone()["specifications"]
    evidence({"scenario": "update old unreviewed text prevents unrelated save", "status": response.status_code,
              "reviewed_fields": reviewed, "no_partial_update": True,
              "provider": "in-process boundary interception; no real WeChat validation"})

def test_empty_sku_update_reviews_retained_nested_text_and_writes_nothing(http, db, users, token, monkeypatch, evidence):
    from api.product import routes

    calls = []

    async def reject_retained_value(text, *, openid, scene=1):
        calls.append(text)
        if text == "UNSAFE-EMPTY-LIST":
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="内容未通过安全审核，请修改后重试")

    monkeypatch.setattr(routes, "require_safe_text", reject_retained_value)
    owner = users[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_merchant=1, openid=%s WHERE id=%s", ("test-openid", owner))
            cur.execute("INSERT INTO products(name,pinyin,description,category,status,user_id) VALUES(%s,%s,%s,%s,%s,%s)",
                        ("empty-sku-canary", "EMPTY-SKU-CANARY", "old description", "服装鞋帽", 0, owner))
            product_id = cur.lastrowid
            cur.execute("INSERT INTO product_skus(product_id,sku_code,price,stock,specifications) VALUES(%s,%s,%s,%s,%s)",
                        (product_id, "sku-retained", 10, 1, json.dumps({"nested": ["UNSAFE-EMPTY-LIST"]})))
        conn.commit()
    response = http.put(f"/api/products/{product_id}", headers={"Authorization": f"Bearer {token(owner, 'jwt')}"},
                        json={"description": "should not save", "skus": []})
    assert response.status_code == 400
    assert "UNSAFE-EMPTY-LIST" in calls
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT description FROM products WHERE id=%s", (product_id,))
            assert cur.fetchone()["description"] == "old description"
            cur.execute("SELECT specifications FROM product_skus WHERE product_id=%s", (product_id,))
            assert "UNSAFE-EMPTY-LIST" in cur.fetchone()["specifications"]
    evidence({"scenario": "empty SKU list preserves retained snapshot and rejects unsafe text",
              "status": response.status_code, "no_partial_update": True,
              "provider": "in-process boundary interception; no real WeChat validation"})

def test_product_update_rejects_changed_snapshot_after_review(http, db, users, token, monkeypatch, evidence):
    from api.product import routes

    changed = False

    async def mutate_at_review(text, *, openid, scene=1):
        nonlocal changed
        if text == "review target" and not changed:
            changed = True
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE products SET description=%s WHERE name=%s", ("concurrent edit", "snapshot-race"))
                conn.commit()

    monkeypatch.setattr(routes, "require_safe_text", mutate_at_review)
    owner = users[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_merchant=1, openid=%s WHERE id=%s", ("test-openid", owner))
            cur.execute("INSERT INTO products(name,pinyin,description,category,status,user_id) VALUES(%s,%s,%s,%s,%s,%s)",
                        ("snapshot-race", "SNAPSHOT-RACE", "old description", "服装鞋帽", 0, owner))
            product_id = cur.lastrowid
        conn.commit()
    response = http.put(f"/api/products/{product_id}", headers={"Authorization": f"Bearer {token(owner, 'jwt')}"},
                        json={"description": "review target"})
    assert changed
    assert response.status_code == 409
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT description FROM products WHERE id=%s", (product_id,))
            assert cur.fetchone()["description"] == "concurrent edit"
    evidence({"scenario": "update snapshot conflict after moderation", "status": response.status_code,
              "concurrent value preserved": True,
              "provider": "in-process review boundary plus isolated database race; no real WeChat validation"})

def test_product_timeout_reply_fails_closed_without_any_product_rows(http, db, users, token, monkeypatch, evidence):
    from api.product import routes
    from fastapi import HTTPException

    async def timeout(text, *, openid, scene=1):
        raise HTTPException(status_code=503, detail="内容审核暂不可用")

    monkeypatch.setattr(routes, "require_safe_text", timeout)
    owner = users[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_merchant=1, openid=%s WHERE id=%s", ("test-openid", owner))
        conn.commit()
    name = "TIMEOUT-NO-WRITE-CANARY"
    body = {"name": name, "category": "服装鞋帽",
            "skus": [{"sku_code": "timeout-sku", "price": 10, "stock": 1,
                      "specifications": {"color": "蓝"}}],
            "attributes": [{"name": "材质", "value": "棉"}]}
    response = http.post("/api/products", headers={"Authorization": f"Bearer {token(owner, 'jwt')}"}, json=body)
    assert response.status_code == 503
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM products WHERE name=%s", (name,))
            assert cur.fetchone() is None
            cur.execute("SELECT id FROM product_skus WHERE sku_code=%s", ("timeout-sku",))
            assert cur.fetchone() is None
            cur.execute("SELECT id FROM product_attributes WHERE name=%s AND value=%s", ("材质", "棉"))
            assert cur.fetchone() is None
    evidence({"scenario": "review unavailable leaves products and children untouched",
              "status": response.status_code, "no_partial_write": True,
              "provider": "in-process unavailable boundary; no real WeChat validation"})

def test_product_malformed_review_verdict_fails_closed_without_writes(http, db, users, token, monkeypatch, evidence):
    from services import wechat_api
    from api.product import routes

    async def malformed_backend(text, *, openid, scene=1):
        return {"errcode": 0, "result": {"suggest": "unknown"}}

    monkeypatch.setattr(wechat_api, "msg_sec_check", malformed_backend)
    owner = users[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_merchant=1, openid=%s WHERE id=%s", ("test-openid", owner))
        conn.commit()
    name = "MALFORMED-REVIEW-NO-WRITE"
    body = {"name": name, "category": "服装鞋帽",
            "skus": [{"sku_code": "malformed-sku", "price": 10, "stock": 1}],
            "attributes": [{"name": "材质", "value": "棉"}]}
    response = http.post("/api/products", headers={"Authorization": f"Bearer {token(owner, 'jwt')}"}, json=body)
    assert response.status_code == 503
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM products WHERE name=%s", (name,))
            assert cur.fetchone() is None
            cur.execute("SELECT id FROM product_skus WHERE sku_code=%s", ("malformed-sku",))
            assert cur.fetchone() is None
            cur.execute("SELECT id FROM product_attributes WHERE name=%s AND value=%s", ("材质", "棉"))
            assert cur.fetchone() is None
    evidence({"scenario": "unknown backend verdict leaves all related tables unchanged",
              "status": response.status_code, "no_partial_write": True,
              "provider": "in-process msg_sec_check reply; no real WeChat validation"})
