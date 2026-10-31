# Payment and order security contract

## Change record (2026-10-25)

ORDER-001/002/003, PAY-001/002, order/merchant privacy: protected aliases now use the same authenticated handlers; client prices never set merchandise prices; fulfillment and expiration lock the authoritative order; refunds use a committed intent before provider I/O; API-v3 callbacks require RSA signature and AES-GCM resource and acknowledge only after local commit. No business allocation, monthly rain-point330/30, coupon cap or membership policy change is authorized. This document describes implementation, not executed acceptance evidence.

## Shared HTTP/error contract

Client calls use `Authorization: Bearer <session-backed-token>`, JSON request/response. Missing/expired/revoked credentials:401; authenticated wrong owner:403; missing order:404; conflicting state or immutable refund identity:409; invalid typed input:422; provider/DB unavailable or unknown external result:503 (provider prepay failure502). Error JSON is `{"detail":"reason"}`. 401 requires login,403 must not cause infinite relogin;409 requires refresh/reconcile;503 must retain the same logical identity and query rather than create a new refund. No shared `key`/`admin_key` grants authority. Callback calls deliberately do not require customer Bearer tokens.

## Order creation and trusted price/stock

**Basic information:** POST `/order/create`; logged-in buyer only;200 JSON. Existing `OrderCreate` body fields remain: `user_id` integer required (must equal token owner), `buy_now` boolean default false, `buy_now_items` array required for immediate purchase; each item `product_id` positive strict integer required, `sku_id` positive strict integer optional (first canonical SKU if absent), `quantity` positive strict integer required, `price` decimal optional legacy display input ignored for pricing. Existing address/delivery/points/coupon/idempotency fields retain the schema. `merchant_id` optional must match actual products' owner. All items must belong to one merchant. Cart joins require SKU/product identity correspondence. Price comes from `product_skus.price`; conditional stock decrement checks affected rows in the same transaction as header/items, so failure leaves neither partial order nor consumed inventory. Zero cash orders settle locally in the same transaction, not by synthetic payment callback.

**Request example:** `POST /order/create`, Bearer header, `{"user_id":101,"buy_now":true,"delivery_way":"pickup","buy_now_items":[{"product_id":3,"sku_id":5,"quantity":1,"price":"0.01"}]}`. Illegal quantity examples:0,-1,1.5,true,"1"; these do not create orders.

**Response:** existing order creation envelope remains; order number string identifies the persisted order and `need_pay` boolean distinguishes actual cash payment from zero cash. Frontend displays service-calculated totals rather than legacy item price. Insufficient stock400/409 requires refresh; invalid SKU/product or merchant mapping422.

## Prepayment (all aliases)

**Basic information:** POST `/wechat-pay/create-order`, `/api/wechat-pay/create-order`, `/order/pay`; owner Bearer required;200 JSON. No request-body authority or openid override. Order must be pending_pay. Coupon IDs and points are fixed at creation, not mutable after prepay creation (409 if supplied values differ). Network is outside DB locks.

| Request field | Location/type | Required/default | Meaning and validation |
|---|---|---|---|
|out_trade_no (order_id alias)|body string|yes|owned order number|
|total_fee|body integer cents|yes positive|legacy display amount; trusted server payable wins|
|openid|body string|yes|must equal authenticated buyer's stored binding|
|description|body string|optional 商品支付|payment description|
|coupon_ids/coupon_id|body integer array/integer|optional stored|must equal stored discounts|
|points_to_use|body decimal|optional stored|must equal stored pending points|

Example `POST /order/pay`, Authorization Bearer, `{"out_trade_no":"synthetic-order","total_fee":100,"openid":"synthetic-binding"}`. Illegal: another user's order/binding returns403. Zero-cash pending order returns409, not fake ZERO_ORDER payment success.

| Response field | Type/required | Meaning |
|---|---|---|
|prepay_id|string yes|provider prepay identifier|
|pay_params|object yes|arguments passed unchanged to wx.requestPayment|
|pay_params.appId|string yes|configured mini-program app ID|
|pay_params.timeStamp|string yes|provider payment timestamp|
|pay_params.nonceStr|string yes|payment nonce|
|pay_params.package|string yes|prepay_id=...|
|pay_params.signType|string yes|RSA|
|pay_params.paySign|string yes|signature; never log|
|total_fee|integer yes|server cents charged|
|wechat_raw_response|object yes|existing provider prepay response; not payment completion evidence|

Success shape `{"prepay_id":"wx-test","pay_params":{"appId":"test","timeStamp":"1","nonceStr":"test","package":"prepay_id=wx-test","signType":"RSA","paySign":"signature"},"total_fee":100,"wechat_raw_response":{"prepay_id":"wx-test"}}`. Client return/navigation is never trusted as paid.

## Refund application, audit, direct submission and recovery

**Basic information:** POST `/refund/apply` buyer; POST `/refund/audit` and `/merchant/approve_refund` belonging merchant or platform admin; POST `/wechat-pay/refund` and `/api/wechat-pay/refund` buyer/admin; POST `/api/offline/tuikuan` belonging seller; POST `/refund/sync-status/{order_number}` platform admin recovery. JSON request,200 response. No external request executes before durable intent commit. Order lock precedes intent and financial locks. Network is outside transactions.

| Parameter | Location/type | Required/default | Validation/meaning |
|---|---|---|---|
|order_number|body string|yes online|persisted order identity|
|order_no|body string|yes offline|offline order identity|
|refund_type|body enum string|yes apply|canonical database values `refund_only` (cash refund) or `return` (return and refund); other values422|
|reason_code|body string|yes apply|application reason|
|approve|body boolean|yes audit|approval/rejection decision|
|reject_reason|body string/null|optional|reason for rejection|
|merchant_address|body string/null|required approving `return`|return destination; supported on both audit aliases|
|refund_fee|body integer/null cents|optional full cash|positive strict integer <= cash paid; bool/string/fraction rejected|
|refund_amount|body integer/null cents|optional offline full cash|same strict service validation|
|reason|body string|optional|direct request reason; not authorization|
|refund_request_id|body string|optional direct `default`|1..64 chars stable identity for separate partial refunds; never change on unknown-result retry|
|order_number|path string|yes sync|latest durable intent recovered|

Examples: buyer `POST /wechat-pay/refund` with Bearer and `{"order_number":"synthetic-order","refund_fee":50,"refund_request_id":"return-item-1"}`. Merchant `POST /merchant/approve_refund` with `{"order_number":"synthetic-order","approve":true,"merchant_address":"synthetic return address"}`. Recovery `POST /refund/sync-status/synthetic-order`, admin Bearer, no body. Illegal `refund_fee:true` or0 =>422; same logical identity with changed amount =>409.

Apply/audit success `{"ok":true}`. Direct/recovery response fields: `success` boolean (local intent status persisted, NOT money arrived); `refund_no` string stable globally unique provider number; `status` string prepared/unknown/processing/success/closed/change; `message` string user-safe explanation. Example `{"success":true,"refund_no":"RF...","status":"processing","message":"退款状态已持久化；受理不代表到账"}`. Offline wraps this in `{code:0,message:"退款受理成功",data:<result>}`.

Same refund application always resolves one logical identity across direct and audit aliases, irrespective of caller keys. Separate direct partial requests use separate stable refund_request_id values; default retains legacy one direct request. Aggregate reservations under order lock cannot exceed cash. Partial success reverses cash-proportional finance effects and restores preceding fulfillment state; cumulative full success sets refunded and revokes order discounts once. PROCESSING/unknown do not release reservations or reverse assets. Closed restores original state, not a guessed completed state; change/abnormal remains held for reconciliation. Rejected applications cannot be approved after rejection. Rejection while refunding409.

Recovery claims a30-second lease, marks unknown before I/O, and on subsequent attempts queries the SAME refund number. Only explicit provider absence permits resubmission with the SAME number and original amounts. Timeout is unknown, not failed. Durable records have no TTL cleanup. Scheduler every minute processes up to50 ready intents; failures log safe event names and remain retryable. `change`/`closed` require operator reconciliation, never blind new-number retry. Historical orders with refund_no but no new intent are not fabricated into accepted records: admin sync404 explicitly requires historical reconciliation/import after provider proof.

GET `/refund/progress/{order_number}` and `/refund/query/{order_number}` require buyer, belonging merchant or admin. No body. Progress returns existing application fields (`id`, `order_number`, `refund_type`, `reason`, `status`, `reject_reason`, `merchant_address`, timestamps); empty `{}` if no application. Query returns `order_number`, `order_status`, `refund_no` nullable, `transaction_id` nullable, `total_amount` yuan number, `created_at`, `updated_at`, `refund_apply` nullable application object, `account_flows:[]`, `wechat_status_note` string. Global account-flow remark searches no longer expose platform ledgers to buyers/merchants. Query is a read snapshot, not a provider sync; use admin sync for active recovery.

## Callback protocol and replay

**Basic information:** POST `/wechat-pay/notify`, `/api/wechat-pay/notify`, `/api/offline/zhifu/notify`; refund POST `/wechat-pay/refund-notify`, `/api/wechat-pay/refund-notify`. `Content-Type: application/json`; no Bearer. Required headers `Wechatpay-Signature` base64 RSA-SHA256, `Wechatpay-Timestamp` integer seconds within300s, `Wechatpay-Nonce` string, `Wechatpay-Serial` configured public-key ID. Header signature covers exact raw body. `WX_MOCK_MODE` never bypasses signature or decryption.

Body `{id:string,event_type:string,resource:{ciphertext:base64 AES256-GCM,nonce:string,associated_data:string}}`. Payment event `TRANSACTION.SUCCESS`; decrypted payload requires `out_trade_no`, `transaction_id`, `trade_state:"SUCCESS"`, matching `mchid` (or configured service-provider identity), appid when present, `amount:{total:integer,currency:"CNY"}`. Refund event `REFUND.*`; payload requires known `out_refund_no`, `refund_status`, exact `amount.refund`/`amount.total`/currency and any supplied transaction/submerchant binding must match intent. Malformed/unsupported/mismatched400; unsigned/untrusted key401; database/settlement/commit failure503. Example illegal plaintext resource receives401 before persistence.

**Response:**204 with no response body ONLY after all order state, settlement, coupon/points and payment_events/refund terminal state commit. 4xx/5xx means not accepted. Valid duplicate business transaction (even different notification ID) acknowledges204 only with prior durable event/terminal evidence. Transaction IDs unique across payment events. Refund number is never parsed to guess another order. Payment status outside pending_pay without durable event fails and requires reconciliation; no fulfillment overwrites cancelled/refunding/refunded states. Scheduler queries pending cash orders and applies the same settlement path. Provider compatibility and real signatures require final controlled external validation; local synthetic RSA/AES is not real WeChat proof.

## Fulfillment and privacy

POST `/order/status` merchant/admin body `{order_number,new_status,reason?}` allows pending_ship->pending_recv and pending_recv->completed only; no public paid/refund transitions. POST `/order/confirm-receive` buyer body `{order_number}` only pending_recv->completed. POST `/merchant/ship` belonging merchant/admin body `{order_number,tracking_number?,express_company?,logistics_type?,item_desc?,scan_text?}` only pending_ship->pending_recv; physical logistics requires6..32-char tracking; pickup/virtual may omit. Success `{ok:true,...}` existing fields (`local_updated`, `message`) remain. Each operation locks and checks owner/state on same connection. Refund-first rejects fulfillment; fulfillment-first can still request refund from resulting allowed state. Expiration locks pending_pay before restoring stock and cancelling; auto-receive and shipping status scheduler use conditional transitions and never override refunding.

GET `/order/{user_id}` buyer/admin; GET `/order/detail/{order_number}` buyer/admin; GET `/order/merchant/{merchant_id}` belonging merchant/admin; GET `/merchant/orders` merchant/admin scope derived from identity. No request bodies; existing order projections remain, unauthorized never receives them. All three `/order/export`, `/order/export/by-time`, `/order/export/daily-summary` are platform-admin-only, retain existing XLSX outputs and request schemas. `/merchant/withdraw` global pool operation now admin-only (actual bank payout contract belongs finance). Cart add/decrease/read/remove all require token owner matching user_id; add/decrease quantity strict positive integer. Lists with no data return `[]` (existing paginated merchant/offline envelope retained). Offline list buyer/seller parameter must match identity unless admin; config-check admin-only.

## Durable offline merchant wallet transfer

Existing offline allocation and actual merchant wallet payout policy is preserved, but no network is hidden inside settlement. `payment_merchant_transfers` outbox is committed alongside local assets, uses stable32-character batch/detail number, queries prior unknown attempts before same-number resubmission, and is recovered every minute with >=60-second provider-query spacing. FINISHED is not treated as success when failure counts/amounts disagree. Closed/failed entries require manual reconciliation; never generate replacement money transfers automatically. This is the existing ordinary merchant wallet batch-transfer product, NOT bankcard withdrawal. API compatibility reference: [official batch query contract](https://pay.weixin.qq.com/doc/v3/merchant/4012458877): nested transfer_batch, NOT_FOUND, need_query_detail=false. Provider account/product eligibility remains an external release gate.

## Migration, configuration and rollout

Apply `migrations/005_security_payments.sql` before enabling routes/jobs: three InnoDB tables, unique logical refund identity, globally unique out_refund_no, unique payment transaction and durable transfer batch. No runtime DDL; no production data mutations performed. Existing in-flight legacy refunds require provider reconciliation before migration into intents; do not auto-resubmit old refunds. Forward rollback must drain/reconcile intents/outbox first; dropping tables loses money-recovery evidence and is not a rollback procedure.

Use existing WECHAT_PAY_MCH_ID, SP_MCH_ID if enabled, WECHAT_APP_ID, API_V3_KEY, PUB_KEY_ID, private/public key paths and public_base_url. Secrets provisioned by authorized operator, never in docs/tests. Background tasks controlled by main lifecycle ENABLE_BACKGROUND_TASKS; route registration starts no threads. Client rollout must add Bearer on all protected aliases, keep discount selections fixed after creation and retain refund identity after503. Test deployments must block external network; no production SMS/payment/refund/transfer calls are authorized.

## Proposed verification (not executed by implementer)

Coordinator: `uv run pytest tests/test_security_payments.py tests/isolation/test_payment_business.py tests/isolation/test_order_state_race.py tests/isolation/test_order_transitions.py` inside guarded isolated MySQL/Redis harness. Include unauthorized alias matrix, real DB callback commit fault and signed replay, last-stock contention, both refund/ship/receive orderings, expiration versus payment, partial cumulative refunds and durable transfer query recovery. Controlled provider boundary tests demonstrate local recovery only; real payment/refund/transfer remains unverified until authorized dedicated merchant validation.

## Reconciliation quarantine and operator tool (additional change)

GET `/refund/reconciliation/cases` requires platform-admin Bearer; no query parameters or body;200 JSON `{items:[]}` when empty. Non-admin403, anonymous401. Example request `GET /refund/reconciliation/cases`, `Authorization: Bearer <admin-token>`, no body; illegal ordinary buyer token403. Response `items` is an array of objects: `case_key` string stable quarantine identity; `order_number` string original order; `transaction_id` string/null unknown legacy binding; `total_fee` integer cents/null unknown amount; `refund_no` string/null absent for late-payment cases; `reason` enum paid_after_local_close/legacy_refund_missing_intent; `state` string open; `created_at` datetime creation time. Example `{"items":[{"case_key":"late:synthetic-tx","order_number":"synthetic-order","transaction_id":"synthetic-tx","total_fee":100,"refund_no":null,"reason":"paid_after_local_close","state":"open","created_at":"2026-10-25T12:00:00"}]}`.

Minute recovery now also queries offline pending cash orders and cancelled online cash orders with no reconciliation case. Verified payment after cancellation creates a durable open case and error event before rejecting the callback (no success ACK, fulfillment, stock consumption or unearned asset grant). Legacy refund_no missing an intent is explicitly quarantined automatically, retaining trusted original order/payment/refund identity. Operator must inspect provider transaction/refund state and apply an approved reconciliation procedure: original full/partial legacy request amount is not recoverable safely from order total alone, and expired-order restocked inventory cannot be resold silently. This is a business/operational blocking prerequisite, not fabricated automatic recovery or permission to send a new refund. Cases have no TTL deletion.

Existing offline merchant template notification is delivered separately after the durable wallet transfer reaches proven successful FINISHED. `notification_sent` persists local delivery bookkeeping; provider template delivery has no exactly-once primitive, so a crash after provider accept and before bookkeeping may duplicate the informational message, never money. Failed messages remain recoverable; finished money transfers remain terminal during message retries.

## Reviewed recovery corrections

Offline first prepayment now persists `security_prepay_frozen=1` even for full-price/no-coupon orders; later discount changes reject before provider I/O. Payment query consumers rotate primary-key cursors and wrap at end so old unpaid/not-found rows cannot permanently starve later online/offline orders. Direct refund reasons (max512 characters) are persisted on the intent; a retry of an original direct refund_request_id resolves its original intent even if a later application exists. Existing legacy refund_no without intent is quarantined before any new number can be created.

Merchant-wallet payout claim and refund reservation both lock the same order first. A still-prepared/unattempted payout is closed atomically before refund intent commits. An already attempted/unknown/completed payout blocks new refund submission409 until operator reconciles merchant funds; no automatic bankcard/wallet clawback product is invented. Template API HTTP200 is accepted only when JSON errcode=0; rejected informational deliveries remain retryable.

Additional authored isolated scenarios: `tests/isolation/test_order_overlap.py` duplicate ship/receipt competition and pay/expiry both lock orderings; `tests/isolation/test_offline_callbacks.py` signed offline callback settlement/final-commit failure, complete rollback and replay with exact10-point grant, single event/outbox; transition tests direct-key replay after new application and prepared-vs-attempted payout/refund outcomes. All are unexecuted by implementer.

Payout reservation correction: pending refund holds (not permanently closes) an unattempted payout. Partial SUCCESS reopens only the remaining original payout using cumulative refunded-cash proportion, rounded to integer cents; CLOSED restores the held eligible amount unchanged. Full refund closes zero remainder. Stable batch identity is safe to reuse because attempts remain zero; once attempted, operator reconciliation is required. Migration retains original_amount to prevent repeated partial-rounding drift.
