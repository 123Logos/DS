# Authentication, operator mutations and user/bankcard privacy

## Change record and client migration

2026-10-25: AUTH-001/002, USER-001 and user/bankcard PRIVACY-001 cutover. Apply numbered migration `004_security_auth.sql` with the tracked migration runner before serving requests. It creates InnoDB SMS limit/challenge and operator-audit tables, ensures point audit columns, and explicitly deletes existing sessions once. Stateless JWTs lacking `sid` are always rejected; `users.token` is never an authentication source. Existing clients must discard stored tokens and log in again. No shared key grants permissions. Optional legacy `key`/`admin_key` fields are ignored, not credentials. No refresh-token flow exists.

All protected requests use `Authorization: Bearer <token>`. JSON endpoints accept/return application/json; SMS bankcard sending uses application/x-www-form-urlencoded. Responses are HTTP200 unless stated. Error shape is `{"detail":"reason"}`; 401 invalid/expired/revoked/missing credential means log in again, 403 ownership/role/status means do not retry as another ID, 400 business rejection means correct the input, 422 schema rejection means correct format, 429 wait for limit window, 503 means service unavailable (never treat it as sent). Server failures never imply success. HTTP500 may occur on transaction failure; no successful local transaction is inferred.

## Identity and revocation contract

`POST /user/auth`: unchanged body `mobile` string, `password` string, optional `name` (custom name forbidden for new registration). Returns `uid` integer internal account ID, `token` string Bearer JWT, `level` integer membership star, `is_new` boolean. Example request `POST /user/auth`, header Content-Type application/json, body `{"mobile":"19900000001","password":"Synthetic-pass-42!"}`; success `{"uid":42,"token":"<credential>","level":0,"is_new":false}`. Wrong password yields400; frozen/deleted403. JWT issuance locks the user and compares the hash used for password verification so a concurrent password change cannot mint a valid stale credential. UUID is issued/accepted only with ENABLE_UUID_AUTH; its disabled issuance defaults to JWT. `POST /wechat/login` retains WeChat-code verification and its existing response; its 124-character opaque token uses the same sessions table. The unused hardcoded-key WechatService.generate_token issuer was removed.

Every supported token authenticates through unexpired sessions joined to active users. JWT includes signed user_id, sid, exp, iat, type=access and session ownership is checked. No identity cache or legacy fallback. Authentication storage outage503 fails closed. Password reset/change, admin password reset, freeze/delete/unfreeze and admin mobile change delete all target-user sessions in their mutation transaction; unrelated users remain logged in. `invalidate_token(token)` deletes the JWT sid or exact opaque token and propagates DB errors. There is no new logout HTTP route.

## Send password-reset SMS

### Basic information

`POST /user/reset-password/sms`, anonymous, application/json, HTTP200. Internally queries and locks the current account at the supplied mobile to bind its trusted account ID to the challenge. Registered and unregistered mobiles follow the same supplier issuance flow and return the same accepted response shape; an unknown account stores no redeemable account identity. Sends only to the supplied validated mainland-China mobile. Codes and account-existence results cannot be returned to clients or logs.

### Request parameters

| Field | Location | Type | Required/default | Validation and meaning | Legal / illegal |
|---|---|---|---|---|---|
| mobile | body | string | required | `^1\d{10}$`; SMS target and reset identity | `19900000001` / `abc` |
| device_id | body | string | required | 16–128 characters; client installation identifier (not an authentication factor) | `installation-000001` / `x` |

Request: `POST /user/reset-password/sms`, `Content-Type: application/json`, body `{"mobile":"19900000001","device_id":"installation-000001"}`. Illegal body `{"mobile":"abc","device_id":"x"}` →422.

### Response parameters

| Field | Type | Required | Meaning/example |
|---|---|---|---|
| session_id | string | yes | 32-character random challenge identity; `aabb...` |
| expired_in | integer | yes | lifetime seconds,300 |
| retry_after | integer | yes | minimum mobile issuance interval seconds,60 |
| status | string | yes | `accepted` means provider accepted, NOT delivered |

Example `{"session_id":"0123456789abcdef0123456789abcdef","expired_in":300,"retry_after":60,"status":"accepted"}`. No `mock_code` field, no null-code success, no data-empty success.

### Usage and business rules

Call issuance before reset. Only latest challenge for the same mobile/purpose/subject is usable, even if a newer send was rejected/unknown. Six-digit cryptographically random code; stored HMAC uses independent SMS_CODE_SECRET (minimum32 characters), bound to random session. TTL5 minutes. Scope counters use MySQL row locks, not process memory: mobile5/hour with60-second cooldown, IP20/hour, device10/hour, global SMS_GLOBAL_HOURLY_LIMIT/hour (default1000). Client cannot select trusted IP: request.client.host is used, not forwarded headers. Deploy behind a correctly configured trusted proxy to avoid all clients sharing one transport peer. Failure increments are mobile+purpose scoped5/hour and persist across resend. Successful business operation and consume commit together; rejected attempts are committed before400. Reissuing does not reset attempts. Do not blindly retry uncertain sends or claim exactly-once SMS delivery.

### Errors

422 malformed fields;429 any issuance limit;503 missing secret/provider configuration, supplier rejection/transport timeout/unconfirmed acceptance;500 DB persistence failure. Example `{"detail":"短信请求过于频繁"}`. Unknown provider outcomes are stored `unknown`, definitive rejections `rejected`; neither authorizes a reset. Pending is persisted before the network request. No DB locks are held during provider calls.

## Redeem password reset

`POST /user/reset-password`, anonymous JSON. Body fields: `mobile` string required (same exact identity used at issuance); `sms_code` string required exactly6 decimal digits; `new_password` string required8–72 characters. Request `{"mobile":"19900000001","sms_code":"382746","new_password":"New-synthetic-pass-42!"}`; invalid `sms_code:"1"` →422. Success `{"msg":"密码已重置"}` (`msg`: required string human result).400 covers invalid/expired/consumed/wrong-purpose/wrong-subject/attempt-locked codes, unknown accounts, and issuance/current-account identity mismatch;500 transaction failure. There is no unregistered-target404 response on this route. Redemption first locks the current account at the mobile and requires its ID to equal the challenge's issuance account ID; a code issued before number reassignment cannot reset the new owner. Correct code is single use: two independent transactions can produce only one successful reset. Password hash update, challenge consumption, target session deletion and audit are one transaction. Error before commit rolls back all four. Frontend must clear all stored credentials and return to login after success.

## Operator mutation matrix

All rows require a configured ADMIN_USER_IDS account's valid Bearer, even with forged/old shared keys. Operator ID comes from authentication; reason comes from business request/default. `security_operator_audit` stores action,target,operator,before/after,reason,time in the same transaction; password hashes/codes are never audit values. No request-time DDL for these operations.

| Method URL | Request (all listed fields required unless optional) | Return fields | Rules |
|---|---|---|---|
| POST /user/set-status | JSON mobile string,new_status enum0normal/1frozen/2deleted,reason string optional default后台调整 | success boolean,msg string | lock target, change status,revoke,audit |
| PUT /user/freeze; PUT /user/unfreeze | JSON mobile string,reason optional,admin_key optional ignored | success boolean,msg string | revoke on either operation so unfreeze cannot resurrect sessions |
| PUT /admin/user/reset-pwd | JSON mobile string,new_password string,admin_key optional ignored | msg string | hash update,revoke,audit |
| POST /user/upgrade | query mobile string | old_level,new_level integers | increment one, maximum6, lock+audit |
| POST /user/set-level | JSON mobile string,new_level integer0–6,reason optional | old_level,new_level integers | lock+audit |
| POST /user/grant-merchant | query mobile string | msg string | set flag1, audit existing/new state |
| PUT /user/mobile | query user_id positive integer,old_mobile,new_mobile strings,key optional ignored | msg string | old identity match,unique new mobile,revoke,audit |
| POST /points | JSON mobile,type enum member/merchant,amount numeric,reason optional | msg string | trusted operator_id,generated event_id,source=admin; points balance before/after and operator audit same transaction |
| POST /admin/unilevel/set | JSON user_id integer,level schema range | user_id,old_level,new_level integers,changed boolean,message string | lock user,upsert level,audit |
| POST /admin/platform-return-address | query name,phone,province,city,district,detail strings,admin_key optional ignored | msg string | administrator configuration,audit |

Example operator request: `POST /user/set-level`, headers Authorization Bearer <admin>, Content-Type application/json, body `{"mobile":"19900000001","new_level":3,"reason":"授权调整"}`; success `{"old_level":2,"new_level":3}`. Illegal new_level7 →422. All return scalar fields above are required, nonnull; msg/message strings are human-readable, not codes. Missing target404; maximum/duplicate identity400; no role403; DB/audit failure500 rolls back state. Existing successful no-change responses may report unchanged state. Repeated point adjustments are separate intentional events, not a client-idempotency contract; do not auto-retry unknown outcomes. This does not redesign financial policy.

## Personal-resource scope and privacy

Public entrypoints only: password/WeChat login, password-reset issuance/redemption, explicitly public platform-return address. All personal routes below require Bearer. Mobile/user_id selectors are checked before business/provider access: only the authenticated identity or explicitly configured platform admin may select another user's personal resource.

- `/user/info`, `/user/list` (list admin-only), `/user/mobile` (admin-only), `/points/balance`, `/points/log`, `/points/summary`, `/my` coupons preserve their prior response structures.
- `POST /user/self-delete` additionally requires matching mobile and password; atomic delete-status/revoke/audit. Returns msg string. Self-service always uses authenticated user's ID (even admin cannot delete someone else through this flow).
- `/user/update-profile` is self-only, matching mobile; old_password required for new_password; row-lock verification then hash/revoke/audit together. Nickname content review remains required and avatar_path cannot bypass avatar review.
- `POST /user/bind-referrer`, `GET /user/refer-direct`, `GET /user/refer-team`, `GET /reward/list`, `GET /user/unilevel`, `GET /user/is-merchant`, return-address read/write now require self/admin mobile scope. Existing request bodies/query parameters and return structures unchanged. Referral/team rows retain their relationship business data; anonymous/cross-owner enumeration denied.
- `GET /reward/by-order/{order_id}` is admin-only rather than exposing every recipient to order-ID enumeration.
- `/address` creation/update/default/delete/list retain server-side ownership checks.
- `GET /unilevel/status`, `POST /unilevel/promote`, `GET /user/referral-qr`, `POST /user/refresh-referral-qr` require self/admin user_id scope. GET queries have no request body; POST promotion/refresh retain query user_id, no body. Existing response schemas unchanged.
- `POST /user/get-phone` JSON code,user_id must match authenticated owner before external phone exchange. `POST /user/decrypt-phone` requires Bearer and exchanged openid must match authenticated openid; retains code,encrypted_data,iv JSON and phone string response. No arbitrary account phone mutation.
- Avatar upload/review/clear retain owner checks. Commented triple-quoted points-clearing endpoints are not registered API routes.

Example privacy read `GET /user/info?mobile=19900000001`, header Authorization Bearer <owner>, no body. Replacing mobile with another account produces403 `{"detail":"只能查询本人信息"}`; anonymous401. No query key can bypass it. Frontends must not use403 as a reason to keep retrying login.

## Bankcards

All `/api/bankcard/*` paths require Bearer and derive user_id exclusively from it: bind, sms/send, modify/apply, modify/status, list,status,logs,my,default/set. Existing card ownership predicates retained.

### Send

`POST /api/bankcard/sms/send`, form parameters account_number string16–30 decimal digits required, device_id string16–128 required, purpose enum bankcard_bind (default) / bankcard_modify. Trusted target is current user's registered mobile, never a client mobile field. Invalid account `abc`422. Example form `account_number=6222021234567890000&purpose=bankcard_bind&device_id=installation-000001`. Headers Authorization Bearer <owner>, Content-Type application/x-www-form-urlencoded. HTTP200 `{"code":0,"message":"验证码已发送","data":{"session_id":"0123456789abcdef0123456789abcdef","expired_in":300}}`. code integer0 and message string required; data.session_id string and data.expired_in integer required. Accepted is not delivered. Same limits and errors as reset; unbound mobile400. mock_code removed.

### Bind and modify

`POST /api/bankcard/bind` keeps JSON account_name(2–100),account_number(16–30 digits),account_bank(2–50),bank_name(2–128),bank_branch_id(optional≤128),bank_address_code(6 digits),sms_code(6 digits),session_id(32 chars). Bind must redeem the matching bankcard_bind challenge for authenticated user+exact card. Local binding and challenge consumption/audit share one transaction after external settlement-data verification. Invalid code returns400 and commits failed attempt; local write failure rolls back consumption. Returns existing envelope code0,message,data(account_id integer,action created/updated/already_bound,verify_method wechat_api,verify_status success,msg ok).

`POST /api/bankcard/modify/apply` keeps new_account_name,new_account_number,new_account_bank,new_bank_name,optional bank_branch_id/bank_address_code and now requires six-digit sms_code AND32-char session_id. Redeems bankcard_modify only before external application; unlike local bind this external operation cannot roll back SMS authorization after sending to provider. API correctly awaits the async service. Returns envelope with data.msg,data.application_no,data.status=pending_review,data.sub_mchid. Foreign purpose/card/session fails400 before external modification. Frontend must request fresh authorization after rejected external application; no blind retry with consumed code.

`GET /api/bankcard/logs?limit=50` has no body, limit1–1000; returns code/message/data array. Each item id(integer),operation_type(string),target_id(integer/null),old_val/new_val(object/null),created_at(string) only. Shared admin_key and IP removed from response. `/my` preserves masked account number/tail and now masks account_name too; never returns full card number. Other bankcard schemas unchanged; request errors400, anonymous401, ownership403, provider/storage failures cannot be interpreted as success.

## Provider configuration and operations

Set .env SMS_SECRET_ID, SMS_SECRET_KEY, SMS_SDK_APP_ID, SMS_SIGN_NAME, SMS_RESET_TEMPLATE_ID, SMS_BANKCARD_TEMPLATE_ID, SMS_REGION, SMS_TIMEOUT_SECONDS and independent SMS_CODE_SECRET. Templates accept exactly one code parameter; provider account requires approved signature/templates and SMS send/status-pull permissions. Missing values explicitly503, never fixed/mock SMS. Production secrets are operator-injected; not in repository. Provider message serial is stored, plaintext code is not. `reconcile_sms_receipts(mobile,begin_time,end_time)` is an operator-only Python service callable (not a public endpoint), queries up to100 provider receipts and persists delivered/failed separately from accepted. Narrow query windows must be used; unknown sends without returned serial are not automatically retried/reconstructed as accepted. Operator must reconcile supplier records before requesting a new send; no exactly-once claim.

Official references: [SendSms](https://www.tencentcloud.com/document/api/382/40536), [Python signing/SDK](https://www.tencentcloud.com/document/product/382/37259), [PullSmsSendStatusByPhoneNumber](https://www.tencentcloud.com/document/product/382/40518). Adapter signs actual HTTPS TC3-HMAC-SHA256 requests, version2021-01-11. Real delivery and signing compatibility require authorized internal mobile + real account credentials; controlled adapter tests are not that evidence.

## Regression execution (coordinator only)

`uv run pytest tests/isolation/test_auth_business.py -q` within guarded isolated runner environment. Tests add real-MySQL/app HTTP ownership checks; all-token revoke/unrelated-user validity; two reset consumers; attempt limits and resend retention; purpose/mobile/expiry rejection; forced audit failure rollback; legacy JWT rejection/logout; real adapter request at controlled HTTP boundary. No tests/build/lint/formatters were executed by AuthOwner. Migration must run before app requests; rollback requires restore/migration plan and cannot safely resurrect legacy credentials. No production mutation or SMS was performed.

Additional privacy change: `/api/bankcard/status` `wechat_display_info` is an explicit optional-field projection of `account_type`, `account_bank`, `verify_result` only; arbitrary upstream fields (especially account number/name) are never forwarded. Default-card mutation also records the authenticated actor and selected account ID in its local transaction. Boundary projection regression: `uv run pytest tests/test_security_auth_privacy.py -q` (not executed by AuthOwner).

## Review corrections and additional registered routes

`GET /all-points?user_id=<positive integer>` is a live route (unlike the commented legacy point-clear handlers). It now requires owner/admin Bearer; no body. Returns unchanged UserAllPointsResponse (four channel balances and total); anonymous401, other user's ID403. Audit review also corrected bankcard poll projections: selected user_id is retained for approved-card uniqueness checks and modify_application_no/modify_fail_reason are retained for `/status` pending/failed display. Critical logs and provider error display never interpolate raw exceptions.

Password-reset challenges additionally bind to the account ID found under a user row lock at issuance. Unknown account receives the same accepted issuance shape but no redeemable account identity. Redemption locks current mobile owner first, then attempt counter and challenge; its stored account ID must match. Mobile changes invalidate outstanding challenges for that target in the same transaction. An old-mobile code cannot follow the number to a different account. Both existing and new-registration password login verify submitted mobile and password again inside the user lock used to insert the session. Neither stale password nor stale mobile can issue a session after concurrent credential/identity change. Auth DB lookup and bankcard SMS lookup+network run in worker threads rather than blocking async event loop. Unused active-user/cache probe wrappers removed; no startup cache shim.

### System merchant role administration

`POST /api/system/grant-system`, authenticated configured platform admin, query user_id required positive integer; is_merchant required integer0/1/2 (ordinary/merchant/third-party-platform, preserves existing business enum); key optional string ignored. No request body. Headers Authorization Bearer <admin>. Example `/api/system/grant-system?user_id=42&is_merchant=2`; success200 `{"msg":"is_merchant 已更新","user_id":42,"is_merchant":2}`. All three response fields required nonnull: msg human description, user_id selected target, is_merchant committed type. Illegal is_merchant3→422. Missing/revoked Bearer401; ordinary/merchant even with old key403; missing target404; audit/storage failure500 and transaction rolls back. Locks user, records trusted operator and actual old/new role in same transaction; repeating desired type has no further role effect but records authorized intent. Literal shared-key authorization removed without compatibility bypass. Clients must migrate to administrator Bearer.

`PUT /api/system/sentences` also requires platform admin; JSON optional banner_sentence and system_sentence (at least one nonnull), strings under existing schema constraints. Example headers Authorization Bearer <admin>, Content-Type application/json, body `{"banner_sentence":"欢迎"}`. No-field body `{}`400; anonymous401/ordinary403. Success200 envelope status string `success`, message string human result, data fields id integer,banner_sentence/system_sentence strings,created_at/updated_at datetimes or null. Before/after values and trusted operator committed together. `GET /api/system/sentences` remains public and read-only; empty table returns data.id=null, blank strings, null times without writing default rows. Region GET /api/provinces,/api/cities/{province_code},/api/districts/{city_code} remain public read-only with existing responses. No other registered system write routes exist in the scanned module.

Fresh-account status consistency: migration004 sets only the `users.status` column default to0 (NORMAL); it never updates existing frozen1/deleted2 rows. Password registration and WeChat registration already write NORMAL0 explicitly. Harness bootstrap defaults match the same enum. Regression covers new password/WeChat users normal and an existing frozen user still denied by login and session issuance.
