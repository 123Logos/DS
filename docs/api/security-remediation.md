# 安全边界与接口兼容说明

本文件记录 2026-10-21 安全整改涉及的既有接口行为变化。路径和主要请求字段保持兼容；未登录、越权或资源不属于当前账户时，接口现在返回 `401/403`，而不是执行操作。

## 三批次合并验收范围

### 第一批：认证、角色和资源归属

所有受保护接口使用 `Authorization: Bearer <token>`。平台管理员由 `ADMIN_USER_IDS` 配置确定；商家操作必须匹配订单 `merchant_id`；普通用户只能访问自己的用户、地址、订单、积分和退款。匿名请求返回 `401`，已登录但作用域不符返回 `403`。旧 `admin_key`/`key` 字段如仍在请求模型中，仅为兼容输入，不再授予权限。

第一批覆盖：`GET/POST /merchant/orders`、`POST /merchant/ship`、`POST /merchant/approve_refund`、微信发货提醒/跳转配置、商户提现/绑卡、`POST /api/coupons/use`、`POST /api/donate/true-total-points`、用户信息/积分汇总/奖励流水和退款查询。管理员可按管理范围查询；商家或用户的查询必须在服务端附加归属条件，不能只依赖前端传入 `user_id`/`merchant_id`。

### 第二批：事务、验证码、回调和并发

退款、确认收货、发货等状态更新必须在同一事务内锁定订单或使用预期旧状态条件更新，并检查影响行数。一次退款请求必须持久化稳定请求号；微信超时或本地提交失败时，后续重试复用该请求号并查询结果，不生成第二笔逻辑退款。

Password recovery is documented in the canonical [authentication contract](security-auth.md#send-password-reset-sms): call `POST /user/reset-password/sms` to create a provider-bound challenge, then redeem it through `POST /user/reset-password`. Challenges are HMAC-bound with `SMS_CODE_SECRET`, not `JWT_SECRET_KEY`; they must never be inserted manually. Missing provider configuration or uncertain provider acceptance returns an error, not a usable code.

微信支付/退款回调只有在本地订单、资金拆分、积分和优惠券回退事务成功提交后才返回成功；数据库异常或结算异常必须返回微信可识别的失败响应，使通知重试。重复通知依赖订单状态、通知事件唯一键和幂等更新，只允许结算一次。

The coordinator has provisioned isolated WSL and server MySQL/Redis infrastructure (see [verification report](../PR218-security-verification-20261025.md)). Four baseline probes record pre-remediation failures. Candidate verification is still pending coordinator-run results; real SMS, WeChat payment/refund, and other external provider outcomes remain unverified and must not be represented by controlled-boundary tests.

### 第三批：审计、内容、日志和证据

人工积分调整必须记录操作者 ID、目标用户、调整前余额、调整额、调整后余额、原因和业务事件 ID；自动入账必须关联订单/退款/业务事件。商品公开文本按实际保存的每个文本字段逐项送审，审核文本与保存文本必须一致，超过上限、异常或非 `pass` 均不得落库。

日志允许记录内部 ID、订单号、事件类型、错误类别和脱敏后的有限标识；禁止原始 Token、手机号、access token、支付请求体、回调 Headers、短信验证码和完整个人资料。异常日志同样适用白名单。


## Canonical contracts and verification

This file is a historical remediation overview. Current endpoint details are maintained in the linked per-slice contracts above; where this summary differs, follow those contracts. The current candidate verification status and independently recorded baseline evidence are in [PR218 verification report](../PR218-security-verification-20261025.md).
## 接口变更记录

| 版本 | 变更 | 兼容性与迁移 |
| --- | --- | --- |
| 2026-10-21-a | 管理、商家、用户资产和退款查询增加 Bearer/归属校验 | 路径和主要字段保留；旧口令字段不再授权，前端必须发送 Bearer |
| 2026-10-21-b | 订单数量、SKU、服务端价格和状态并发约束收紧 | 旧客户端可继续发送 `price`，但服务端忽略；数量需改为正整数 |
| 2026-10-21-c | 找回密码改为短信签发、用途绑定、限次和原子核销 | 固定 `111111` 废弃；前端先调用发送接口，再提交验证码 |

## 回归证据矩阵

Canonical API and implementation contracts: [authentication and user privacy](security-auth.md), [orders and payments](security-payments.md), [finance](security-finance.md), [content review](msg-sec-check.md), and [isolated verification harness](security-harness.md). These are implementation contracts, not test-pass claims. See [PR218 verification report](../PR218-security-verification-20261025.md) for observed baseline evidence, infrastructure evidence, and candidate verification status.

## 订单

### `POST /order/create`

- 必须使用 Bearer 登录，`user_id` 必须等于认证账户 ID。
- `buy_now_items[].quantity` 必须是严格正整数；`sku_id` 必须属于对应商品。
- `buy_now_items[].price` 为兼容字段，服务端忽略其金额，始终读取数据库 SKU 单价。
- 库存使用条件扣减；并发库存不足返回 `409`，订单事务回滚。

### `GET /order/{user_id}`、`GET /order/detail/{order_number}`

普通账户只能读取本人订单；平台管理员可读取管理范围内订单。

### `POST /order/status`

必须是平台管理员或认证商家，且商家只能操作自己的订单。公开状态接口只允许配送状态的合法迁移；支付成功、退款成功等资金状态由受信支付/退款回调驱动。

### `POST /order/confirm-receive`

必须登录，订单必须属于当前用户且处于 `pending_recv`。

## 退款与支付

### `POST /api/wechat-pay/refund`

必须登录并只能操作本人已支付订单；平台管理员可按后台流程操作。退款单使用订单锁和条件状态更新，重复请求返回处理中结果，不重复发起退款。

### `POST /api/refund/apply`

必须登录并只能为本人订单申请退款。审核接口要求平台管理员或订单所属商家；退款查询按买家/商家归属隔离。

## 管理与财务

资金池、补贴发放/调整、优惠券发放/兑换、用户状态/等级/积分、商户授予、后台改密和手机号修改等管理接口必须携带平台管理员 Bearer 认证。原有 `admin_key`、`key` 字段仍接受以避免旧客户端请求体校验失败，但不再作为授权凭据。

## 找回密码

### `POST /user/reset-password`

Password-reset challenges are bound to the account identity resolved under a user-row lock when issued, not only to a mobile string. Unknown mobiles receive the same issuance response but no redeemable account-bound challenge. Redemption resolves and locks the current mobile owner and checks that it matches the stored account ID; changing a mobile invalidates outstanding challenges for that account. Concurrent password/mobile changes are rechecked under the session-creation lock so stale credentials cannot mint a session. Full flow and request contract remain in [security-auth.md](security-auth.md).
This endpoint has not been validated in this legacy summary. The current request flow, rate limits, challenge lifecycle, provider configuration, and errors are defined only by the canonical [authentication contract](security-auth.md#redeem-password-reset). Do not manually insert reset codes or derive hashes from the JWT signing secret. SMS credentials/delivery and candidate acceptance remain unverified until explicitly evidenced.

## 商品公开文本

商品名称、描述、购买规则、属性和 SKU 规格在新增/修改落库前必须通过服务端 `msgSecCheck`，账户没有可用微信审核身份或审核不通过时返回错误且不写入数据库。
