# FIN-001 / FIN-002 财务安全契约

## 变更记录与迁移

2026-10-25：所有注册财务数据路由（包括原无鉴权报表、配置读写、提现审核和最后注册的商户提现路由）统一要求有效 Bearer 会话。仅原非敏感 `GET /` 状态接口保持公开，精确限定方法、路径和处理函数；不扩大到任何财务数据接口，也不改变独立 `/health`、`/ready` 路由。旧 `key` / `admin_key` 不授予权限；不保留财务数据匿名或共享密钥兼容路径。管理员由 `core.auth.is_platform_admin` 判定，不接受客户端角色。客户端必须同批迁移：401 清除会话并重新登录，403 显示无权限，不自动循环登录。

数据库先执行 `migrations/006_security_finance.sql`。新表 `finance_requests` 保存可信操作者、区分大小写的请求 key、操作、规范参数摘要、原始结果；`finance_events` 保存结算/退款/折扣事件。两表与余额、券、账本使用同一个 InnoDB 事务，无运行时 DDL。不得对尚未对账事件做 TTL 删除。回滚应用前保留这些持久身份表；不得删除后重放旧业务。

## 所有路由通用认证和数据作用域

**基本信息**：沿用注册的完整 URL（无 `/finance` 前缀）、HTTP method、原请求和成功响应结构；Content-Type / Accept 为 `application/json`；所有成功响应 HTTP200。下表列出的个人接口可以由本人或平台管理员访问；其余所有财务数据路由，包括所有 `/api/admin/*`、平台/公益资金池查询、全用户预览、提现查询/列表/指南、配置、清池和管理写入，均只允许平台管理员。未知/后续新增财务路由默认管理员，不能自动继承个人作用域。唯一公开财务路由 `GET /` 无请求体、无参数，返回 `{"message":"财务管理系统API运行中","version":"3.2.0"}`，字段均为固定字符串，不含财务或用户信息；其他方法/路径无此豁免。

| 本人接口（GET，除注明者） | 请求作用域和业务 |
|---|---|
| `/api/coupons/expiring` | 忽略外部目标，以会话 id 查询；days 默认3，1..30 |
| `/api/coupons/use`（POST） | coupon_id、user_id 正整数；order_type 可选 normal/member；用户必须本人，且券归属/有效期/未使用满足条件 |
| `/api/donate/true-total-points`（POST） | user_id 正整数且本人；amount 正数；锁用户余额，1:1捐赠，用户支出与公益池收入同事务 |
| `/api/rewards/referral`, `/api/rewards/flow` | user_id 可选；省略强制本人，不代表全部用户 |
| `/api/reports/points/subsidy`, `/api/reports/points/unilevel`, `/api/reports/points/referral-team`, `/api/reports/points/all`, `/api/reports/points-flow` | user_id 可选，省略强制本人 |
| `/api/reports/order-points` | user_id 可选，省略强制本人；order_no 只是额外过滤，不能扩大作用域；start_date/end_date yyyy-MM-dd 必填 |
| `/api/reports/subsidy/weekly`, `/api/reports/subsidy/monthly` | user_id 可选，省略强制本人；year>=2024，week1..53 或 month1..12 |
| `/api/reports/points/member/weekly`, `/api/reports/points/member/monthly` | 同上，会员积分个人报表 |
| `/api/reports/points/merchant/weekly`, `/api/reports/points/merchant/monthly` | 同上，只能看到本账号商家积分，不能替换商户用户 id |
| `/api/reports/unilevel/points-flow`, `/api/reports/withdrawal`, `/api/reports/points/all-flows`, `/api/reports/points/member/detail` | user_id 可选，省略强制本人；其余原日期/分页/类型过滤不能扩大作用域 |

管理员可明确传 user_id 查询目标，或留空查询全用户；普通用户传他人 user_id 在执行服务前 HTTP403。`/api/reports/platform/flow-summary` 和 `/api/reports/points/all-detail` 含平台级信息，始终管理员，不因传本人 user_id 放行。所有财务读写使用权威会话认证，撤销令牌同样拒绝。
所有个人报表汇总和记录使用同一用户过滤；周/月补贴、会员积分、商家积分和联创点数汇总不得去掉 user_id。周补贴 data.summary.company_points_balance 对指定用户作用域返回 null，记录若为平台积分来源，其 points_source.current_balance 同样为 null；只有管理员未指定用户的全局报告才返回平台池余额。个人订单积分报告的 platform_points_included 为0，不读取全局池补入个人合计。客户端应把 null 显示为无权限/不适用，不能解释为实际零余额。

**请求参数**：Authorization header 必填，字符串 `Bearer <token>`；无默认值；必须为未撤销有效会话。个人接口 user_id query 是正整数，可选（use/donate 必填）；默认本人，仅管理员能扩大作用域。页码 page>=1；原各接口 page_size 上限仍保留。报表 GET 无请求体。

**请求体示例**：`GET /api/reports/points/subsidy`，Headers `Authorization: Bearer <token>`、`Accept: application/json`，无请求体。非法示例：本人 token 请求 `GET /api/reports/points/subsidy?user_id=<其他用户>` 返回403，即使同时提供 `admin_key`。

**返回参数**：ResponseModel 的 success:boolean 必返（是否成功）、message:string 必返（描述）、data:接口原业务对象/可空。个人报表数据保持原字段，不引入新的分页包装；其嵌套记录只能来自经过作用域过滤的数据。无记录返回原空 users/records/flows 数组和零汇总，不用他人数据补空结果。分页接口沿用 data.pagination.page/page_size/total/total_pages 或原 page/page_size/total/records 结构，不新增 `has_more`。

**返回示例**：`{"success":true,"message":"查询成功","data":{"summary":{"total_users":0,"report_type":"subsidy_points"},"users":[]}}`。

**使用方法与业务规则**：登录后调用；个人查询无需先调用管理员接口。GET 无资金副作用。券使用锁券行，竞争请求只能一个从 unused 变为 used；日期超出有效期拒绝。捐赠用户余额锁在整个扣款/收入/双流水事务内，竞争不能丢失余额。提现审核的 auditor 原客户端字段不再作为可信操作者，实际审计记录使用管理员会话 id，审核状态和流水同事务。原业务分配比例、会员政策、雨点月330/每日30规则不变。

**错误**：401 无效/过期/撤销会话（重新登录）；403 非管理员或跨用户（不要换 key 重试）；422 参数缺失/格式不合法；400 余额不足、券不可用等业务冲突；500 数据库/内部失败，整笔回滚。标准错误体 `{"detail":"只能访问本人财务数据"}`。无独立业务错误码字段。

## 持久发券接口

**基本信息**：以下均 POST、平台管理员、HTTP200 成功；JSON响应。发行请求新增必填 `Idempotency-Key` header，1..128 个 ASCII 可打印非空白字符，区分大小写。身份为 `(会话管理员id,key)`，跨操作复用 key 也会冲突；网络结果未知时只能用原 key/原参数重试。无自动过期。

| URL | 参数位置、类型、必填、默认、范围及意义 |
|---|---|
| `/api/coupons/distribute` | query user_id:int 必填>0；amount:number 必填且为正整数张数（每张1元，非整数不再截断）；coupon_type:string 默认user，user/merchant；applicable_product_type:string 默认all，all/normal_only/member_only；valid_days:int 默认COUPON_VALID_DAYS，0..365 |
| `/api/coupons/distribute-batch` | JSON user_ids:int[] 必填非空目标；amount:number 必填>0 为单张券面额；coupon_type、applicable_product_type同上（默认user/all） |
| `/api/coupons/exchange` | query count:int 可选>0，每用户最大张数；省略沿用系统配置，原每用户1000上限保留 |
| `/api/fund-pools/transform-to-coupon` | query pool_type:string 必填，public_welfare/maintain_pool/shop_pool/city_pool/branch_pool/fund_pool；user_id:int 必填>0；amount:number 必填正整数元；coupon_type、applicable_product_type同上；remark:string 可选操作备注，默认null |

**请求体示例**：`POST /api/coupons/distribute?user_id=123&amount=2&coupon_type=user&applicable_product_type=all&valid_days=30`，Headers `Authorization: Bearer <admin-token>`、`Idempotency-Key: issue-20261025-123-01`，无请求体。批量请求 `POST /api/coupons/distribute-batch` 同样 headers，加 `Content-Type: application/json`，Body `{"user_ids":[123,124],"amount":1,"coupon_type":"user","applicable_product_type":"all"}`。非法示例：amount=1.5 的单人发行422；缺 key422；普通用户即使提供 key403。

**返回参数**：外层 success:boolean、message:string、data:object 必返。单人发行 data.coupon_ids:int[] 为持久化券 id；count:int 券数；amount_per_coupon:number 固定1；total_amount:number 总面额；applicable_product_type:string 适用范围；valid_days:int 天数。转正同结构但无 applicable_product_type/valid_days。批量 data.success_count:int 成功券数、failed_users:object[] 每项 user_id:int/reason:string、coupon_ids:int[]；交换 data.success_count:int 成功人数、total_users:int 锁定候选人数、failed_users:array（事务成功时空）、total_coupons_issued:int 总券数、message:string 摘要。

**返回示例**：`{"success":true,"message":"已发放 2 张 1 元优惠券","data":{"coupon_ids":[41,42],"count":2,"amount_per_coupon":1.0,"total_amount":2.0,"applicable_product_type":"all","valid_days":30}}`。批量全失败允许 `{"success":true,"message":"成功发放 0 张优惠券","data":{"success_count":0,"failed_users":[{"user_id":123,"reason":"余额不足"}],"coupon_ids":[]}}`。

**使用方法与业务规则**：单人发行按张1:1扣 true_total_points，整个请求不足则无券/无流水/无成功幂等记录；锁用户行后读取权威余额。批量保留原业务允许的逐目标业务失败语义，但每个失败目标先回滚 SAVEPOINT，绝不提交该目标半成品；数据库错误终止并回滚全部。全平台兑换一个事务按用户id顺序锁定，避免过去分批独立提交造成中途失败后重试重复发放。转正锁目标/池余额，池支出、券、日志和请求结果一起提交。原 key 重放返回原券 id，不重新扣款。没有记录时返回空券数组，不伪造券。池转正不扣目标雨点，政策不变。

**错误**：401/403如前；422缺 key/非法参数；409 `{"detail":"Idempotency-Key 已用于不同请求"}`（必须修正调用方，不能自动换 key掩盖冲突）；400余额不足或目标不存在；500数据库失败。未知响应先以原身份重试；失败事务不遗留可见成功记录。

## 支付/退款事务内部契约（非 HTTP）

- `FinanceService.settle_order(order_no,user_id,order_id,points_to_use=0,coupon_discount=0,external_conn=conn)`：在订单行锁后，以 finance_events settlement/order_no 判重；所有资产、账本、优惠券核销和可信支付状态迁移在传入连接完成。绝不提交或关闭传入连接；异常必须传播。无外部连接时自己提交。PaymentOwner 只在可信支付/零元结算路径调用。
- `reverse_split_on_refund(order_number,external_conn=conn,event_key=out_refund_no,refund_amount=Decimal(refund_fee)/100)`：订单锁和单笔稳定退款号去重；同号不同金额拒绝。按累计现金退款/订单实付比例回冲原实际账本，累计目标四位小数减已回冲值避免末笔舍入累积；覆盖原两种精确订单 token 备注，不能匹配同前缀其他订单。与退款终态同事务，不独立 commit。累计退款不得超过实付。退款账本可追溯原订单及 finance_events 中退款号/各账户金额。
- `FinanceService.revoke_order_discounts(order_number,external_cur=cur)`：只在完整订单状态 refunded 时退回积分/有效券并按原余额上限收回奖励；finance_events discount_refund/order_number 去重。部分退款不提前全退折扣；调用方在累计全额退款终态执行。所有错误导致外层事务回滚，事件标记不能先于资产提交。
- 旧 `FinanceService.refund_order` 自主改状态/独立回冲入口删除，所有退款调用方必须迁往 PaymentOwner 持久意图流程。

## 商户银行卡提现：明确未接入边界

`POST /api/withdraw/merchant-to-bankcard` 仍管理员、使用原 JSON schema（out_request_no/amount/account_type/bank_memo/remark/notify_url）；不新增路由或伪造成功。**返回 HTTP503** `{"detail":"商户提现供应商尚未接入，未创建申请或扣款"}`，无成功返回体、无记录和资产写入。原查询 `/api/withdraw/merchant-to-bankcard/query?out_request_no=...`、列表和历史记录保留，均管理员；历史 INIT 不代表微信受理。实际提款适配器、商户提款产品权限/凭据、结果查询/回调对账未具备，功能不能宣称实现或启用。BankcardService 现有结算卡绑定能力不等于提款能力。

## 验收和外部证明边界

新增 `tests/test_security_finance.py` 在 guard 认可的真实隔离 MySQL 测试持久重放/异参冲突、单人多张不足整笔回滚、事件与资产共同回滚；`tests/isolation/test_finance_business.py` 由隔离 harness 覆盖实际 HTTP 并发余额竞争/重放。执行命令：隔离环境初始化迁移后 `uv run pytest tests/test_security_finance.py tests/isolation/test_finance_business.py -q`。本实现阶段未运行测试、构建、lint或格式化；这些不是已通过声明。真实微信/短信/提款供应商证明不由合成数据或受控适配器替代。
