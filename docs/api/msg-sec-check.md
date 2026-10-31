# 微信文本内容安全接口与资料写入契约

业务基准：[禹泽业务接口文档](../禹泽小程序接口文档.md)，原始需求 V1.1 第八章。审核仅检查用户文本，不代替权益金融属性、宣传用语与交易模式的人工合规审查。

## 变更记录（2026-10-18）

| 变更前 | 变更后 | 影响 |
| --- | --- | --- |
| errcode=0 即放行 | 必须整数 errcode=0 且 result.suggest=pass | v2 risky/review 均阻止提交 |
| 上游异常、未知错误放行 | HTTP 200 + pass=false | 微信不可用时暂不能发布；安全优先 |
| 可指定任意 openid | 只使用登录账户 openid；提供的 openid 不匹配即拒绝 | 正常省略或提供本人 openid 的客户端兼容 |
| 空白文本放行；scene 自动转型 | 空白文本422；scene 必须JSON整数1~4 | 客户端需修正输入 |
| 资料修改按传入 mobile 写入，无认证 | Bearer认证、mobile匹配当前用户、按认证ID写入 | 旧客户端必须登录并携带Token |
| 姓名可跳过预检直接写入 | 修改昵称、新微信注册昵称均服务端审核 | 审核失败无写入；不可用503 |

## 通用约定

部署基址记为 `https://<API_HOST>`，需换成实际后端域名；不代表新增部署。响应 Content-Type 均为 `application/json`。Bearer 使用本项目业务登录令牌，**不是微信 access_token**。本次未新增凭据。

#### 文本安全预检

**基本信息**：`POST https://<API_HOST>/api/security/msg-sec-check`。登录有效且账户正常的会员可用；不要求商户/六星等级。Content-Type: application/json。业务审核结果（包含拒绝、服务不可用）返回200。

**请求参数**：

| 参数 | 位置 | JSON类型 | 必填/默认 | 规则、业务含义 | 合法/非法示例 |
| --- | --- | --- | --- | --- | --- |
| Authorization | header | string | 是/无 | Bearer业务Token，认证当前会员 | `Bearer <token>` / 缺失 |
| Content-Type | header | string | 是/无 | JSON请求体 | application/json / text/plain |
| content | body | string | 是/无 | 1~2500字，不能全空白；原文不截断不改写送审 | 消费回馈 / 空白、2501字 |
| scene | body | integer | 否/1 | 1资料、2评论、3论坛、4社交日志；拒绝布尔和数字字符串 | 1 / 5、true、"1" |
| openid | body | string或null | 否/null | 最长128字符；省略/null使用登录账户；非null必须与账户完全相同，不能替他人审核 | 本人openid / 他人openid |

**请求体示例**：

```http
POST https://<API_HOST>/api/security/msg-sec-check
Authorization: Bearer <business-token>
Content-Type: application/json

{"content":"本权益为会员消费回馈福利，非金融资产，不可提现、不可转让","scene":1}
```

非法示例：`{"content":"   ","scene":1}` → 422；`{"content":"昵称","openid":"other-user"}` → 200但pass=false。

**返回参数**：

| 字段 | JSON类型 | 必返 | 空值/枚举 | 含义 | 示例 |
| --- | --- | --- | --- | --- | --- |
| pass | boolean | 是 | 不为空；true/false | true为本次原文明确通过；false禁止提交 | false |
| message | string | 是 | 不为空；展示文本，不作为程序枚举 | 用户提示，不包含上游原文/Token/堆栈 | 检测服务暂不可用，请稍后重试 |

**返回示例**：

```json
{"pass":true,"message":"内容合规"}
```
```json
{"pass":false,"message":"内容含有违规信息，请修改后重试"}
```
```json
{"pass":false,"message":"内容需进一步审核，暂不可提交"}
```
```json
{"pass":false,"message":"检测服务暂不可用，请稍后重试"}
```

本接口无分页、无空列表响应；上游空对象、非对象、缺少errcode/result/suggest、未知suggest均不可用，不能判通过。

**使用方法与业务规则**：

1. 先微信登录获得业务Token。微信要求该openid近两小时访问过小程序；缺失openid或访问超时不得通过。
2. 输入完成后预检；只在 `response.pass === true` 时继续实际写入请求。修改文本后旧结果失效。
3. `request.js` 对200应正常resolve；`security.js` 遇到pass=false必须阻止提交。**catch、超时、401、422、429、5xx均不得默认true**。本目录未包含这两个客户端文件，客户端迁移仍需真实小程序源码验证。
4. 预检不签发授权凭证、不写数据库、不扣权益；无Idempotency-Key要求，重复请求可能重复消耗微信额度，不能认为结果永久有效。
5. 本项目尚无该接口专用每用户限流。微信官方上限：单appId 4000次/分钟、200万次/天，未上架小程序100次/天。避免每次按键调用，提交前按原文去重；额度耗尽拒绝，不绕过。
6. 代理不等于强制审核。`/user/update-profile` 以及新用户 `/wechat/login` 已在实际写入前独立审核；其他商品/店铺等文本写入尚需覆盖，见安全报告。
7. review暂阻止发布，本次没有人工复核工作流；本接口不改变会员等级、资产、订单或酒坛权属，不涉及注销恢复或额度退还。

**错误**：

| HTTP | 业务码 | 条件 | 返回/前端动作 |
| --- | --- | --- | --- |
| 200 | 无；pass=false | risky、review、旧版87014、缺少/伪造openid、上游超时/错误/畸形 | 显示message，禁止提交 |
| 401 | 无 | 缺失/无效/过期业务Token | `{"detail":"认证令牌无效或已过期"}`，重新登录；缺失Token可能为Not authenticated |
| 403 | 无 | 冻结/注销账户 | `{"detail":"账号已冻结"}`，禁止提交 |
| 422 | 无 | 请求参数不合法 | 下例，修正参数，不调用发布 |
| 500 | 无 | 认证数据库等内部故障 | `{"detail":"服务器内部错误，请稍后重试"}`，保留草稿 |

```json
{"detail":[{"type":"string_too_long","loc":["body","content"],"msg":"String should have at most 2500 characters","input":"<超长输入>","ctx":{"max_length":2500}}]}
```

错误detail是字符串或验证错误数组；数组元素的type为错误类型，loc为位置路径，msg为解释，input为拒绝的输入，ctx为可选约束信息。不要向日志复制完整请求/响应中的隐私文本。

#### 修改本人资料

**基本信息**：`POST https://<API_HOST>/user/update-profile`；必须登录并拥有目标账户；JSON；成功200。昵称审核采用scene=1。

**请求参数**：

| 参数 | 位置 | JSON类型 | 必填/默认 | 规则与含义 | 合法/非法 |
| --- | --- | --- | --- | --- | --- |
| Authorization | header | string | 是/无 | 本人Bearer业务令牌 | Bearer <token> / 缺失 |
| Content-Type | header | string | 是/无 | application/json | application/json / text/plain |
| mobile | body | string | 是/无 | 必须与登录记录完全相同（含微信占位手机号）；不用于授权查找 | 本人手机号 / 他人手机号 |
| name | body | string或null | 否/null | 1~100字非全空白；null不修改，提供时先审核 | 禹泽会员 / 空白 |
| avatar_path | body | string或null | 否/null | 仅null或省略可接受；头像走独立审核上传 | null / 任意路径均400 |
| old_password | body | string或null | 否/null | 修改密码时必填，需与原密码匹配 | 本人旧密码 / 错误密码 |
| new_password | body | string或null | 否/null | 非null触发改密；现有模型未限制长度，仍是待修风险 | 新密码 / 缺旧密码 |

**请求体示例**：

```http
POST https://<API_HOST>/user/update-profile
Authorization: Bearer <business-token>
Content-Type: application/json

{"mobile":"13800000000","name":"禹泽会员"}
```

非法：他人mobile→403；`name:" "`→422；`avatar_path:"/pic/x.jpg"`→400。

**返回参数**：`msg`：string，必返不为空；`ok`表示写入完成，`无字段需要更新`表示未提供可更新字段。不返回密码、openid或审核原始结果。

**返回示例**：`{"msg":"ok"}`；无变更：`{"msg":"无字段需要更新"}`。

**使用方法与业务规则**：先登录，预检可选但服务端审核不可跳过；使用认证ID查找并更新，不信任客户端ID。审核在数据库事务前进行，不占数据库连接等待微信；同步数据库操作在线程池。审核失败不改姓名也不改密码。重复同名请求最终值相同，但重新消耗审核额度；无Idempotency-Key、无专用频控；不承诺并发版本冲突检测。无状态转移、资产扣减、退款或分页。

**错误**：401/403认证或归属错误；400头像路径直写、违规/待复核、缺旧密码/旧密码错误；404账户已不存在；422模型校验；503微信不可用/未绑定openid；500内部故障。400例 `{"detail":"内容未通过安全审核，请修改后重试"}`，503经main全局处理为 `{"detail":"服务器内部错误，请稍后重试"}`。所有失败必须保留草稿并停止后续写操作。

**迁移**：发布后旧匿名调用立即失效，没有不安全的匿名兼容路径。前端携带Bearer与本人mobile，仅明确成功后刷新页面。头像仍走原审核接口。

## 微信登录影响

`POST /wechat/login` 完整参数见业务接口文档。本次对nickName增加1~100字非空白检查；新用户使用code兑换的openid审核通过才注册。已有用户登录不修改昵称，不重复审核。违规/待复核400、微信审核不可用503；登录失败不得误认为账号已创建。旧客户端仍使用code/nickName字段。

## 依据

- [微信官方 msgSecCheck v2：result.suggest、openid两小时、2500字及额度](https://developers.weixin.qq.com/miniprogram/dev/server/API/sec-center/sec-check/api_msgseccheck.html)
- [OWASP：默认拒绝、每次请求校验、不可依赖客户端](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP：日志不得记录 access token](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

## 旧手机号注册入口影响

`POST /user/auth` 的新用户分支禁止非null的 `name`（400，`detail="自定义昵称请通过微信登录或登录后的资料审核接口设置"`）；省略或null仍使用现有服务端默认昵称。已有账号密码登录不改昵称。本入口无可信微信openid，不允许伪造身份送审。旧客户端应省略注册name，并在微信登录后的资料修改接口设置昵称；本次未实现手机号验证码认证或账号绑定新流程。
## 商品创建与更新的文本安全审核

适用接口：`POST /api/products` 新建商品、`PUT /api/products/{id}` 修改商品。两者均要求 Bearer 登录；创建者必须是商家或平台，更新者必须是商品所属商家或平台管理员。Content-Type 和响应 Content-Type 为 `application/json`，成功返回 HTTP 200。

### 请求参数及审核范围

| 参数 | 位置 | JSON类型 | 必填/默认 | 校验及业务含义 |
| --- | --- | --- | --- | --- |
| Authorization | header | string | 是/无 | `Bearer <business-token>`，服务端确定操作者；客户端 `user_id` 不能覆盖身份 |
| Content-Type | header | string | 是/无 | 必须为 `application/json` |
| name | body | string/null | 创建必填；更新可选 | 商品名称；实际保存的最终值独立审核 |
| description | body | string/null | 否/null | 商品描述；创建/更新最终值独立审核 |
| category | body | string/null | 创建必填；更新可选 | 必须为项目既有类别；最终值审核 |
| buy_rule | body | string/null | 否/null | 对外购买规则；最终值审核 |
| attributes | body | object[]/null | 否/null | 属性数组；审核每个属性键、名称和值文本，不将 JSON 整体送审。字段兼容 `{ "name": "材质", "value": "棉" }` 与单键 `{ "材质": "棉" }` |
| skus | body | object[]/null | 创建必填；更新可选 | 每个 SKU 的 `sku_code`、规格对象每个 key/value 文本分别审核。创建SKU另需价格、库存；更新已有SKU可带 id，新增SKU不带 id且需 sku_code/price/stock |

产品字段完整说明：`user_id` 为body integer/null，创建时忽略、更新时仅平台管理员可更改；`is_member_product` boolean默认false；`status` integer默认0且仅允许0/1/2/3（草稿/上架/下架/缺货）；`freight` number默认0且只接受0；`max_points_discount`、`reward_rain`、`reward_points` 为非负number/null；`is_virtual`、`cash_only` boolean默认false。这些机器/非文本字段不送审。创建需要 `skus` 数组；每个SKU `sku_code` string必填、`price` number与`stock` integer必填非负、`original_price` 非负number/null，`specifications` 是可嵌套JSON object/null。更新SKU的 `id` integer/null；无id为新增（需sku_code/price/stock），带id必须属于该商品；提供列表沿用现有语义：未列出的SKU删除。`attributes` object[]/null；缺省/null不修改，提供数组时替换现有属性；无效空属性项保持原有跳过行为。

仅审核公开文本字符串叶项及对象键；数字/布尔/内部ID等机器字段不送审。SKU规格的所有嵌套键与字符串值递归逐项审核；空白文本不调用微信。每个文本项按Python `len()` (Unicode code points)上限2500字符，超过时HTTP 400并返回字段路径，不截断；多个文本项累计长度不限制，不把JSON聚合长度当限制。

### 请求示例

```http
POST https://<API_HOST>/api/products
Authorization: Bearer <business-token>
Content-Type: application/json

{"name":"棉质上衣","description":"日常穿着","category":"服装鞋帽","buy_rule":"每人限购","skus":[{"sku_code":"shirt-blue","price":99,"stock":5,"specifications":{"颜色":"蓝色","尺码":["M","L"]}}],"attributes":[{"name":"材质","value":"棉"}]}
```

更新示例：`PUT https://<API_HOST>/api/products/42`，同样Headers，Body可为 `{"description":"新描述","attributes":[{"name":"材质","value":"棉"}]}`；非法示例包括任一公开文本项为2510字符，或将 `specifications` 的嵌套值设为违规内容，返回审核/长度错误且不写入任何产品、属性或SKU部分数据。

成功返回原有商品响应：`status`（string，必返，`success`）、`message`（string，必返，创建/更新结果）、`data`（object，必返，完整商品记录）。`data.id` 是商品integer ID；`name`、`pinyin`、`description`、`category`、`status`、`user_id` 分别是商品文本/状态/拥有者；`main_image`、`detail_images`、`banner_images` 是图片路径或列表（无图时可为null/空列表）；`is_member_product`、`buy_rule`、`freight`、`max_points_discount`、`is_home_recommend`、`reward_rain`、`reward_points`、`is_virtual`、`cash_only` 为商品销售/展示属性；`created_at`、`updated_at` 是时间戳。`skus` 是数组，每项 `id` (integer)、`sku_code` (string)、`price` (number)、`original_price` (number/null)、`stock` (integer)、`specifications` (object/null)。`attributes` 是数组，每项 `name` 和 `value` 为string。未另行给值的字段仍按实际schema返回；无SKU/属性时是空数组。成功响应示例结构：`{"status":"success","message":"商品已创建","data":{"id":42,"name":"棉质上衣","pinyin":"mianzhi shangyi","description":"日常穿着","category":"服装鞋帽","status":0,"user_id":7,"main_image":null,"detail_images":[],"skus":[{"id":11,"sku_code":"shirt-blue","price":99.0,"original_price":null,"stock":5,"specifications":{"颜色":"蓝色","尺码":["M","L"]}}],"attributes":[{"name":"材质","value":"棉"}]}}`。


### 使用规则、错误与兼容性

写入端每次调用都独立送审，不依赖客户端预检；所有文本项明确通过后才执行插入/更新。任一违规、review、上游不可用/异常即 fail-closed，不发生部分写入。更新先读取不可变内容快照并关闭数据库连接，再调用审核服务；审核后启动短事务锁定商品、SKU及属性，若任何已审核商品文本或嵌套SKU/属性文本与快照不一致，则返回409且不写入。未发生冲突才在同一事务保存，禁止审核期间持有连接/锁。平台管理员可更新任何商品，但无openid仍不能写入；必须有服务端绑定openid。

| HTTP | 触发 | 客户端处理 |
| --- | --- | --- |
| 200 | 审核通过且完整写入 | 使用响应中的 `data` 刷新商品 |
| 400 | 审核拒绝、单项文本超过2500字符或数据库输入错误 | 保留草稿；超长项按detail中的字段路径缩短，不自动截断；不得假设有部分更新 |
| 403 | 角色/所有权不符或当前账户无微信审核openid | 禁止提交/先绑定微信身份 |
| 404 | 更新商品不存在 | 刷新商品列表 |
| 422 | 请求模型字段无效 | 按字段错误修正 |
| 409 | WeChat审核期间商品文本被其他写请求修改，导致最终快照已过期 | 丢弃此次结果，重新加载商品内容后再次编辑/送审；不自动重试覆盖 |
| 503 | 微信审核不可用 | 保留草稿，稍后重试；服务暂不可用不得放行 |

旧客户端请求/响应形状不变；更新时遗漏文本字段仍保存原值，但原值也纳入最终快照审核。没有审核票据、额度扣减或幂等Key；重复调用会重新消耗审核额度。快照冲突返回409，客户端应重新加载再提交，不自动覆盖并发写入。事务短锁仅用于快照一致性检查和保存。当前SKU/属性结构与请求兼容，不需迁移。

## 商品文本审核变更记录（CONTENT-001）

| 变更前 | 变更后 | 影响 |
| --- | --- | --- |
| 商品attributes与SKU规格以整段JSON审核，长JSON可能超过服务上限或漏审内部字段 | 逐个审核公开文本键/值及SKU文本，不做聚合JSON和截断 | 多次微信审核调用，但每项遵守2500字符限制 |
| 已更新只审核请求字段，或在数据库事务锁中等待上游审核 | 读取快照后关闭DB连接再审核；通过后锁定记录并比较全部审核文本，冲突HTTP409，不写入 | 网络等待不持锁；并发编辑者重新载入后再提交 |

真实微信端字符边界和provider行为仍需授权环境联调；本地控制流/mock测试不构成真实微信验证。

## 验证记录

WSL 原生 Linux Python 3.14.7，锁定依赖安装确认 dbutils 3.2.0。最终 `pytest -q -p no:cacheprovider tests`：48 passed，13条存量Pydantic弃用告警。实际 `main:app` HTTP冒烟覆盖代理pass/risky/timeout、资料写入审核拒绝/越权拒绝和OpenAPI认证/布尔响应模型；上游微信与登录身份为隔离替身，未验证真实微信资质、用户两小时访问记录、生产数据库提交或前端实际交互。详见 [安全与测试报告](../禹泽项目安全与测试报告.md)。
