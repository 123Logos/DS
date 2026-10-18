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

## 验证记录

WSL 原生 Linux Python 3.14.7，锁定依赖安装确认 dbutils 3.2.0。最终 `pytest -q -p no:cacheprovider tests`：48 passed，13条存量Pydantic弃用告警。实际 `main:app` HTTP冒烟覆盖代理pass/risky/timeout、资料写入审核拒绝/越权拒绝和OpenAPI认证/布尔响应模型；上游微信与登录身份为隔离替身，未验证真实微信资质、用户两小时访问记录、生产数据库提交或前端实际交互。详见 [安全与测试报告](../禹泽项目安全与测试报告.md)。
