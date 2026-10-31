# PR #219 最小止血补丁分析

日期：2026-10-24
目标分支：`fix/msg-sec-check-fail-closed`
远端基线：`69c6901 Merge PR #1: docs for #219 remediation options and acceptance checklist`

## 1. 业务代码改动文件清单

对比命令：

```bash
git log --oneline --no-merges c1cd77438d077a7b612c6048620d60b8f8cae3ce..HEAD
git diff --stat c1cd77438d077a7b612c6048620d60b8f8cae3ce..HEAD -- . ':(exclude)*.md'
git diff --name-only c1cd77438d077a7b612c6048620d60b8f8cae3ce..HEAD -- . ':(exclude)*.md'
```

结果：

- 非文档提交：无。
- 非文档差异统计：无。
- 业务代码改动文件：无。
- 当前 HEAD 的唯一非文档路径变化为零；HEAD 仅包含 PR #219 相关文档提交。

仓库文档约束要求的 `docs/DEVELOPMENT.md` 在当前工作树中未找到。

## 2. 安全校验/消息校验入口、调用链与错误分支

### 2.1 文本消息安全校验

入口及调用链：

1. `POST /api/security/msg-sec-check`
   - `api/security/routes.py:41-61`
   - 认证依赖 `get_current_user`。
   - 缺少当前用户 `openid`：返回 HTTP 200、`pass=false`。
   - 请求中的 `openid` 与认证身份不一致：返回 HTTP 200、`pass=false`，且不调用微信。
   - Pydantic 对空白、长度、`scene` 类型/范围做 422 拒绝。
2. 写入端强制审核：
   - `api/user/routes.py:176-184`：本人资料昵称写入前调用 `require_safe_text`。
   - `api/user/routes.py:1389-1392`：微信新用户昵称注册前调用 `require_safe_text`。
   - `api/product/routes.py:44-57`、`api/product/routes.py:511`、`api/product/routes.py:648-656`：商品公开文本和 SKU 规格写入前调用 `require_safe_text`。
3. 统一判定：
   - `services/wechat_api.py:336-355` 的 `check_text_security`。
   - 上游异常、非字典、非严格整数 `errcode`、未知错误码、缺失/未知 `suggest` 均转为 `unavailable`。
   - 只有严格的 `errcode == 0` 且 `suggest` 为 `pass`/`risky`/`review` 才继续分类。
4. 写入拒绝：
   - `services/wechat_api.py:358-366` 的 `require_safe_text`。
   - `unavailable` 返回 503；非 `pass` 返回 400；没有异常转放行分支。

结论：上述文本校验链路当前已是 fail-closed。本轮不应为其重构或扩大修改面。

### 2.2 头像异步消息安全审核

入口及调用链：

1. 微信回调路由：`api/wechat_wxa/routes.py:112-116` 调用 `AvatarModerationService.handle_result`。
2. 回调判定：`services/avatar_moderation_service.py:301-331`。
3. 只有批次内所有记录为 `pass` 时，`services/avatar_moderation_service.py:386-405` 才移动文件并更新用户头像。
4. `risky`/`failed` 会使批次失败并清理待审核文件。

发现的 fail-open 风险：

- `services/avatar_moderation_service.py:319-326` 当前使用：
  `int(data.get("errcode") or result.get("errcode") or detail.get("errcode") or 0)`。
- 缺失 `errcode`、空值 `errcode` 或布尔 `False` 会被 `or 0` 视为 0。
- 若同一回调含 `suggest=pass`，后续会被归类为 `pass`，可能满足整批 `all(status == "pass")` 并公开写入头像。
- 这违反“审核响应缺少必要成功字段时必须拒绝”的 fail-closed 要求。

## 3. 九条未完成项在本仓库的对应位置

以下位置来自 `docs/待完成事项.md`、`docs/PR219-04-逐项整改与验收清单.md` 与当前代码定位；本报告不把位置存在视为已完成。

| 项 | 当前对应位置 | 状态 |
|---|---|---|
| U1 短信签发、发送、用途绑定、原子核销 | `api/user/routes.py`、用户 schema、认证/用户服务及验证码相关逻辑 | 未完成；未发现已验收的真实短信发送闭环 |
| U2 JWT 与全部会话撤销 | `core/auth.py`、登录签发点、改密/退出/禁用入口 | 未完成；需证明存量 JWT 服务端撤销 |
| U3 审核/直接退款稳定身份、幂等与恢复 | `api/order/refund.py`、`api/order/merchant.py:385-395`、退款服务/支付客户端 | 未完成；外部成功本地失败和恢复未验收 |
| U4 支付/退款通知持久化后确认 | `api/wechat_pay/routes.py` 的支付、退款通知路径 | 未完成；全部提交失败/重放路径未验收 |
| U5 订单状态竞态 | `api/order/order.py`、`api/order/wechat_shipping.py`、`api/order/refund.py`、`api/wechat_pay/routes.py`、后台任务 | 未完成；全部迁移无双连接证据 |
| U6 MySQL 库存/余额/发券竞争 | `core/database.py`、订单/财务/积分/券服务 | 待隔离环境；当前无本次独立 MySQL 竞争证据 |
| U7 商品属性/SKU 全文本审核 | `api/product/routes.py:44-57, 503-511, 648-656`、商品 schema、`services/wechat_api.py` | 未完成/待边界验收；当前已有审核调用，但深层文本及 2501 边界未完整验收 |
| U8 授权矩阵、核销、幂等、回调、日志专项 | `core/auth.py`、订单/财务/用户/支付/回调路由及 `tests/` | 未完成；历史测试不能替代本轮专项证据 |
| U9 真实短信/微信支付退款/审核联调 | 微信/支付/短信外部配置与 `api/wechat_wxa/routes.py`、`api/wechat_pay/routes.py` | 待外部授权与隔离环境；本地不具备真实联调条件 |

## 4. 六条前端影响项中涉及后端接口的部分

1. **统一 Bearer 请求层**：所有受保护接口依赖 `core.auth.get_current_user`；文本审核接口为 `POST /api/security/msg-sec-check`，资料接口为 `POST /user/update-profile`。
2. **管理员权限**：后端应以 `ADMIN_USER_IDS` 等服务端配置判定管理员；`api/order/merchant.py:385-395` 是商家退款审核入口，不能由客户端 `admin_key`/`key` 授权。
3. **本人作用域**：`/user/update-profile` 由认证用户 ID 和手机号匹配控制；头像上传、头像清空及个人资源接口按认证用户 ID 校验。
4. **401/403 处理**：认证依赖负责 401；归属/权限不符由接口返回 403；客户端不得把这些错误转为继续提交。
5. **服务端价格与数量**：订单/商品接口必须使用服务端权威价格并拒绝非正整数数量；具体资金接口仍属 U5/U6/U8 未验收范围。
6. **短信找回**：后端应提供“申请发送→用途绑定核销→改密”的完整接口契约；当前真实短信闭环未完成，不能以固定码或前端生成码兼容放行。

## 5. 候选止血点清单

| 文件:行 | 当前行为 | fail-open 风险 | 最小改法 | 影响面 | 是否可独立回滚 |
|---|---|---|---|---|---|
| `services/avatar_moderation_service.py:319-326` | 从回调顶层、`result`、`detail` 读取 `errcode`，缺失/空值经 `or 0` 归一为成功；随后 `suggest=pass` 可进入 `pass` 分支 | 缺少必要成功字段的审核响应可能被当成成功，触发头像公开写入 | 在解析前要求 `errcode` 存在且为严格整数（并拒绝布尔）；无法确认 `0` 时返回非通过状态（建议 `failed`），不改变函数签名或数据库结构 | 仅影响头像异步审核回调；有效的 `errcode=0`/`suggest=pass` 和明确 risky/review 语义保持不变 | 是；单文件逻辑与对应回归测试可单独提交/回滚 |
| `services/avatar_moderation_service.py:409-425` | 回调处理/文件移动异常记录日志后直接返回；记录可能继续保持 `pending`，待审核媒体仍可能在 TTL 内可取 | 处理异常不应形成已发布头像，但会保留待审核媒体；是否属于本轮“安全校验失败必须拒绝”需结合媒体暴露契约确认 | 暂不实施；当前证据不足以证明它是公开发布 fail-open，避免扩大补丁 | 可能涉及回调重试、媒体访问和清理语义 | 若确认范围后可独立回滚，但本轮不选 |
| `services/wechat_api.py:336-355` | 文本审核异常和未知响应转 `unavailable`，写入端由 `require_safe_text` 拒绝 | 当前未发现 fail-open；修改会扩大已闭合路径 | 不修改 | 影响所有文本预检、资料、注册及商品写入 | 不适用；本轮不选 |

**本轮建议止血范围：**仅实施第一项头像回调 `errcode` 严格失败分支；不涉及公共接口签名、数据库结构、短信、JWT、支付、退款或订单状态。

## 6. 本地无法验证、必须隔离环境验证

- 真实微信头像异步审核回调签名/报文兼容性及授权 `AppID/openid`：待隔离环境验证。
- 真实微信文本审核 2500 字 UTF-8/Unicode 边界：待隔离环境验证。
- 并发核销：待隔离环境验证。
- JWT 撤销：待隔离环境验证。
- 订单状态竞争：待隔离环境验证。
- MySQL/Redis 双连接竞争与连接隔离：待隔离环境验证。
- 退款“外部成功本地失败”、原退款号查询恢复及幂等：待隔离环境验证。
- 真实短信投递、支付/退款及生产回调：待隔离环境验证。

## 7. 本阶段结论

当前工作区干净，分支与远端检查符合任务要求，且未修改业务代码。建议维护者确认后再进入第 2 步；确认范围仅为表中第一项时，后续新增一个针对“缺失/非严格 `errcode` 不得进入 `pass`”的回归测试，并以一个独立 `fix(sec): fail-closed on malformed avatar review callback` 提交完成。
