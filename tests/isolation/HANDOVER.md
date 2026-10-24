# PR #219 隔离环境测试交接手册

本文交接给环境/测试负责人，用于配置独立 MySQL、Redis 和测试接口后执行 U1/U2/U3/U5/U6 验收。测试只允许使用合成数据，所有合成数据必须带 `test_219_` 前缀。

## 1. 所需环境变量

请在隔离环境或 CI Secret/Variables 中提供以下配置。下面只有变量模板，不包含真实密码、Token、证书或生产地址。

### MySQL

```dotenv
ISOLATED_MYSQL_HOST=<isolated-mysql-host>
ISOLATED_MYSQL_PORT=3306
ISOLATED_MYSQL_USER=<isolated-test-user>
ISOLATED_MYSQL_PASSWORD=<isolated-test-password>
ISOLATED_MYSQL_DATABASE=<isolated-test-database>
```

### Redis

```dotenv
ISOLATED_REDIS_HOST=<isolated-redis-host>
ISOLATED_REDIS_PORT=6379
ISOLATED_REDIS_PASSWORD=<isolated-redis-password-or-empty>
ISOLATED_REDIS_DB=0
```

### 合成数据 seed 与清理

这些 SQL 必须只操作 `test_219_` 前缀数据；不得使用 `FLUSHALL`、清空整张表或无条件删除其他数据。

```dotenv
ISOLATED_CLEANUP_SQL=<parameterized-delete-sql-containing-test_219_>
ISOLATED_SEED_USER_SQL=<parameterized-user-seed-sql-containing-test_219_>
ISOLATED_SEED_ORDER_SQL=<parameterized-order-seed-sql-containing-test_219_>
```

fixture 会把 `test_219_` 作为参数传给这些 SQL，并拒绝不包含该前缀的配置。

### U1 验证码并发核销

```dotenv
ISOLATED_CAPTCHA_VERIFY_URL=<isolated-captcha-verify-url>
ISOLATED_CAPTCHA_VERIFY_BODY=<json-request-body>
ISOLATED_CAPTCHA_REDEEM_QUERY=<query-returning-test_219_redeem_count>
```

### U2 JWT 撤销

```dotenv
ISOLATED_LOGIN_URL=<isolated-login-url>
ISOLATED_LOGIN_BODY=<json-login-body>
ISOLATED_REVOKE_URL=<isolated-revoke-or-password-change-url>
ISOLATED_REVOKE_BODY=<json-revoke-body-or-{}> 
ISOLATED_PROTECTED_URL=<isolated-protected-endpoint>
ISOLATED_JWT_DENYLIST_PREFIX=test_219_jwt_deny_
```

### U5 订单状态竞争

```dotenv
ISOLATED_PAYMENT_CALLBACK_URL=<isolated-payment-callback-url>
ISOLATED_PAYMENT_CALLBACK_BODY=<json-payment-callback-body>
ISOLATED_CANCEL_URL=<isolated-cancel-url>
ISOLATED_CANCEL_BODY=<json-cancel-body>
ISOLATED_ORDER_STATE_QUERY=<query-returning-state-stock-balance-for-test_219_>
ISOLATED_ORDER_SIDE_EFFECT_QUERY=<query-returning-single-side-effect-count-for-test_219_>
```

### U6 MySQL/Redis 双连接故障与安全校验

```dotenv
ISOLATED_SECURITY_FAULT_PATCH_TARGET=<approved-test-patch-target>
ISOLATED_SECURITY_URL=<isolated-security-check-url>
ISOLATED_SECURITY_CONTENT=test_219_security_probe
ISOLATED_SECURITY_DIRTY_WRITE_QUERY=<query-counting-test_219_dirty_writes>
```

### U3/U4 退款外部成功、本地失败

```dotenv
ISOLATED_REFUND_URL=<isolated-refund-url>
ISOLATED_REFUND_BODY=<json-refund-body>
ISOLATED_REFUND_COMMIT_PATCH_TARGET=<approved-test-commit-patch-target>
ISOLATED_REFUND_RECONCILIATION_QUERY=<query-returning-pending-and-external-reference-counts>
ISOLATED_REFUND_EXTERNAL_COUNT_QUERY=<query-returning-test_219_external-refund-count>
```

请求体、SQL 和 patch target 必须对应当前隔离部署版本。请勿填入生产 URL、生产数据库、生产 Redis、生产 Token、生产证书或真实用户/订单数据。

## 2. 如何配置

1. 在隔离测试工作区根目录创建本地 `.env`，或在 CI 中创建同名的受保护变量。
2. 将上述变量填入实际隔离环境值；密码和凭据只通过本地未提交文件或 CI Secret 注入。
3. 不要提交 `.env`、真实密码、证书、Token、真实用户/订单数据。
4. 启动测试前确认 MySQL 和 Redis 均为独立实例，且网络出口不会连接生产服务。
5. 确认所有 seed、查询和清理配置仅涉及 `test_219_` 合成数据。

如果变量不存在或连接失败，不要使用 SQLite、内存 Mock 或其他替代物；保留测试错误并在验收反馈中标记“阻塞：隔离环境未就绪”。

## 3. 如何执行测试

在配置完成的隔离工作区执行：

```powershell
uv run pytest tests/isolation/ -v
```

建议同时保存完整日志：

```powershell
uv run pytest tests/isolation/ -v 2>&1 | Tee-Object -FilePath "$env:TEMP\219-isolation-test.log"; exit $LASTEXITCODE
```

## 4. 结果如何反馈

### 测试全绿（Pass）

请反馈：

- 完整命令和退出码；
- pytest 完整输出或日志截图；
- 每个 U 项的通过数量；
- MySQL/Redis 隔离实例标识（不得包含密码）；
- 并发请求数、最终订单/库存/余额/核销状态等断言结果。

### 测试失败（Fail/Error）

请先区分测试脚本问题和业务行为问题：

- 如果是测试脚本里的接口路径、请求参数、SQL 查询或 patch target 写错，请保留完整错误输出，标记为“脚本配置/契约问题”，联系开发修复测试脚本。
- 如果是发现真实业务 Bug，例如并发扣库存超发、验证码被多次核销、旧 JWT 撤销后仍可访问、退款重复打款或本地状态未进入待对账状态，**严禁修改 `services/` 下的业务代码**。
- 真实业务 Bug 必须反馈：完整 pytest 报错日志、请求/响应摘要、测试用例和合成业务 ID、SQL 现场查询结果、连接/事务信息、最终数据库与 Redis 状态。
- 不要用重跑、手工改库或删除记录掩盖失败；如需清理，只允许 fixture 的精确 `test_219_` 清理机制。

### 环境阻塞

如果环境变量缺失、MySQL/Redis 连接失败或隔离网络未就绪，反馈：

> 阻塞：隔离环境未就绪。未使用 SQLite/内存 Mock 替代，测试场景未执行。

## 5. 清理机制

- 每个测试用例结束后，fixture 会执行配置的精确清理 SQL。
- 清理 SQL 必须包含 `test_219_`，fixture 会拒绝不带此前缀的清理配置。
- Redis 仅扫描并删除 `test_219_*` 键。
- 不使用 `FLUSHALL`，不清空整张表，不删除其他前缀或环境的数据。
- 测试结束后请抽查清理结果，并在反馈中说明 `test_219_` 数据已清理。

本手册对应的测试只用于 PR #219 隔离验收，不代表生产部署安全，也不授权生产故障注入、真实短信发送、支付或退款操作。
