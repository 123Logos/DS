# PR #219 隔离并发与故障测试

这些测试只使用 `test_219_` 前缀的合成数据，禁止连接生产 MySQL/Redis。测试不修改业务代码。

## 环境要求

必须配置：

- `ISOLATED_MYSQL_HOST`、`ISOLATED_MYSQL_USER`、`ISOLATED_MYSQL_DATABASE`
- `ISOLATED_REDIS_HOST`
- `ISOLATED_CLEANUP_SQL`、`ISOLATED_SEED_USER_SQL`、`ISOLATED_SEED_ORDER_SQL`
- 各测试文件引用的接口 URL、请求体、查询 SQL 和 patch target

所有 SQL 配置必须包含 `test_219_`，清理 SQL 通过参数接收 `test_219_` 前缀；fixture 会拒绝未包含该前缀的清理或 seed SQL。不得使用 SQLite、内存 Mock、`FLUSHALL` 或清空整表替代隔离环境。

## 执行

```powershell
uv run pytest tests/isolation/ -v 2>&1 | Tee-Object -FilePath "$env:TEMP\219-isolation-test.log"; exit $LASTEXITCODE
```

环境未就绪时测试会报错，不会自动降级为替代数据库或内存实现。

## PR #219 对应关系

| 文件 | 验收项 |
|---|---|
| `test_captcha_concurrency.py` | U1 验证码并发核销 |
| `test_jwt_revocation.py` | U2 JWT 撤销 |
| `test_refund_external_success_local_fail.py` | U3/U4 退款外部成功、本地失败与恢复 |
| `test_order_state_race.py` | U5 订单状态竞争 |
| `test_mysql_redis_dual_connection.py` | U6 双连接故障与 fail-closed |
