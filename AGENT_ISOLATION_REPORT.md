# PR #219 隔离环境并发与故障测试报告

日期：2026-10-24
分支：`test/219-isolation-concurrency`

## 执行命令

```powershell
uv run pytest tests/isolation/ -v 2>&1 | Tee-Object -FilePath "$env:TEMP\219-isolation-test.log"; exit $LASTEXITCODE
```

## 结果摘要

- 收集测试：5 项。
- 通过：0 项。
- 失败：0 项。
- 阻塞：5 项。
- 未使用 SQLite、内存 Mock 或其他替代隔离环境。
- 阻塞证据：fixture 初始化时缺少 `ISOLATED_MYSQL_HOST`；另一测试的初始化同时报告缺少 `ISOLATED_REDIS_HOST`。
- 测试进程退出码：1。

| 任务编号 | 测试文件 | 实际命令 | 结果 | 失败原因 / 证据 | 未验证边界 |
|---|---|---|---|---|---|
| U1 验证码并发 | `tests/isolation/test_captcha_concurrency.py` | `uv run pytest tests/isolation/ -v ...` | 阻塞 | fixture 报错：缺少 `ISOLATED_MYSQL_HOST`；未建立数据库连接，未执行 30 并发核销 | 短信真实发送、验证码供应商受理与投递：待隔离环境验证 |
| U2 JWT 撤销 | `tests/isolation/test_jwt_revocation.py` | `uv run pytest tests/isolation/ -v ...` | 阻塞 | fixture 报错：缺少 `ISOLATED_REDIS_HOST`；未登录、未撤销 Token A、未检查 deny-list | 多实例 JWT 撤销传播、真实 Redis：待隔离环境验证 |
| U3/U4 退款失败 | `tests/isolation/test_refund_external_success_local_fail.py` | `uv run pytest tests/isolation/ -v ...` | 阻塞 | fixture 报错：缺少 `ISOLATED_MYSQL_HOST`；未执行外部成功/本地 commit 失败场景 | 微信退款外部受理、查询恢复、回调对账：待隔离环境验证 |
| U5 订单竞争 | `tests/isolation/test_order_state_race.py` | `uv run pytest tests/isolation/ -v ...` | 阻塞 | fixture 报错：缺少 `ISOLATED_MYSQL_HOST`；未执行支付回调/取消并发 | 真实 MySQL 行锁、库存/余额终态与订单状态竞态：待隔离环境验证 |
| U6 双连接故障 | `tests/isolation/test_mysql_redis_dual_connection.py` | `uv run pytest tests/isolation/ -v ...` | 阻塞 | fixture 报错：缺少 `ISOLATED_MYSQL_HOST`；未执行故障注入或 fail-closed 接口断言 | MySQL/Redis 双连接断开、真实安全接口脏写检查：待隔离环境验证 |

## 环境结论

隔离环境未就绪。由于必需环境变量不存在，本次没有连接任何数据库或 Redis，也没有调用业务接口；测试代码已按要求保留为真实隔离环境测试，待配置隔离 MySQL、Redis、合成数据 seed SQL、清理 SQL 及接口地址后重新执行。

本次未部署生产、未进行生产故障注入、未发送真实短信、未发生支付或退款。
