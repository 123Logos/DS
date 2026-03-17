# 电商小程序后端api

## 启动前准备

```bash
# 复制示例文件为 .env
cp .env.example .env

# 编辑 .env
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=password
MYSQL_DATABASE=database

UVICORN_PORT=8000

WECHAT_APP_ID=WECHAT_APP_ID
WECHAT_APP_SECRET=WECHAT_APP_SECRET
```
---

## 运行 / 启动说明

- **Linux（systemd）**

	如果使用 systemd 管理服务，可按以下步骤操作：

	- 将服务单元文件 `ds.service` 放到 `/etc/systemd/system/`（如尚未部署服务单元）。
	- 重新加载 systemd：

		```bash
		sudo systemctl daemon-reload
		```

	- 启动服务：

		```bash
		sudo systemctl start ds.service
		```

	- 重启服务（在更新后常用）：

		```bash
		sudo systemctl restart ds.service
		```

	- 查看服务状态：

		```bash
		sudo systemctl status ds.service
		```

	- 查看实时日志：

		```bash
		sudo journalctl -u ds.service -f
		```

- **Windows**

	Windows 系统可使用 [uv](https://docs.astral.sh/uv/getting-started/installation/)（按项目约定的工具）运行与调试：

	- 安装 [uv](https://docs.astral.sh/uv/getting-started/installation/)（根据你使用的包管理器或安装方式）。
	- 初始化虚拟环境：

		```powershell
		uv venv
		```

	- 根据 `pyproject.toml`（或项目的 .toml 配置）同步/安装依赖：

		```powershell
		uv sync
		```

	- 以调试/运行模式启动项目：

		```powershell
		uv run main.py
		```

保留说明

- 启动后，访问 `http://127.0.0.1:<port>/docs` 查看 API 文档
- 或访问 `http://127.0.0.1:<port>/redoc` 查看 ReDoc 文档

---

## 离线收款二维码支持

1. 项目根目录下新增 `offline/` 文件夹，会被应用挂载为静态目录。
   - 在该目录放置微信小程序域名验证文件（比如 `senIScNn8d.txt`），
     即可通过 `https://<your-domain>/offline/senIScNn8d.txt` 访问。
   - 普通扫码（非小程序码）也可以指向此路径，例如作为服务器域名验证。
   - 请在 `.env` 中设置 `HOST` 为你的公开域名（不带尾部斜杠），
     以便接口返回的 `url` 正常带上域名前缀；例如：
     `HOST=https://hzai.tech`

2. 新增接口 `POST /api/offline/permanent-qrcode`，返回的数据中
   除了微信小程序码 (`qrcode`) 外还带几个辅助字段：
   * `url` – 用于生成普通二维码的 Web 链接，例如：
     `https://<your-domain>/offline/?id=123`。
     扫码后会加载静态页面并跳转到小程序。
   * `universal_link` – 旧的链接保留，格式
     `https://<your-domain>/offline/permanentPay?merchant_id=123`。
   * `plain_qrcode` – 同 `url` 对应的 PNG 图像的 Base64 数据
     （`data:image/png;base64,...`），前端可以直接展示。

   如果 `HOST` 未配置，这些字段会返回相对路径
   `/offline/?id=123` 或 `/offline/permanentPay?....`，前端需补全域名。
   前端在生成二维码时仍应对路径做 URL 编码（当前仅包含数字，安全）。

3. 为了配合上述 URL，我们增加了一个 HTTP 路由
   `GET /offline/permanentPay`，会根据 `merchant_id` 参数
   重定向到对应小程序页面（使用微信 universal link）。
   扫描普通二维码时会先访问
   `https://<your-domain>/offline/?id=...`，此时静态目录下的
   `index.html` 会读取 `id` 并再跳转到 `/offline/permanentPay`。
   这样微信/浏览器均能正确进入小程序并传递商家 ID。

---

> [!NOTE]
>
> `<port>` 为环境变量 `UVICORN_PORT`，若未设置则默认使用 `8000`
---

## AI 辅助免责声明

本项目在 AI/大型语言模型（包括 GitHub Copilot、ChatGPT 及相关工具）的协助下开发，受到了偶尔知道自己在做什么的人类的监督。

---