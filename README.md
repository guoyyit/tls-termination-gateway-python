# TLS Termination Gateway (Python)

在不改变原有明文监听的前提下，为服务补充**本地 TLS 终结**与**虚拟主机证书管理**：
按 SNI 域名选择证书、证书/私钥热更新、按主机校验客户端证书、有界会话缓存与
密钥轮换失效、启动磁盘恢复（坏证书不拖垮整体）、并发上限/慢客户端超时/优雅停止，
以及全程脱敏且可关联的审计。

## 快速开始

```bash
uv sync
cp gateway.example.toml gateway.toml   # 填入真实证书路径
uv run python main.py gateway.toml     # 启动加密监听（明文 FastAPI 服务保留）
```

- 明文示例应用：`main.py`（`FastAPI`，`GET /`）。
- 加密监听配置：见 `gateway.example.toml`。
- 核心实现：`tls_gateway/`
  - `cert_store.py`：证书选择、原子热更新、SNI 切换、客户端校验姿态
  - `session_cache.py`：有界 LRU 会话注册表 + epoch 轮换失效
  - `gateway.py`：监听器、并发上限、超时、客户端证书门禁、优雅停止
  - `audit.py`：结构化、白名单脱敏、可关联的审计
  - `config.py` / `server.py`：TOML 配置与装配入口

## 测试

```bash
uv run pytest
```

## 文档

完整语义（**证书选择顺序**、**会话缓存与密钥轮换**、客户端证书校验、热更新一致性、
优雅停止、审计字段）见 [`docs/configuration.md`](docs/configuration.md)。
