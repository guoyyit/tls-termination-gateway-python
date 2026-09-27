# TLS Termination Gateway (Python)

在保留现有 FastAPI 明文监听（uvicorn，默认 `127.0.0.1:8000`）的同时，新增一个
TLS 终结网关（默认 `127.0.0.1:8443`）：按 SNI 选择虚拟主机证书终结 TLS，
校验客户端证书，然后将解密后的流量代理到后端明文监听。

```
client --TLS--> gateway (gateway/) --plain HTTP--> uvicorn/FastAPI (main.py)
```

## 运行

```bash
uv sync
GATEWAY_CERT_DIR=certs GATEWAY_DEFAULT_HOST=localhost uv run python main.py
```

关键环境变量（均有默认值）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `GATEWAY_CERT_DIR` | `certs` | 证书目录，文件名为 `<host>.crt.pem` / `<host>.key.pem` |
| `GATEWAY_DEFAULT_HOST` | `localhost` | 默认证书对应的主机名 |
| `GATEWAY_VHOSTS` | 空 | 逗号分隔的额外虚拟主机名 |
| `GATEWAY_PORT` / `GATEWAY_BACKEND_PORT` | `8443` / `8000` | 加密入口 / 明文后端端口 |
| `GATEWAY_CLIENT_AUTH` | `none` | `none`/`optional`/`required`（应用于所有虚拟主机的示例配置） |
| `GATEWAY_CLIENT_CA` | 空 | 校验客户端证书的 CA 文件 |
| `GATEWAY_MAX_CONNECTIONS` | `1000` | 并发连接上限 |
| `GATEWAY_SLOW_CLIENT_TIMEOUT` | `10` | 慢客户端超时（秒），作用于 TLS 握手与读 |
| `GATEWAY_SHUTDOWN_GRACE` | `5` | 优雅停止排空期（秒） |
| `GATEWAY_SESSION_CACHE_SIZE` / `GATEWAY_SESSION_TTL` | `1024` / `300` | 会话缓存上限与 TTL |
| `GATEWAY_SESSION_ROTATION` | `3600` | 会话密钥轮换间隔（秒） |
| `GATEWAY_AUDIT_LOG` | 空 | 审计 JSONL 输出文件（不设置则仅内存） |

程序化配置见 `gateway/config.py`（`GatewayConfig` / `VHostConfig`，支持按虚拟主机
独立设置 `client_auth` 与 `client_ca_path`）。

## 证书选择顺序

每个 TLS 握手按以下顺序选择证书（`gateway/vhosts.py`）：

1. **SNI 精确匹配**：客户端 SNI 规范化（小写、去尾部点）后与已加载的虚拟主机
   逐一精确匹配，命中则切换到该主机的 `SSLContext`；
2. **默认证书**：SNI 未匹配、未提供 SNI、或查找过程出现异常时，使用
   `default_vhost` 当前的证书；
3. **降级启动**：若默认证书本身不可用（缺失/损坏/过期），监听器以任一可用
   虚拟主机的证书引导，保证可用域名继续对外服务；一个可用证书都没有时
   `start()` 抛出可诊断的 `RuntimeError`。

每次选择（含回退默认）都会写入审计（`cert_selected` / `cert_default_used`，
含证书版本号与 SHA-256 指纹，便于关联）。

## 证书热更新

`VHostRegistry.reload(config)`（或 `CertStore.reload`）执行热更新：

- 新证书/私钥先**完整加载并校验**（可读性、PEM 格式、证书与私钥匹配、有效期），
  全部通过后才以**写时复制**方式原子换入；任何一步失败都抛出 `CertLoadError`，
  旧版本继续服役；
- 已建立的连接继续使用握手时的旧版本，不受更新影响；
- 新连接只能看到更新后的完整版本——不存在证书与私钥不匹配的中间状态；
- 每次成功重载记录 `cert_reloaded` 审计（版本号单调递增）。

## 客户端证书校验

按虚拟主机配置 `client_auth`（`none`/`optional`/`required`）。受 CPython 限制
（`SSL_set_SSL_CTX` 后握手初始的 verify mode 不变），校验分两层：

1. **TLS 层**：引导上下文以 `CERT_OPTIONAL` 请求客户端证书，并用所有虚拟主机
   客户端 CA 的**并集**验证。链到未知 CA 的证书在此被拒绝，连接中止并记录
  `client_cert_invalid`（含 OpenSSL verify 原因，如
   `unable to get local issuer certificate`）；
2. **应用层**：按 SNI 选中的虚拟主机再次用其**自己的** `client_ca_path`
   验证证书链（`gateway/clientauth.py`），并区分失败原因返回：

   | 场景 | 响应 | 审计 |
   | --- | --- | --- |
   | `required` 但未提供证书 | `403` + `X-Gateway-Error: missing_client_certificate` | `client_cert_missing` |
   | 证书不被该虚拟主机信任 | `403` + `X-Gateway-Error: untrusted_client_certificate` | `client_cert_invalid` |
   | 校验通过 | 正常代理 | `client_cert_ok` |

未通过校验的请求**不会**进入后端代理。注意：客户端 CA 集合在启动时确定，
修改 `client_ca_path` 需重启生效（服务端证书热更新不受此限）。

## 会话缓存与轮换语义

`gateway/session_cache.py` 的 `BoundedSessionCache` 是网关级会话票据缓存：

- **有界**：最多 `max_size` 条，满时驱逐最久未用（LRU）条目，长时间运行
  不会无限增长；
- **TTL**：每条自写入起 `ttl` 秒有效，过期条目永不返回并惰性清除；
- **轮换失效**：每条记录都标记签发它的会话密钥代数（generation）。
  `rotate_keys()` 递增代数并**清空所有旧代数条目**——轮换后的旧票据永不被
  复用。网关按 `session_key_rotation_interval` 周期轮换并记录
  `session_keys_rotated` 审计。

连接复用（HTTP keep-alive）由字节级代理天然支持。

**CPython 限制说明**：OpenSSL 的会话票据密钥按 `SSLContext` 生成，CPython 未
暴露跨上下文共享票据密钥的 API。SNI 切换到非默认虚拟主机时，该主机签发的
票据在下次连接（首先到达默认主机的上下文）无法解密，会自动回退为完整握手；
默认虚拟主机的会话恢复（TLS 1.3 ticket）可正常工作（见
`tests/test_session_cache.py::test_tls_session_resumption`）。默认主机证书
热更新后旧票据同样失效（新上下文持有新密钥），符合轮换安全失效语义。

## 启动时证书恢复

`build_gateway()` 从磁盘逐个加载虚拟主机证书：缺失、损坏、过期、证书与私钥
不匹配的证书仅禁用其对应主机名，记录 `cert_load_failed`（含具体原因），
不影响其他虚拟主机；全部不可用时 `start()` 抛出 `RuntimeError`。

## 并发上限、慢客户端与优雅停止

- **并发上限**：达到 `max_connections` 时新连接在 TLS 握手前即被拒绝并记录
  `connection_rejected`；
- **慢客户端**：TLS 握手与客户端读超过 `slow_client_timeout` 即断开并记录
  `slow_client_timeout`；
- **优雅停止**（`stop()`）：先关闭监听套接字拒绝新连接，等待在途连接排空
  （最长 `shutdown_grace_period` 秒），超时后 `abort()` 强制关闭未完成连接。

## 审计

`gateway/audit.py` 输出结构化事件：每条含单调递增 `seq`、UTC 时间戳、稳定
事件类型、主机名与失败原因，可写入 JSONL 文件。事件**绝不**包含私钥材料或
请求体等敏感内容（仅有证书指纹、有效期、对端证书主题等公开信息）。

## 测试

```bash
uv run pytest
```

覆盖：未知域名回退、并发热更新、客户端证书失败（缺失/不受信任 CA/跨主机
信任）、会话恢复与缓存轮换、证书损坏/过期启动恢复、并发上限、慢客户端
超时与优雅停止（排空/拒绝新连接/超时强关）。
