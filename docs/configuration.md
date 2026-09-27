# TLS Termination Gateway

本地 TLS 终结网关，在保留原有明文监听（`main.py` 中的 FastAPI/uvicorn）的同时，
新增一个加密监听器，并按访问域名（TLS SNI）选择虚拟主机证书。

- 语言/运行时：Python 3.14，仅使用标准库 `ssl`/`asyncio` + `cryptography`。
- 加密监听：`server.tls_host` / `server.tls_port`（默认 `127.0.0.1:8443`）。
- 明文监听：原有服务保持不变（`plaintext_host` / `plaintext_port`）。

## 1. 证书选择顺序

每个连接在 TLS 握手期间根据 SNI 选择证书，顺序固定为：

1. **SNI 精确匹配**已配置且健康的虚拟主机 → 返回该主机的证书。
2. **未提供 SNI**（`server_name` 为空）→ 返回默认证书。
3. **SNI 未知**（没有任何虚拟主机匹配）→ 返回默认证书。
4. **匹配到的主机当前不可用**（启动/热更新时证书缺失、损坏、过期或密钥不匹配）
   → 回退到默认证书；该主机的失败原因被记录并在启动诊断中返回，不影响其它主机。

> 实现上只有一个“前置（front）”`SSLContext` 交给监听器，其自带默认证书链；
> SNI 回调把该连接切换到目标虚拟主机的**不可变** entry context。选择结果会写入
> 审计事件 `cert_selected`（精确匹配）或 `cert_default_used`
> （`reason=sni_unmatched` / `sni_absent`）。

## 2. 证书与私钥热更新

- 加载时先做完整校验：解析证书、校验证书/私钥匹配（比较公钥）、校验有效期，
  然后 `load_cert_chain` 原子装载，最后才发布新的不可变快照。
- **新连接只能看到更新后的完整版本**：发布要么使用全新 entry（证书与私钥一致），
  要么完全不变，不存在证书与私钥不匹配的中间状态。
- **更新不中断已建立连接**：已完成握手的连接继续使用其握手时的旧 context；
  SNI 回调是“逐连接切换”，旧 context 不会被原地修改。
- 单个主机热更新失败（如文件缺失）会抛出异常并保留旧 entry 继续服务。
- 编程接口：`CertificateStore.reload_vhost(VHostConfig)`、
  `CertificateStore.reload_default(cert, key)`。

## 3. 客户端证书校验（按虚拟主机）

- 仅当虚拟主机 `require_client_cert = true` 时强制客户端证书，并用 `client_ca`
  指定信任的客户端 CA。
- 所有服务端 context 以 `CERT_OPTIONAL` + 客户端 CA **并集**运行：
  - 客户端**提供**证书时，OpenSSL 必须在握手期校验通过；证书过期、签发者不受信任、
    自签名等都会**在握手期失败**并发出对应的 TLS alert，请求**不会**进入后续处理。
  - 客户端**不提供**证书时握手可以完成；随后网关对该主机检查对端证书，为空则以
    稳定原因 `client_cert_absent` 拒绝并关闭连接（同样不会进入处理）。
- 之所以采用“前置 CERT_OPTIONAL + 握手后按主机强制”，是因为 SNI 切换 context 时
  OpenSSL 的 `SSL_set_SSL_CTX` 不会把新 context 的 `verify_mode` 应用到已创建的
  连接（这也是 nginx 在 SNI 回调里额外 `SSL_set_verify` 的原因），而 Python 标准库
  不暴露连接级 verify 设置。统一在前置与各 entry context 上设置相同校验姿态，保证
  无论是否发生 context 切换行为都一致。
- 失败原因被归类为**稳定、可区分**的机器码（审计与告警共用）：
  `client_cert_absent`、`client_cert_expired`、`client_cert_not_yet_valid`、
  `client_cert_self_signed`、`client_cert_self_signed_chain`、
  `client_cert_unknown_ca`、`client_cert_revoked`、`client_cert_bad_signature`、
  `client_cert_invalid_purpose`、`client_cert_verify_failed`、
  `client_cert_failed`（兜底）。

## 4. 连接复用与有界会话缓存

- 支持同一 TLS 连接上的顺序/流水线请求（HTTP keep-alive）。
- 网关维护一个**有界**会话注册表 `SessionCache`（容量 `server.max_sessions`），
  采用 LRU 淘汰；长期运行不会无限增长。
- 会话策略为**有状态会话**：服务端 context 关闭无状态票据
  （`OP_NO_TICKET`），协商出的会话带 session id 并进入该 context 的服务端缓存，
  从而可被有界注册表观测与计数。
- 会话按 **epoch（纪元）** 标记：
  - `rotate_session_keys()` 先把 epoch +1 并清空注册表（旧会话立即不可恢复），
    再基于磁盘证书**重建全部 SSLContext**；新 context 拥有全新的服务端会话缓存，
    旧 session id / 票据无法再恢复。
  - 任何来自旧 epoch 的条目都不会被接受（`put` 直接丢弃、`get` 视为失效），
    因此长时间运行不会复用失效会话。

> 说明：TLS 1.3 的会话恢复本质依赖无状态票据；本网关为获得“随密钥轮换可靠失效、
> 且可被有界管理”的语义，统一禁用无状态票据，使用有状态会话缓存。最低 TLS 版本为
> TLS 1.2。

## 5. 启动时从磁盘恢复证书状态

- 启动（`build_gateway` / `CertificateStore.load_initial`）逐个主机加载，任何一个
  证书**缺失 / 损坏 / 过期 / 密钥不匹配**都只会：
  - 在返回的 `{主机名: 诊断原因}` 映射中记录；
  - 写入 `cert_load_failed` 审计事件；
  - **不会**导致整体不可用——默认证书与其它健康主机继续服务。
- 默认证书自身不可用时，TLS 监听器不启动（没有可出示的证书），但诊断信息清晰给出。

## 6. 并发上限、慢客户端超时与优雅停止

- `max_connections`：接受连接时**立即**判定容量；已满则不进行 TLS 握手，直接审计
  `connection_rejected/reason=max_connections` 并关闭（不无限排队）。
- `handshake_timeout`：限制 TLS 握手时长（慢客户端保护）。
- `read_timeout`：限制每次请求读取的空闲时间，超时审计并关闭。
- `shutdown()` 优雅停止顺序：
  1. 关闭监听 socket，并将限流器置为 draining——**拒绝所有新连接**
     （审计 `reason=draining`）；
  2. 在 `shutdown_timeout` 内**排空在途请求**；
  3. 超时仍未结束的连接被**强制关闭**：取消在途处理任务并关闭传输层。
- 注意：不显式 `await Server.wait_closed()`，因为现代 asyncio 的该方法会等待所有
  客户端 socket 关闭；排空/强关由网关自行控制。

## 7. 审计

- 结构化 JSON（每行一条），字段：`ts`、`event`、`correlation_id`、`vhost`、
  可选 `reason`、可选 `extra`。
- **稳定可关联**：一次连接的 SNI 选择与客户端证书结果共享同一个
  `correlation_id`，便于串联排查。
- 事件：`cert_loaded`、`cert_load_failed`、`cert_selected`、`cert_default_used`、
  `client_cert_required`、`client_cert_failed`、`client_cert_ok`、
  `session_rotated`、`connection_rejected`、`gateway_stopped`。
- **不泄露敏感内容**：`extra` 采用字段白名单（指纹、有效期、序列号、对端地址、
  客户端证书 CN 等），私钥、PEM、请求头/请求体等一律不会写入审计。

## 8. 运行

```bash
uv sync
# 启动 TLS 网关（同时保留 main.py 的明文 FastAPI 服务）
uv run python main.py gateway.example.toml
```

## 9. 测试

```bash
uv run pytest
```

覆盖：未知域名回退默认证书、缺省 SNI、并发热更新（在途连接持续可用）、
客户端证书缺失/不受信失败及可区分原因、TLS 1.2 会话恢复与轮换后失效、
连接复用（流水线）、证书损坏/过期/密钥不匹配隔离、并发上限、
优雅排空与超时强关、审计脱敏与关联。
