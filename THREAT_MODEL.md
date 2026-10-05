# secproto 威胁建模报告 (Threat Model)

> 版本: 1.0 | 范围: secproto 自定义 TCP 安全协议全栈
> 方法: STRIDE (Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege)
> 假设: 攻击者控制网络链路，可发送任意字节流；不假设攻击者已攻破信任的身份密钥。

---

## 0. 系统边界

```
              ┌──────────────────────────────────────────┐
              │              secproto server             │
              │  ┌────────────┐  ┌───────────────────┐   │
  TCP ───────►│  │ connGate   │→ │ transport.Conn    │   │
  (unauth)    │  │ (IP 限速)  │  │ (握手 + AEAD)     │   │
              │  └────────────┘  └────────┬──────────┘   │
              │                           │ 明文 JSON     │
              │                    ┌──────▼──────┐       │
              │                    │  appapi     │       │
              │                    │ (worker池)  │       │
              │                    └─────────────┘       │
              │  ┌────────────┐                          │
              │  │ admin HTTP │ (loopback + token)       │
              │  └────────────┘                          │
              └──────────────────────────────────────────┘
```

六大入口:
1. **未认证握手面** — TCP accept → X25519/Ed25519 握手完成前
2. **帧解析面** — 已认证/加密通道上的帧头解析与解密
3. **appapi** — 解密后的 JSON 请求处理层
4. **admin** — localhost 管理 HTTP 接口
5. **身份密钥面** — Ed25519 身份密钥的存储与使用
6. **侧信道运维面** — 日志、审计、时序、度量

---

## 1. 未认证握手面 (Unauthenticated Handshake Surface)

**风险等级: 高**

### S — 身份伪造 (Spoofing)
- **攻击者能力**: 拥有任意 Ed25519 密钥对，可发起握手
- **利用面**: 无信任锚时接受任意身份；签名可伪造
- **加固前缺口**: 无身份验证，任意客户端可完成握手
- **加固措施**: TOFU 信任存储 + 公钥固定 (pin)；ServerProof 用 Ed25519 签名绑定 DH 共享密钥；客户端验证服务端身份
- **对应测试**: T5 (MITM rejection), T13 (CRL + multi-pin)
- **残余风险**: TOFU 首次连接仍需带外验证指纹；长期运行后信任存储膨胀（未实现自动清理）

### D — 拒绝服务 (Denial of Service) — 半开连接
- **攻击者能力**: 发起 TCP connect 但不发送 ClientHello
- **利用面**: 每个 accept 占用一个 goroutine + fd，直到握手超时
- **加固前缺口**: 无握手超时，goroutine 可无限堆积
- **加固措施**: `HandshakeTimeout = 10s` 强制断开；`connGate` 每IP连接上限 (32) + 令牌桶限速 (16/sec)
- **对应测试**: T17 (handshake timeout), TK (half-open flood), `TestConnGateMaxConns`, `TestConnGateRateLimit`
- **残余风险**: 分布式多IP攻击可绕过单IP限速；10s 超时内仍占用 fd（需配合 OS 层 SYN cookie / backlog）

### T — 篡改 (Tampering) — 握手消息篡改
- **攻击者能力**: 修改握手帧字段
- **利用面**: 降级协商弱密码套件、篡改时间戳
- **加固前缺口**: 握手消息无完整性保护
- **加固措施**: ServerProof 签名覆盖 ClientHello/ServerHello 摘要；最低版本检查 (`MinSupportedVersion`)
- **对应测试**: T5 (signature rejection)
- **残余风险**: 无

---

## 2. 帧解析面 (Frame Parsing Surface)

**风险等级: 高**

### D — 拒绝服务 — 超大 Length 字段
- **攻击者能力**: 发送合法帧头但 Length 声明 >64KiB
- **利用面**: 接收方按 Length 预分配内存 → OOM
- **加固前缺口**: MaxFramePayload = 16MiB，可被用于内存放大
- **加固措施**: `MaxFramePayload = 64KiB`；`ParseHeader` 在分配前检查 length，超限即 `ErrInvalidFrame` + 断开连接；`OversizedFrame` 计数
- **对应测试**: TA (oversized length), T18 (oversized frame), `TestFrameOversizedPayload`
- **残余风险**: 64KiB 以内仍可发送合法帧（正常业务需要）；无法防御 64KiB 级别的慢速泛洪（需配合 appapi worker 池）

### T — 篡改 (Tampering) — 密文/AAD 篡改
- **攻击者能力**: 修改密文或帧头字段
- **利用面**: 篡改后 AEAD 认证失败，连接断开
- **加固前缺口**: 已正确实现（AEAD tag 覆盖 payload + AAD）
- **加固措施**: AES-256-GCM / ChaCha20-Poly1305；AAD 包含 Magic/Version/MsgType/KeyID/Seq/Timestamp + session_id
- **对应测试**: T2 (ciphertext tampering)
- **残余风险**: 无

### I — 信息泄露 (Information Disclosure) — 重放/过期帧
- **攻击者能力**: 截获并重放合法帧
- **利用面**: 重放攻击导致状态重复；过期帧绕过时间窗口
- **加固前缺口**: 已实现 seq 窗口 + 时间戳窗口
- **加固措施**: `ReplayWindowSize=1024`；`DataTimeWindow=60s`；时间戳纳入 AAD
- **对应测试**: T3 (replay), T4 (expired)
- **残余风险**: 窗口内的重放仍可成功（seq 未超窗口）；时钟偏移超过 `MaxClockOffset` 会被拒绝（可用性风险）

### D — 拒绝服务 — 畸形帧
- **攻击者能力**: 发送错误 magic / 版本 / 长度的帧
- **利用面**: 解析逻辑崩溃或资源消耗
- **加固措施**: `ParseHeader` 严格校验 magic、version、length；失败即断开；`InvalidFrame` 计数
- **对应测试**: `TestFrameBadMagic`
- **残余风险**: 无

---

## 3. appapi 层

**风险等级: 高**

### D — 拒绝服务 — 超大 payload
- **攻击者能力**: 发送 >32KiB 的解密后 JSON
- **利用面**: JSON 解析消耗 CPU/内存
- **加固前缺口**: 无 payload 大小限制
- **加固措施**: `MaxAppPayload = 32KiB`，在 `process` 中解析前检查；`AppPayloadReject` 计数
- **对应测试**: TC (oversized payload), T18, `TestPayloadTooLarge`
- **残余风险**: 32KiB 以内的合法 JSON 仍可处理（业务需要）

### D — 拒绝服务 — 深嵌套 JSON
- **攻击者能力**: 发送深度 >32 的嵌套 JSON
- **利用面**: 递归解析栈溢出 / CPU 耗尽
- **加固前缺口**: `json.Unmarshal` 无深度限制
- **加固措施**: `checkJSONDepth` 使用 `json.Decoder.Token()` 流式检查，`MaxJSONDepth=32`；超限返回 `bad_request`
- **对应测试**: TB (deep JSON), T18, `TestJSONDepthLimit`
- **残余风险**: 深度 ≤32 但宽度极大的 JSON 仍可消耗内存（`MaxJSONArrayLen=4096` 仅限制顶层数组）

### D — 拒绝服务 — req_id 滥用
- **攻击者能力**: 发送超长或含非法字符的 req_id
- **利用面**: dedup cache key 膨胀 / 日志注入
- **加固前缺口**: 无 req_id 校验
- **加固措施**: `validReqID` 限制长度 ≤128，字符集 `[A-Za-z0-9._-]`；`AppReqIDReject` 计数
- **对应测试**: TD (req_id validation), T19, `TestReqIDValidation`
- **残余风险**: 合法 req_id 仍可用于 dedup 缓存填充（`DefaultDedupSize=1024` 限制每连接缓存大小）

### D — 拒绝服务 — kv.set 无限写入
- **攻击者能力**: 发送大量 kv.set 请求
- **利用面**: 内存无限增长
- **加固前缺口**: 无存储容量限制
- **加固措施**: `boundedKV` LRU 缓存，`MaxKVEntries=1024`；key ≤256B, value ≤4096B
- **对应测试**: TE (kv capacity), T19, `TestKVCapacity`
- **残余风险**: 攻击者可频繁写入导致 LRU 抖动，但内存有界

### D — 拒绝服务 — worker 池耗尽
- **攻击者能力**: 并发发送大量慢请求
- **利用面**: 读循环阻塞，新请求排队
- **加固前缺口**: 每请求一个 goroutine，无并发限制
- **加固措施**: 有界 worker 池 (`DefaultMaxWorkers=64`)；`dispatch` 非阻塞获取 worker，满则立即返回 `too_many_requests`；`AppWorkerReject` 计数
- **对应测试**: TF (worker backpressure), T20, `TestWorkerBackpressure`, `TestWorkerBounds`
- **残余风险**: 64 个慢 handler 仍可占用所有 worker（`HardHandlerTimeoutMs=5s` 硬超时兜底）

### D — 拒绝服务 — handler 死循环 / panic
- **攻击者能力**: 触发 handler 中的 panic 或无限循环
- **利用面**: goroutine 泄漏 / 进程崩溃
- **加固前缺口**: handler 无超时，panic 未 recover
- **加固措施**: `HardHandlerTimeoutMs=5s` 硬超时；`recover()` 捕获 panic，返回 `internal_error`；`AppPanicRecovered` 计数
- **对应测试**: TG (handler timeout + panic), `TestPanicRecovery`, `TestTimeout`
- **残余风险**: panic recover 后 goroutine 退出，但已分配的资源（如打开的文件）需 handler 自行 defer 清理

### I — 信息泄露 — 错误信息
- **攻击者能力**: 观察错误响应
- **利用面**: 通过错误信息推断内部状态
- **加固前缺口**: 错误消息泄露具体校验失败原因
- **加固措施**: `errResp` 按 code 统一返回模糊消息（`bad_request`→"request rejected"）；`sendResp` 对非 OK 响应施加 2ms 恒定延迟
- **对应测试**: TG (no stack leak), `TestBadJSON`
- **残余风险**: `code` 字段仍暴露粗粒度分类（设计必要）；2ms 延迟在高并发下可能被网络抖动掩盖

---

## 4. admin 层

**风险等级: 中**

### S — 身份伪造 — token 猜测
- **攻击者能力**: 暴力破解 admin token
- **利用面**: 无限次尝试 token
- **加固前缺口**: 无登录限速
- **加固措施**: 每IP 5 次失败 → 锁定 30s；`subtle.ConstantTimeCompare` 恒定时间比较；`AdminAuthFail`/`AdminRateLimited` 计数
- **对应测试**: TH (auth lockout), T21, `TestAuthLockout`
- **残余风险**: 分布式多IP攻击可绕过单IP锁定；token 长度由运维决定（建议 ≥32 字节随机）

### T — 篡改 — CSRF
- **攻击者能力**: 诱导已认证管理员访问恶意页面
- **利用面**: 浏览器自动携带 cookie 发起跨域请求
- **加固前缺口**: 写操作无 CSRF 防护
- **加固措施**: PUT/POST/DELETE 必须携带 `X-Admin-Action` 自定义 header（浏览器跨域无法设置）；缺失返回 403
- **对应测试**: T21 (CSRF), `TestCSRFHeaderRequired`
- **残余风险**: admin 使用 Bearer token 而非 cookie，CSRF 风险本就较低；自定义 header 是纵深防御

### T — 篡改 — 配置越界
- **攻击者能力**: 提交非法配置值（padding=0, window=0, jitter>interval）
- **利用面**: 禁用填充 / 禁用时间窗口 / 负数 sleep
- **加固前缺口**: 配置无边界校验
- **加固措施**: `RuntimeConfig.Apply` 逐字段校验：padding∈[1,1024], window∈[1s,1h], jitter≤interval；失败回滚（无部分写入）；`AdminConfigReject` 计数
- **对应测试**: TI (config bounds), T21
- **残余风险**: 合法范围内的极端值（如 window=1s）可能影响可用性（运维决策）

### I — 信息泄露 — 连接信息
- **攻击者能力**: 获取 admin 访问权后查看连接列表
- **利用面**: 暴露 peer 公钥 / 明文数据
- **加固措施**: `ConnInfo` 仅暴露 fingerprint（公钥哈希）、地址、字节数；不暴露公钥原文或任何 payload
- **对应测试**: T16 (admin stats)
- **残余风险**: 地址信息可用于网络侦察（可接受，admin 本就是可信接口）

### I — 信息泄露 — UI XSS
- **攻击者能力**: 控制 peer_fingerprint 或 remote_addr 字段（通过连接注入脚本标签）
- **利用面**: admin UI 执行恶意脚本
- **加固前缺口**: 直接插入 HTML
- **加固措施**: UI 使用 `textContent` 插入所有动态值；`esc()` 函数 HTML 转义
- **对应测试**: TJ (UI XSS), T21
- **残余风险**: 无

### E — 权限提升 — 非 loopback 访问
- **攻击者能力**: 从网络访问 admin 端口
- **利用面**: admin 接口暴露到公网
- **加固前缺口**: 可能绑定 0.0.0.0
- **加固措施**: `ensureLoopback` 强制绑定地址为 loopback；非 loopback 返回错误
- **对应测试**: `TestLoopbackEnforcement`
- **残余风险**: 同一主机上的其他进程/容器可访问 admin（需配合 token 认证）

### I — 信息泄露 — 错误信息 + 时序
- **攻击者能力**: 观察 admin 错误响应的内容和耗时
- **利用面**: 区分"token 错误"与"已锁定"；区分不同配置校验失败
- **加固措施**: 所有错误路径施加 5ms 恒定延迟 (`failDelay`)；配置错误返回统一 "request rejected"
- **对应测试**: TH, TI
- **残余风险**: 锁定返回 429 而非 401，仍可区分（设计选择，用于阻止暴力破解）

---

## 5. 身份密钥面 (Identity / Key Surface)

**风险等级: 中**

### I — 信息泄露 — 密钥存储
- **攻击者能力**: 读取密钥文件
- **利用面**: 获取 Ed25519 种子，伪造身份
- **加固前缺口**: 密钥可明文存储
- **加固措施**: `EncryptSeed` 使用 scrypt + AES-256-GCM 加密种子；空口令被拒绝
- **对应测试**: T11 (passphrase key)
- **残余风险**: 口令强度由用户决定；内存中的密钥在进程运行期间无法保护（OS 层责任）

### S — 身份伪造 — 密钥泄露
- **攻击者能力**: 获取身份密钥
- **利用面**: 完全伪装合法身份
- **加固措施**: CRL 吊销列表支持；多公钥固定
- **对应测试**: T13 (CRL + multi-pin)
- **残余风险**: 密钥泄露后到吊销生效之间存在窗口期；吊销列表无自动分发机制

### T — 篡改 — 密钥轮换
- **攻击者能力**: 触发 key_id 回绕
- **利用面**: (key, nonce) 重用导致 AEAD 安全失效
- **加固措施**: `MaxKeyID=250`，达到后必须全量重协商；`ErrRekeyOverflow`
- **对应测试**: T6 (nonce reuse after rekey)
- **残余风险**: 无

---

## 6. 侧信道运维面 (Side-Channel / Ops Surface)

**风险等级: 低**

### I — 信息泄露 — 日志
- **攻击者能力**: 读取服务日志
- **利用面**: 获取 payload / token / 密钥 / req_id
- **加固措施**:
  - `Redact()` 函数仅返回长度，不返回内容
  - `SensitiveLogger` 贯穿协议栈
  - 日志仅包含地址 + 通用错误 ("protocol error")
  - admin 审计日志仅记录 action + 字段名，不记录值
  - token 用 `subtle.ConstantTimeCompare` 比较，永不落日志
- **对应测试**: 代码审计（无自动化测试覆盖日志内容）
- **残余风险**: `server.go:104` 日志包含 `remoteAddr`（可接受，非敏感）；错误值为 `PublicError("protocol error")`（已模糊化）

### I — 信息泄露 — 时序侧信道
- **攻击者能力**: 测量响应时间
- **利用面**: 区分不同错误类型 / 推断 token 前缀
- **加固措施**:
  - 传输层: `fail()` 施加 `failureDelay` + `NewPublicError`
  - appapi: `sendResp` 对错误响应施加 2ms 延迟
  - admin: `failDelay()` 对所有错误施加 5ms 延迟
- **对应测试**: TG (no stack leak), TH
- **残余风险**: 网络抖动可能掩盖延迟；handler 执行时间差异仍可观测（`HardHandlerTimeoutMs` 限制上限）

### I — 信息泄露 — 流量分析
- **攻击者能力**: 观察密文长度和时序
- **利用面**: 推断业务行为
- **加固措施**:
  - `PaddingBlockSize=16` 填充隐藏明文长度
  - `DummyFrameInterval=10s` ± `DummyFrameJitter=3s` 发送 dummy 帧混淆时序
- **对应测试**: T10 (padding)
- **残余风险**: 填充块大小为 16，仍可泄露 ≤16 字节粒度的长度信息；dummy 帧间隔固定模式可被统计分析

### R — 否认 (Repudiation) — 操作审计
- **攻击者能力**: 管理员执行操作后否认
- **利用面**: 无法追溯配置变更 / 连接关闭
- **加固措施**: admin `audit()` 记录所有状态变更（config.update, connection.close），含时间戳和字段名
- **对应测试**: 代码审计
- **残余风险**: 审计日志写入 stderr，无持久化 / 防篡改保证（需配合 syslog / 外部日志系统）

---

## 7. 加固措施 → 测试编号映射表

| 加固措施 | 测试编号 |
|---------|---------|
| 64KiB 帧上限 + OversizedFrame 计数 | TA, T18, TestFrameOversizedPayload |
| 握手超时 (10s) | T17, TK |
| connGate 每IP上限 + 令牌桶 | TK, TestConnGateMaxConns, TestConnGateRateLimit |
| MaxAppPayload=32KiB | TC, T18, TestPayloadTooLarge |
| JSON 深度 ≤32 | TB, T18, TestJSONDepthLimit |
| req_id 校验 | TD, T19, TestReqIDValidation |
| worker 非阻塞背压 | TF, T20, TestWorkerBackpressure |
| handler 硬超时 + panic recover | TG, TestTimeout, TestPanicRecovery |
| boundedKV LRU | TE, T19, TestKVCapacity |
| admin 认证限速 + IP 锁定 | TH, T21, TestAuthLockout |
| admin CSRF (X-Admin-Action) | T21, TestCSRFHeaderRequired |
| admin 配置边界 (padding≥1 等) | TI, T21 |
| admin UI XSS (textContent) | TJ, T21 |
| 统一模糊错误 + 恒定延迟 (appapi) | TG |
| 统一模糊错误 + 恒定延迟 (admin) | TH, TI |
| AEAD 认证 + AAD | T2 |
| 重放保护 (seq 窗口) | T3 |
| 时间戳窗口 | T4 |
| 身份验证 (签名 + pin) | T5, T13 |
| 密钥轮换隔离 | T6 |
| PFS 重协商 | T9 |
| 填充 | T10 |
| 口令加密密钥 | T11 |

---

## 8. 残余风险汇总 (Residual Risks)

1. **分布式 DoS**: 单IP限速可被多IP分布式攻击绕过。需在网络层 (防火墙 / WAF / CDN) 补充防御。
2. **密钥泄露窗口期**: 身份密钥泄露后到 CRL 生效前，攻击者可伪装合法身份。建议缩短密钥轮换周期。
3. **日志持久化**: 审计日志仅写入 stderr，无防篡改保证。建议接入 syslog 或外部日志系统。
4. **时序侧信道残余**: 2-5ms 恒定延迟在高延迟网络下可能被掩盖；handler 执行时间差异仍可观测。
5. **JSON 宽度攻击**: 深度限制不防宽度攻击（如 4096 元素数组，每个元素嵌套 32 层）。建议对总 token 数或总解析时间设限。
6. **admin 同主机访问**: loopback 限制无法阻止同主机其他进程访问 admin，需配合 token 强度和主机隔离。
7. **Go 标准库漏洞**: 当前使用 go1.26.0，存在若干标准库漏洞（crypto/tls, net/http, crypto/x509），已在 go1.26.1+ 修复。建议升级到最新补丁版本。
8. **无传输层 TLS**: admin 接口为明文 HTTP（仅 loopback）。如跨主机使用 admin，必须套 SSH 隧道或反向代理 TLS。

---

## 9. 测试闭环状态

- Go 单元测试: **全部通过** (admin 7, appapi 12, crypto 9, protocol 4, server 3, transport 2)
- Python 黑盒测试: **32/32 通过** (T1-T21 + TA-TK)
- `go vet`: 通过
- `go mod verify`: all modules verified
- `govulncheck`: 仅标准库漏洞（go1.26.0，需升级到 1.26.1+），无第三方依赖高危漏洞
