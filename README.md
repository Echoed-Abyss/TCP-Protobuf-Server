# secproto — 自定义 TCP 安全协议

一个自定义的 TCP 安全协议，为点对点连接提供双向认证、前向保密与流量混淆。
底层完全基于标准密码学原语（X25519、Ed25519、HKDF-SHA256、AES-256-GCM /
ChaCha20-Poly1305），不自行发明任何密码学算法。

> **安全声明。** 本项目是协议设计的工程实践。它**未经第三方审计**。
> 在没有独立评审的情况下，请勿用它保护机密、受监管或高价值数据。
> 生产环境请优先使用经过充分验证的传输层方案（TLS 1.3、WireGuard、SSH）。
> 明确的威胁模型与已知边界见
> [PROTOCOL.md](PROTOCOL.md#11-已知安全边界)。

## 特性

- **双向认证**：握手报文采用 Ed25519 签名，绑定完整握手转录。
- **前向保密（PFS）**：每次握手（以及每次全量重协商）使用全新的 X25519 临时密钥。
- **AEAD 加密**：默认 AES-256-GCM，回退 ChaCha20-Poly1305；每方向独立密钥与序列号。
- **重放防护**：1024 项的序列号滑动窗口 + 时间戳时间窗口，双重校验。
- **TOFU + 公钥固定（pinning）**：支持多公钥固定以平滑轮换，并内置 CRL 吊销列表。
- **流量混淆**：载荷填充到 16 字节块，并按抖动发送周期性 dummy/cover 帧。
- **时钟偏移协商**：握手交换时间戳，降低对 NTP 的强依赖。
- **口令加密身份密钥**：scrypt + AES-256-GCM 包裹 Ed25519 seed，私钥明文不落盘。
- **统一模糊错误**：所有失败对外返回同一错误，并施加恒定延迟，使失败模式不可区分。

## 仓库结构

```
cmd/secproto/          CLI 入口（genkey | server | client）
internal/crypto/       AEAD 密码、X25519/Ed25519 密钥、HKDF、密钥文件
internal/proto/secpb/  握手消息的 protobuf 生成代码
internal/protocol/     帧格式、常量、错误、指标、填充
internal/session/      单连接密码状态 + 重放窗口
internal/transport/    Conn、握手、rekey、重协商、读循环
internal/trust/        TOFU / 多公钥固定 / CRL 信任存储
proto/                 protobuf 源文件
tests/                 Python 黑盒测试套件（T1–T13）
```

## 构建

需要 Go 1.22+（`go.mod` 声明为 1.26；代码仅使用稳定版标准库 +
`golang.org/x/crypto`）。

```sh
# 本机构建
make build

# 静态 Linux amd64 二进制（用于发布 / 容器）
make build-linux          # -> build/secproto-linux-amd64

# 交叉编译示例
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o build/secproto-linux-arm64 ./cmd/secproto
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o build/secproto-darwin-arm64 ./cmd/secproto

# vendor / 离线构建
make vendor
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" \
    -o build/secproto ./cmd/secproto
```

## 快速开始

```sh
# 1. 生成经口令加密的身份密钥
export SECPROTO_PASSPHRASE='correct-horse-battery-staple'
./build/secproto-linux-amd64 -role genkey -key /tmp/server.key
./build/secproto-linux-amd64 -role genkey -key /tmp/client.key

# 2. 启动服务端（回显收到的数据）
./build/secproto-linux-amd64 -role server -key /tmp/server.key \
    -addr 127.0.0.1:8443

# 3. 运行客户端（固定服务端公钥）
./build/secproto-linux-amd64 -role client -key /tmp/client.key \
    -addr 127.0.0.1:8443 \
    -peer-pub <第 2 步打印的服务端公钥 hex>
```

## 配置项

所有选项都可经环境变量或命令行 flag 设置。对非口令项，flag 优先；对
口令，环境变量优先级高于 flag（更安全）。

| CLI flag           | 环境变量             | 默认值           | 说明                                                   |
|--------------------|----------------------|------------------|--------------------------------------------------------|
| `-role`            | `SECPROTO_ROLE`      | _（必填）_       | `genkey` \| `server` \| `client`                        |
| `-addr`            | `SECPROTO_ADDR`      | `127.0.0.1:8443` | 监听（server）或拨号（client）地址                      |
| `-key`             | `SECPROTO_KEY`       | _（必填）_       | 身份密钥文件路径                                        |
| `-peer-pub`        | `SECPROTO_PEER_PUB`  | _（空）_         | 逗号分隔的对端 Ed25519 公钥（hex），用于固定           |
| `-revoke`          | `SECPROTO_REVOKE`    | _（空）_         | 逗号分隔的已吊销公钥（hex）——CRL                        |
| `-trust-store`     | `SECPROTO_TRUST_STORE` | _（空）_       | TOFU 信任存储文件路径                                   |
| `-passphrase`      | —                    | _（空）_         | 身份密钥口令（不安全；建议用环境变量）                  |
| —                  | `SECPROTO_PASSPHRASE`| _（空）_         | 身份密钥口令（推荐）                                    |

其他可调参数是
[`internal/protocol/constants.go`](internal/protocol/constants.go)
中的编译期常量：

| 常量                       | 默认值        | 含义                                             |
|----------------------------|---------------|--------------------------------------------------|
| `ProtocolVersion`          | `1`           | 线路协议版本                                     |
| `MinSupportedVersion`      | `1`           | 可接受的最低版本                                 |
| `HeaderSize`               | `37`          | 固定帧头长度（字节）                             |
| `MaxFramePayload`          | `16 MiB`      | 单帧最大载荷                                     |
| `HandshakeTimeWindow`      | `30 s`        | 握手帧的时钟偏移容忍                             |
| `DataTimeWindow`           | `60 s`        | 数据帧的时钟偏移容忍                             |
| `ReplayWindowSize`         | `1024`        | 滑动重放窗口大小                                 |
| `HeartbeatInterval`        | `15 s`        | 心跳帧间隔                                       |
| `SessionKeyTTL`            | `1 h`         | 会话密钥生命周期（触发 PFS 重协商）              |
| `MaxKeyID`                 | `250`         | 强制重协商前的 `key_id` 上限                     |
| `PaddingBlockSize`         | `16`          | 载荷填充块大小（`0` 关闭）                       |
| `MaxPaddingSize`           | `1024`        | 单帧最大填充开销                                 |
| `DummyFrameInterval`       | `10 s`        | dummy/cover 帧的基础间隔                         |
| `DummyFrameJitter`         | `±3 s`        | 施加于 dummy 间隔的随机抖动                      |
| `DefaultDummyPayloadSize`  | `64`          | dummy 帧载荷大小                                 |
| `MaxClockOffset`           | `5 min`       | 允许补偿的最大时钟偏移                           |
| `ForceRenegotiateInterval` | `1 h`         | 强制全量 PFS 重握手的间隔                        |

### 身份密钥文件

- **加密存储（推荐）：** `scrypt(N=32768, r=8, p=1)` 从口令与 16 字节随机盐
  派生出 32 字节 AES 密钥；用 AES-256-GCM（12 字节 nonce）包裹 32 字节
  Ed25519 seed。文件布局：`[salt 16][nonce 12][ciphertext+tag 48]`。
- **旧版明文：** 原始 32 字节 Ed25519 seed。仅为向后兼容保留；当口令为空时
  `genkey` 会打印告警；用无口令方式加载加密密钥文件会直接失败。

## 密钥轮换与吊销

- **带内 rekey**（`MsgTypeRekey`）：由
  `HKDF(old_traffic_secret || new_random)` 派生新的流量密钥。快速轻量，但
  **不提供前向保密**——旧流量密钥一旦泄露，可推导后续所有带内密钥。仅用于
  会话内的 nonce 空间 / 密钥生命周期管理。
- **全量重协商**（`MsgTypeReneg*`）：在加密会话内进行全新的 X25519 交换，
  新密钥与旧会话无关，因此旧密钥泄露**不会**暴露新流量。这是唯一满足 PFS 的
  轮换路径。当 `key_id` 达到 `MaxKeyID`，或会话密钥超过 `SessionKeyTTL`
  （默认 1 小时）时自动触发。
- **多公钥固定：** `-peer-pub` 接受逗号分隔的列表，轮换窗口内新旧密钥均被接受。
- **CRL：** `-revoke` 接受逗号分隔的公钥列表，无论固定或 TOFU 状态如何，
  这些密钥一律被拒绝。

平滑轮换身份密钥的操作手册：

1. 生成新的身份密钥（`genkey`）。
2. 把新公钥加入对端的 `-peer-pub` 列表（保留旧公钥）。
3. 重启对端。
4. 将本端身份切换为新密钥并重启。
5. 从对端的 `-peer-pub` 列表移除旧公钥，并（可选）加入 `-revoke`。

## 测试

### Go 单元测试

```sh
make test          # go test ./... -v
make vet           # go vet ./...
```

### Python 黑盒测试（T1–T13）

Python 套件直接以线路协议通信，覆盖：握手、篡改、重放、过期、MITM、
nonce 复用、并发、重连、PFS 重协商、填充、口令密钥、时钟偏移、CRL/多公钥。

```sh
pip install -r tests/requirements.txt
export SECPROTO_BIN=./build/secproto-linux-amd64
python3 tests/secproto_test.py
```

预期输出：`RESULTS: 13/13 tests passed`。

## 交叉编译矩阵（参考）

```sh
for os in linux darwin windows; do
  for arch in amd64 arm64; do
    [ "$os" = "windows" ] && ext=.exe || ext=
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
      -ldflags="-s -w" -o build/secproto-$os-$arch$ext ./cmd/secproto
  done
done
```

## 许可

内部工程产物。未授予公开许可证。
