# secproto 协议规范

本文档规定 `secproto` 的线路协议与密码学设计，应与
[`internal/`](internal/) 下的源码对照阅读。若本文档与代码不一致，以代码为准
——欢迎提交 issue 修正文档。

版本：**1**（`ProtocolVersion = 1`）。

## 1. 帧格式

每条消息是一个帧。帧头固定 **37 字节**，采用大端序，其后紧跟载荷。

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x5343)       | Vers| Type|KeyID|   Seq ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ...Seq (续)                 |          Nonce (12 字节) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ...Nonce (续)               |       Timestamp (8 字节) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ...Timestamp (续)           |        Length (4 字节)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload (Length 字节)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 偏移   | 大小 | 字段         | 类型        | 说明                                                         |
|-------:|-----:|--------------|-------------|--------------------------------------------------------------|
|  0     |  2   | `Magic`      | `uint16 BE` | `0x5343`（"SC"）。不匹配的帧被直接丢弃。                      |
|  2     |  1   | `Version`    | `uint8`     | 协议版本。必须满足 `>= MinSupportedVersion` 且 `<= ProtocolVersion`。 |
|  3     |  1   | `MsgType`    | `uint8`     | 消息类型（见 §2）。                                          |
|  4     |  1   | `KeyID`      | `uint8`     | 流量密钥标识。明文握手帧为 `0`。                              |
|  5     |  8   | `Seq`        | `uint64 BE` | 每方向独立、单调递增的序列号，用于重放防护。                  |
| 13     | 12   | `Nonce`      | `byte[12]`  | AEAD nonce，构造为 `nonce_prefix(4) || seq(8)`。线路上的值是信息性的；接收方按 `KeyID` + `Seq` 重新计算。 |
| 25     |  8   | `Timestamp`  | `uint64 BE` | 发送时的 Unix 纳秒时间戳，用于时间窗口校验。                  |
| 33     |  4   | `Length`     | `uint32 BE` | 载荷长度（字节），上限 `MaxFramePayload`（16 MiB）。           |
| 37     | 变长 | `Payload`    | `byte[]`    | 明文时为 protobuf 握手字节；加密时为 `AEAD(ciphertext || tag)`。 |

### 2. 消息类型

| 值    | 名称                     | 加密 | 用途                                               |
|------:|--------------------------|:----:|----------------------------------------------------|
|  0    | `Unknown`                | —    | 保留 / 非法。                                       |
|  1    | `ClientHello`            | 否   | 发起握手。                                          |
|  2    | `ServerHello`            | 否   | 服务端临时公钥 + 选定的密码套件。                   |
|  3    | `ServerProof`            | 否   | 服务端对 `CH || SH` 的 Ed25519 签名。               |
|  4    | `ClientFinished`         | 是   | 客户端对 `CH || SH || SP` 的 Ed25519 签名。         |
|  5    | `ServerFinished`         | 是   | `success=true` 确认握手完成。                       |
|  6    | `Data`                   | 是   | 应用数据。                                          |
|  7    | `Heartbeat`              | 是   | 保活；无载荷语义。                                  |
|  8    | `Rekey`                  | 是   | 带内密钥轮换（非 PFS）。                            |
|  9    | `Alert`                  | 是   | 致命告警；接收方关闭连接。                          |
| 10    | `RenegClientHello`       | 是   | PFS 重协商：全新 X25519，客户端侧。                 |
| 11    | `RenegServerHello`       | 是   | PFS 重协商：服务端侧。                              |
| 12    | `RenegServerProof`       | 是   | PFS 重协商：服务端签名。                            |
| 13    | `RenegClientFinished`    | 是   | PFS 重协商：客户端签名。                            |
| 14    | `RenegServerFinished`    | 是   | PFS 重协商：最终确认。                              |
| 15    | `Dummy`                  | 是   | Cover 流量；载荷为随机值并被忽略。                  |

## 3. 握手

### 3.1 初始握手（明文）

```
客户端                                              服务端
  |                                                    |
  |-- ClientHello (1) -------------------------------->|   version、cipher_suites、
  |     client_random、client_eph_pub、                |   client_identity_pub、client_time
  |                                                    |
  |<-- ServerHello (2) --------------------------------|   version、cipher_suite、
  |     server_random、server_eph_pub、                |   server_identity_pub、server_time
  |                                                    |
  |<-- ServerProof (3) --------------------------------|   Ed25519(CH || SH)
  |                                                    |
  |  [双方由 X25519 + HKDF 派生会话密钥]                |
  |                                                    |
  |-- ClientFinished (4，加密) ----------------------->|   Ed25519(CH || SH || SP)
  |                                                    |
  |<-- ServerFinished (5，加密) -----------------------|   success = true
  |                                                    |
```

除 `ClientFinished` 与 `ServerFinished` 外，握手消息均以明文发送（无 AEAD）。
前两条加密消息是 `ClientFinished` 与 `ServerFinished`，它们证明持有派生出的
密钥，并绑定完整转录。

`ClientHello.client_time` 与 `ServerHello.server_time` 是 Unix 纳秒时间戳，
用于时钟偏移估计（见 §7）。

### 3.2 服务端身份验证

客户端按以下顺序验证服务端的 Ed25519 公钥：

1. 本地固定的密钥（`-peer-pub` / `SetPeerID`）。
2. 针对拨号地址的 TOFU 信任存储条目。
3. 若两者都未配置，则接受该密钥（当配置了信任存储时，首次使用即保存）。

服务端对客户端的身份密钥应用同样的逻辑。

### 3.3 全量重协商（PFS，加密）

初始握手之后，任一方都可触发全量重握手。重协商消息（类型 10–14）**以当前
会话密钥加密**发送。双方各自生成全新的 X25519 临时密钥；新的流量密钥由新的
共享密钥派生，与旧会话**相互独立**。

```
客户端                                              服务端
  |-- RenegClientHello (10，加密) ------------------>|   全新 client_eph_pub、client_random
  |<-- RenegServerHello (11，加密) ------------------|   全新 server_eph_pub、server_random
  |<-- RenegServerProof (12，加密) ------------------|   Ed25519(RenegCH || RenegSH)
  |-- RenegClientFinished (13，加密) --------------->|   Ed25519(RenegCH || RenegSH || RenegSP)
  |<-- RenegServerFinished (14，加密) ---------------|   success = true
  |  [双方安装新会话；旧会话被擦除]                    |
```

重协商完成时，旧 `Session`（含其流量密钥、密钥材料与会话 ID）会经
`Session.Wipe()` 置零。

## 4. 密钥派生

所有密钥派生均使用 HKDF-SHA256。共享密钥是 X25519 的原始 32 字节输出。

```
salt             = client_random || server_random        （64 字节）
handshake_secret = HKDF-SHA256(ikm = x25519_shared,
                                salt = salt,
                                info = "secproto/v1/handshake",  L = 32)
traffic_secret   = HKDF-SHA256(ikm = handshake_secret,
                                salt = （无）,
                                info = "secproto/v1/traffic",    L = 32)
client_write_key = HKDF-Expand(traffic_secret, "client write key",  32)
server_write_key = HKDF-Expand(traffic_secret, "server write key",  32)
client_nonce_pfx = HKDF-Expand(traffic_secret, "client nonce",       4)
server_nonce_pfx = HKDF-Expand(traffic_secret, "server nonce",       4)
session_id       = HKDF-Expand(traffic_secret, "session id",         8)
```

`traffic_secret` 会被保留（在会话关闭 / 重协商时擦除），以便带内 rekey 派生
下一代密钥。

### 4.1 密钥方向

| 角色   | 写密钥 / nonce      | 读密钥 / nonce      |
|--------|---------------------|---------------------|
| 客户端 | `client_write_key`  | `server_write_key`  |
| 服务端 | `server_write_key`  | `client_write_key`  |

### 4.2 带内 rekey（非 PFS）

```
new_ikm            = old_traffic_secret || new_random   （64 字节）
new_traffic_secret = HKDF-SHA256(ikm = new_ikm, salt = （无）,
                                  info = "secproto/v1/traffic", L = 32)
```

子密钥由 `new_traffic_secret` 以与上文相同的标签展开。`key_id` 自增 1；
序列号重置为 0。由于密钥材料已改变，`(key, nonce)` 空间不会与上一代冲突。

> **带内 rekey 不提供前向保密。** 一旦攻击者恢复旧流量密钥，即可推导后续
> 每一个带内密钥。需要前向保密时，请使用全量重协商（§3.3）。

### 4.3 AEAD nonce 构造

```
nonce = nonce_prefix(4 字节，大端) || seq(8 字节，大端)
```

对固定密钥，`seq` 每方向单调，因此 nonce 唯一。rekey/重协商后，密钥与
nonce 前缀均改变，因此 `seq` 重置不会复用任何 `(key, nonce)` 对。

## 5. AAD 构造

AEAD 的附加认证数据绑定帧头与会话：

```
AAD = HeaderBytes || session_id

HeaderBytes = Magic(2) || Version(1) || MsgType(1) || KeyID(1)
              || Seq(8) || Timestamp(8)             （21 字节）
```

注意 `Nonce` 与 `Length` **不**包含在 `HeaderBytes` 中（nonce 由
`KeyID`+`Seq` 派生；`Length` 因 AEAD tag 覆盖密文而被隐式认证）。将
`Timestamp` 纳入 AAD 意味着攻击者无法在不破坏 AEAD tag 的前提下篡改时间戳，
因此时间窗口校验与帧在密码学上被绑定在一起。

## 6. 载荷填充

加密之前，明文被包裹为：

```
padded = [uint32 明文长度，大端] || 明文 || [零填充]
```

`padded` 的总长度向上取整到 `PaddingBlockSize`（默认 16）的整数倍。填充字节
为 0；接收方在解密后校验其为零（在 AEAD tag 之上的纵深防御）。帧的 `Length`
字段覆盖 `AEAD(padded)`，因此密文长度只暴露按块取整后的长度，不暴露真实明文
长度。

若 `PaddingBlockSize <= 1`，则不进行块填充（4 字节长度前缀仍然保留，以保持
前向兼容）。

## 7. 时钟偏移协商

`ClientHello.client_time` 与 `ServerHello.server_time` 让双方估计时钟偏移：

```
offset = peer_time - local_now
```

偏移被限制在 `±MaxClockOffset`（默认 5 分钟）内；超出该范围的偏移按 0 处理
（关闭补偿）。时间戳校验随之使用：

```
peer_ts_local = peer_ts - offset
```

**风险分析。** 偏移来自明文握手中的时间戳（`ClientHello`/`ServerHello`），
未经认证，但它仅被用于**放宽**可接受的时间窗口，绝不会用于接受比"原始窗口
减去偏移"更旧的帧。伪造 `server_time` 的攻击者最多能把客户端窗口平移
`±MaxClockOffset`，而这本就是已容忍的偏移量。对于数据帧，时间戳还被 AEAD
AAD 覆盖，因此无法在不破坏认证的情况下篡改数据帧时间戳。除现有时间窗口已经
允许的范围外，不会引入新的重放或降级向量。

## 8. 重放防护

两种相互独立的机制：

1. **序列号滑动窗口**（`ReplayWindowSize = 1024`）。已出现过的 `seq`，或
   `seq > max_seen` 但落在窗口之外，一律拒绝。
2. **时间戳时间窗口**（`DataTimeWindow = 60 s`，
   `HandshakeTimeWindow = 30 s`）。时间戳（经时钟偏移补偿后）与 `now` 相差
   超过窗口的帧被拒绝。

两项检查都在**解密之前**执行。只有在成功解密之后，`seq` 才被标记为已接受。

## 9. 错误处理与模糊错误语义

所有安全失败（重放、过期、解密失败、握手失败、非法帧）都被映射为同一个对外
错误类型：

```go
type PublicError struct{ msg string }  // Error() 返回 "protocol error"
```

在错误返回给调用方之前，会施加一个恒定的 `failureDelay`（默认 5 ms），使得
失败模式无法通过时序区分。网络/EOF 错误原样返回（它们不携带安全相关信息）。

内部指标（`ReplayRejected`、`ExpiredRejected`、`DecryptFailed`、
`HandshakeFailed`、`InvalidFrame`）保留用于本地可观测性，但绝不传输给对端、
也不写入错误消息。

发生任何安全失败时，连接被关闭。

## 10. 身份密钥存储

身份密钥是 Ed25519 密钥对。32 字节 seed 的存储形式为：

- **加密（推荐）：**
  ```
  [salt 16][nonce 12][ciphertext+tag 48]
  ```
  `key = scrypt(passphrase, salt, N=32768, r=8, p=1, 32)`；
  `ciphertext = AES-256-GCM(key, nonce, seed, AAD=nil)`。
- **旧版明文：** 原始 32 字节 seed。当口令为空时 `genkey` 会告警。

当提供了口令时，seed 绝不会以明文写入磁盘，也绝不会被记录到日志（仅可能用
截断的 SHA-256 指纹做标识）。

## 11. 已知安全边界

本协议面向**经过认证、加密、低层级的点对点 TCP 链路**。它**不**声称是通用
安全传输，且存在以下已知限制：

- **未经第三方审计。** 设计与实现未经独立评审。请假定其中存在缺陷。
- **无证书链 / PKI。** 身份基于原始 Ed25519 密钥，采用 TOFU / 固定机制。
  没有 CA、没有证书过期，除静态 CRL 外也没有内建吊销协议。
- **前向保密是"会话级"而非"消息级"。** 会话内的带内 rekey 不提供 PFS。
  只有全量重协商（默认每小时一次，或 `key_id` 耗尽时）才恢复 PFS。
- **流量分析被缓解，但未被消除。** 填充把长度取整到 16 字节块，dummy 帧
  增加了时序噪声，但强敌仍可从报文的时序与体量推断活动模式。
- **时钟偏移容忍有界。** 时钟相差超过 5 分钟的对端将握手失败。
- **无内建 DoS 防护。** 协议不限制连接或握手速率；请部署在防火墙 / 限流
  组件之后。
- **身份密钥不提供前向保密。** Ed25519 身份密钥是长期密钥；一旦泄露，攻击者
  可一直冒充该对端，直到密钥被轮换且旧密钥被吊销。
- **侧信道。** 实现未针对微架构侧信道（缓存时序、Spectre 类攻击）做加固。
  高安全场景下请勿在共享的不可信硬件上运行。
- **无后量子安全性。** X25519 与 Ed25519 会被大型量子计算机攻破，未混入任何
  后量子密钥封装。

## 12. 密码学原语（全部来自 Go 标准库 / x/crypto）

| 用途           | 原语                       | 来源                           |
|----------------|----------------------------|--------------------------------|
| 密钥交换       | X25519（Curve25519）       | `golang.org/x/crypto/curve25519` |
| 身份认证       | Ed25519                    | `crypto/ed25519`               |
| 密钥派生       | HKDF-SHA256                | `golang.org/x/crypto/hkdf`     |
| AEAD（默认）   | AES-256-GCM                | `crypto/aes`、`crypto/cipher`  |
| AEAD（回退）   | ChaCha20-Poly1305          | `golang.org/x/crypto/chacha20poly1305` |
| 密钥包裹       | scrypt + AES-256-GCM       | `golang.org/x/crypto/scrypt`   |
| 随机数         | `crypto/rand`              | `crypto/rand`                  |

未使用任何自创的密码学原语。
