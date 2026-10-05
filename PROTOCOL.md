# secproto Protocol Specification

This document specifies the wire protocol and cryptographic design of
`secproto`. It is intended to be read alongside the source code in
[`internal/`](internal/). Where this document and the code disagree, the
code is authoritative — please open an issue to fix the doc.

Version: **1** (`ProtocolVersion = 1`).

## 1. Frame format

Every message is a single frame. The header is **37 bytes**, fixed,
big-endian. The payload follows immediately.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x5343)       | Vers| Type|KeyID|   Seq ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ...Seq (cont.)              |          Nonce (12 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ...Nonce (cont.)            |       Timestamp (8 bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ...Timestamp (cont.)        |        Length (4 bytes)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload (Length bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size | Field        | Type        | Description                                             |
|-------:|-----:|--------------|-------------|---------------------------------------------------------|
|  0     |  2   | `Magic`      | `uint16 BE` | `0x5343` ("SC"). Frames without this are dropped.       |
|  2     |  1   | `Version`    | `uint8`     | Protocol version. Must be `>= MinSupportedVersion` and `<= ProtocolVersion`. |
|  3     |  1   | `MsgType`    | `uint8`     | Message type (see §2).                                  |
|  4     |  1   | `KeyID`      | `uint8`     | Traffic-key identifier. `0` for plaintext handshake.    |
|  5     |  8   | `Seq`        | `uint64 BE` | Per-direction sequence number. Monotonic; replay-protected. |
| 13     | 12   | `Nonce`      | `byte[12]`  | AEAD nonce. Constructed as `nonce_prefix(4) || seq(8)`. The wire value is informational; receivers recompute from `KeyID` + `Seq`. |
| 25     |  8   | `Timestamp`  | `uint64 BE` | Unix nanoseconds at send time. Used for the time-window check. |
| 33     |  4   | `Length`     | `uint32 BE` | Payload length in bytes. Capped at `MaxFramePayload` (16 MiB). |
| 37     | var  | `Payload`    | `byte[]`    | Protobuf handshake bytes (plaintext) **or** `AEAD(ciphertext || tag)` for encrypted frames. |

### 2. Message types

| Value | Name                     | Encrypted | Purpose                                            |
|------:|--------------------------|:---------:|----------------------------------------------------|
|  0    | `Unknown`                | —         | Reserved / invalid.                                |
|  1    | `ClientHello`            | No        | Initiates handshake.                               |
|  2    | `ServerHello`            | No        | Server ephemeral key + selected cipher suite.      |
|  3    | `ServerProof`            | No        | Server Ed25519 signature over `CH || SH`.          |
|  4    | `ClientFinished`         | Yes       | Client Ed25519 signature over `CH || SH || SP`.    |
|  5    | `ServerFinished`         | Yes       | `success=true` confirms handshake.                 |
|  6    | `Data`                   | Yes       | Application data.                                  |
|  7    | `Heartbeat`              | Yes       | Keep-alive; no payload semantics.                  |
|  8    | `Rekey`                  | Yes       | In-band key rotation (non-PFS).                    |
|  9    | `Alert`                  | Yes       | Fatal; recipient closes the connection.            |
| 10    | `RenegClientHello`       | Yes       | PFS renegotiation: fresh X25519, client side.      |
| 11    | `RenegServerHello`       | Yes       | PFS renegotiation: server side.                    |
| 12    | `RenegServerProof`       | Yes       | PFS renegotiation: server signature.               |
| 13    | `RenegClientFinished`    | Yes       | PFS renegotiation: client signature.               |
| 14    | `RenegServerFinished`    | Yes       | PFS renegotiation: final ack.                      |
| 15    | `Dummy`                  | Yes       | Cover traffic; payload is random and ignored.      |

## 3. Handshake

### 3.1 Initial handshake (plaintext)

```
Client                                              Server
  |                                                    |
  |-- ClientHello (1) -------------------------------->|   version, cipher_suites,
  |     client_random, client_eph_pub,                 |   client_identity_pub, client_time
  |                                                    |
  |<-- ServerHello (2) --------------------------------|   version, cipher_suite,
  |     server_random, server_eph_pub,                 |   server_identity_pub, server_time
  |                                                    |
  |<-- ServerProof (3) --------------------------------|   Ed25519(CH || SH)
  |                                                    |
  |  [both derive session keys from X25519 + HKDF]     |
  |                                                    |
  |-- ClientFinished (4, encrypted) ------------------>|   Ed25519(CH || SH || SP)
  |                                                    |
  |<-- ServerFinished (5, encrypted) ------------------|   success = true
  |                                                    |
```

All handshake messages except `ClientFinished` and `ServerFinished` are
sent in plaintext (no AEAD). The first two encrypted messages are
`ClientFinished` and `ServerFinished`, which prove possession of the
derived keys and bind the full transcript.

`ClientHello.client_time` and `ServerHello.server_time` are Unix
nanosecond timestamps used for clock-offset estimation (see §7).

### 3.2 Server identity verification

The client verifies the server's Ed25519 public key against, in order:

1. The locally pinned key (`-peer-pub` / `SetPeerID`).
2. The TOFU trust store entry for the dial address.
3. If neither is configured, the key is accepted (and stored on first use
   when a trust store is configured).

The server applies the same logic to the client's identity key.

### 3.3 Full renegotiation (PFS, encrypted)

After the initial handshake, either side may trigger a full
re-handshake. The renegotiation messages (types 10–14) are **encrypted
under the current session key**. A fresh X25519 ephemeral key is
generated on each side; the new traffic keys are derived from the new
shared secret and are **independent** of the old session.

```
Client                                              Server
  |-- RenegClientHello (10, enc) ------------------->|   fresh client_eph_pub, client_random
  |<-- RenegServerHello (11, enc) -------------------|   fresh server_eph_pub, server_random
  |<-- RenegServerProof (12, enc) -------------------|   Ed25519(RenegCH || RenegSH)
  |-- RenegClientFinished (13, enc) ----------------->|   Ed25519(RenegCH || RenegSH || RenegSP)
  |<-- RenegServerFinished (14, enc) -----------------|   success = true
  |  [both install new session; old session wiped]    |
```

When renegotiation completes, the old `Session` (including its traffic
secret, keys, and session ID) is zeroed via `Session.Wipe()`.

## 4. Key derivation

All key derivation uses HKDF-SHA256. The shared secret is the raw 32-byte
X25519 output.

```
salt            = client_random || server_random        (64 bytes)
handshake_secret = HKDF-SHA256(ikm = x25519_shared,
                                salt = salt,
                                info = "secproto/v1/handshake",  L = 32)
traffic_secret   = HKDF-SHA256(ikm = handshake_secret,
                                salt = (none),
                                info = "secproto/v1/traffic",    L = 32)
client_write_key = HKDF-Expand(traffic_secret, "client write key",  32)
server_write_key = HKDF-Expand(traffic_secret, "server write key",  32)
client_nonce_pfx = HKDF-Expand(traffic_secret, "client nonce",       4)
server_nonce_pfx = HKDF-Expand(traffic_secret, "server nonce",       4)
session_id       = HKDF-Expand(traffic_secret, "session id",         8)
```

`traffic_secret` is retained (wiped on session close / renegotiation) so
that in-band rekey can derive the next generation of keys.

### 4.1 Key directions

| Role   | Write key / nonce   | Read key / nonce     |
|--------|---------------------|----------------------|
| Client | `client_write_key`  | `server_write_key`   |
| Server | `server_write_key`  | `client_write_key`   |

### 4.2 In-band rekey (non-PFS)

```
new_ikm          = old_traffic_secret || new_random   (64 bytes)
new_traffic_secret = HKDF-SHA256(ikm = new_ikm, salt = (none),
                                  info = "secproto/v1/traffic", L = 32)
```

Sub-keys are expanded from `new_traffic_secret` with the same labels as
above. `key_id` is incremented by 1; sequence numbers reset to 0. Because
the key material changes, the `(key, nonce)` space does not collide with
the previous generation.

> **In-band rekey is not forward-secret.** An attacker who recovers the
> old traffic secret can derive every subsequent in-band key. Use full
> renegotiation (§3.3) for forward secrecy.

### 4.3 AEAD nonce construction

```
nonce = nonce_prefix(4 bytes, big-endian) || seq(8 bytes, big-endian)
```

For a fixed key, `seq` is monotonic per direction, so nonces are unique.
After rekey/renegotiation, the key and nonce prefix both change, so a
`seq` reset does not reuse a `(key, nonce)` pair.

## 5. AAD construction

The AEAD Additional Authenticated Data binds the frame header and the
session:

```
AAD = HeaderBytes || session_id

HeaderBytes = Magic(2) || Version(1) || MsgType(1) || KeyID(1)
              || Seq(8) || Timestamp(8)             (21 bytes)
```

Note that `Nonce` and `Length` are **not** included in `HeaderBytes`
(the nonce is derived from `KeyID`+`Seq`, and `Length` is authenticated
implicitly because the AEAD tag covers the ciphertext). Including
`Timestamp` in the AAD means an attacker cannot alter the timestamp
without breaking the AEAD tag, so the time-window check is
cryptographically bound to the frame.

## 6. Payload padding

Before encryption, the plaintext is wrapped:

```
padded = [uint32 plaintext_len, big-endian] || plaintext || [zero padding]
```

The total `padded` length is rounded up to a multiple of
`PaddingBlockSize` (default 16). Padding bytes are zero; the receiver
verifies they are zero after decryption (defense in depth, on top of the
AEAD tag). The frame's `Length` field covers `AEAD(padded)`, so the
ciphertext length reveals only the block-rounded size, not the true
plaintext length.

If `PaddingBlockSize <= 1`, no block padding is applied (the 4-byte
length prefix is still present for forward compatibility).

## 7. Clock-offset negotiation

`ClientHello.client_time` and `ServerHello.server_time` let each peer
estimate the clock offset:

```
offset = peer_time - local_now
```

The offset is clamped to `±MaxClockOffset` (default 5 minutes); offsets
beyond that are treated as zero (compensation disabled). Timestamp
validation then uses:

```
peer_ts_local = peer_ts - offset
```

**Risk analysis.** The offset is derived from an unauthenticated
timestamp in the plaintext handshake (`ClientHello`/`ServerHello`), but
it is only used to *widen* the acceptable time window, never to accept
frames older than the raw window minus the offset. An attacker who
forges `server_time` can shift the client's window by at most
`±MaxClockOffset`, which is already the tolerated skew. The timestamp is
also covered by the AEAD AAD for data frames, so data-frame timestamps
cannot be tampered with without breaking authentication. No new replay or
downgrade vector is introduced beyond what the existing time window
already permits.

## 8. Replay protection

Two independent mechanisms:

1. **Sequence-number sliding window** (`ReplayWindowSize = 1024`). A
   frame with `seq` already seen, or `seq > max_seen` but falling outside
   the window, is rejected.
2. **Timestamp time window** (`DataTimeWindow = 60 s`,
   `HandshakeTimeWindow = 30 s`). A frame whose timestamp (adjusted for
   clock offset) is more than the window away from `now` is rejected.

Both checks run **before** decryption. `seq` is marked as accepted only
after successful decryption.

## 9. Error handling & ambiguous errors

All security failures (replay, expired, decrypt-failed, handshake-failed,
invalid frame) are mapped to a single public error type:

```go
type PublicError struct{ msg string }  // Error() returns "protocol error"
```

Before the error is returned to the caller, a constant `failureDelay`
(default 5 ms) is applied so that failure modes are not distinguishable
by timing. Network/EOF errors are returned as-is (they carry no
security-relevant detail).

Internal metrics (`ReplayRejected`, `ExpiredRejected`, `DecryptFailed`,
`HandshakeFailed`, `InvalidFrame`) are kept for local observability but
are never transmitted to the peer or included in error messages.

On any security failure, the connection is closed.

## 10. Identity key storage

Identity keys are Ed25519 key pairs. The 32-byte seed is stored either:

- **Encrypted (recommended):**
  ```
  [salt 16][nonce 12][ciphertext+tag 48]
  ```
  `key = scrypt(passphrase, salt, N=32768, r=8, p=1, 32)`;
  `ciphertext = AES-256-GCM(key, nonce, seed, AAD=nil)`.
- **Legacy unencrypted:** a raw 32-byte seed. `genkey` warns when the
  passphrase is empty.

The seed is never written to disk in plaintext when a passphrase is
provided, and it is never logged (only a truncated SHA-256 fingerprint
may be used for identification).

## 11. Known security boundaries

This protocol is designed for authenticated, encrypted, low-level
point-to-point TCP links. It does **not** claim to be a general-purpose
secure transport and has the following known limitations:

- **No third-party audit.** The design and implementation have not been
  independently reviewed. Assume there are bugs.
- **No certificate chain / PKI.** Identity is based on raw Ed25519 keys
  with TOFU/pinning. There is no CA, no certificate expiry, and no
  built-in revocation protocol beyond the static CRL.
- **Forward secrecy is session-based, not message-based.** Within a
  session, in-band rekey does not provide PFS. PFS is restored only by
  full renegotiation (every hour by default or when `key_id` is
  exhausted).
- **Traffic analysis is mitigated, not eliminated.** Padding rounds
  lengths to 16-byte blocks and dummy frames add timing noise, but a
  powerful adversary can still infer activity patterns from packet
  timing and volume.
- **Clock skew tolerance is bounded.** Peers with clocks more than 5
  minutes apart will fail to handshake.
- **No built-in DoS protection.** The protocol does not rate-limit
  connections or handshakes; deploy behind a firewall / rate limiter.
- **No forward secrecy for identity keys.** The Ed25519 identity key is
  long-term; if it is compromised, the attacker can impersonate the peer
  until the key is rotated and the old key is revoked.
- **Side channels.** The implementation is not hardened against
  microarchitectural side channels (cache timing, Spectre-class
  attacks). Do not run on shared untrusted hardware for high-security
  workloads.
- **No post-quantum security.** X25519 and Ed25519 are broken by a
  large quantum computer. No PQ key encapsulation is mixed in.

## 12. Cryptographic primitives (all from Go stdlib / x/crypto)

| Purpose          | Primitive                  | Source                        |
|------------------|----------------------------|-------------------------------|
| Key exchange     | X25519 (Curve25519)        | `golang.org/x/crypto/curve25519` |
| Authentication   | Ed25519                    | `crypto/ed25519`              |
| Key derivation   | HKDF-SHA256                | `golang.org/x/crypto/hkdf`    |
| AEAD (default)   | AES-256-GCM                | `crypto/aes`, `crypto/cipher` |
| AEAD (fallback)  | ChaCha20-Poly1305          | `golang.org/x/crypto/chacha20poly1305` |
| Key wrapping     | scrypt + AES-256-GCM       | `golang.org/x/crypto/scrypt`  |
| Randomness       | `crypto/rand`              | `crypto/rand`                 |

No custom cryptographic primitives are used.
