# secproto — Secure TCP Protocol

A custom TCP security protocol providing mutual authentication, forward
secrecy, and traffic obfuscation for point-to-point connections. Built on
standard cryptographic primitives (X25519, Ed25519, HKDF-SHA256,
AES-256-GCM / ChaCha20-Poly1305) with no home-grown cryptography.

> **Security note.** This is an engineering exercise in protocol design.
> It has not undergone a third-party audit. Do not use it to protect
> classified, regulated, or high-value data without an independent review.
> Prefer battle-tested transports (TLS 1.3, WireGuard, SSH) for production
> use. See [PROTOCOL.md](PROTOCOL.md#known-security-boundaries) for the
> explicit threat model and known limitations.

## Features

- **Mutual authentication** via Ed25519 signatures over the handshake
  transcript.
- **Forward secrecy** via fresh X25519 ephemeral keys per handshake (and
  per full re-handshake / renegotiation).
- **AEAD encryption** (AES-256-GCM, with ChaCha20-Poly1305 fallback) with
  per-direction keys and sequence numbers.
- **Replay protection** using a sliding sequence-number window
  (1024 entries) plus a timestamp time window.
- **TOFU + pinning** trust store, with multi-key pinning for smooth
  rotation and a CRL for revocation.
- **Traffic obfuscation**: payload padding to 16-byte blocks and
  periodic dummy/cover frames with jitter.
- **Clock-offset negotiation** to reduce NTP dependency.
- **Passphrase-encrypted identity keys** (scrypt + AES-256-GCM).
- **Unified ambiguous errors** and constant failure delay so that
  security-failure modes are indistinguishable externally.
- **Passphrase-encrypted identity keys** at rest (scrypt + AES-256-GCM).

## Repository layout

```
cmd/secproto/          CLI entry point (genkey | server | client)
internal/crypto/       AEAD ciphers, X25519/Ed25519 keys, HKDF, keyfile
internal/proto/secpb/  Generated protobuf for handshake messages
internal/protocol/     Frame format, constants, errors, metrics, padding
internal/session/      Per-connection crypto state + replay window
internal/transport/    Conn, handshake, rekey, renegotiation, read loop
internal/trust/        TOFU / multi-pin / CRL trust store
proto/                 Protobuf source
tests/                 Python black-box test suite (T1–T13)
```

## Build

Requires Go 1.22+ (the `go.mod` declares 1.26; the code uses only stable
stdlib + `golang.org/x/crypto`).

```sh
# Host build
make build

# Static Linux amd64 binary (for release / containers)
make build-linux          # -> build/secproto-linux-amd64

# Cross-compile examples
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o build/secproto-linux-arm64 ./cmd/secproto
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o build/secproto-darwin-arm64 ./cmd/secproto

# Vendored / offline build
make vendor
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" \
    -o build/secproto ./cmd/secproto
```

## Quick start

```sh
# 1. Generate a passphrase-encrypted identity key.
export SECPROTO_PASSPHRASE='correct-horse-battery-staple'
./build/secproto-linux-amd64 -role genkey -key /tmp/server.key
./build/secproto-linux-amd64 -role genkey -key /tmp/client.key

# 2. Start the server (echoes received data).
./build/secproto-linux-amd64 -role server -key /tmp/server.key \
    -addr 127.0.0.1:8443

# 3. Run the client (pin the server's public key).
./build/secproto-linux-amd64 -role client -key /tmp/client.key \
    -addr 127.0.0.1:8443 \
    -peer-pub <server-pubkey-hex-from-step-2>
```

## Configuration

All options can be set via environment variables or CLI flags (flags take
precedence for non-passphrase values; the passphrase env var is preferred
over the flag for security).

| CLI flag           | Env var              | Default          | Description                                           |
|--------------------|----------------------|------------------|-------------------------------------------------------|
| `-role`            | `SECPROTO_ROLE`      | _(required)_     | `genkey` \| `server` \| `client`                      |
| `-addr`            | `SECPROTO_ADDR`      | `127.0.0.1:8443` | Listen (server) or dial (client) address              |
| `-key`             | `SECPROTO_KEY`       | _(required)_     | Path to the identity key file                         |
| `-peer-pub`        | `SECPROTO_PEER_PUB`  | _(empty)_        | Comma-separated peer Ed25519 public keys (hex) to pin |
| `-revoke`          | `SECPROTO_REVOKE`    | _(empty)_        | Comma-separated revoked public keys (hex) — CRL       |
| `-trust-store`     | `SECPROTO_TRUST_STORE` | _(empty)_      | Path to the TOFU trust-store file                     |
| `-passphrase`      | —                    | _(empty)_        | Identity-key passphrase (insecure; use env var)       |
| —                  | `SECPROTO_PASSPHRASE`| _(empty)_        | Identity-key passphrase (preferred)                   |

Additional tunables are compiled-in constants in
[`internal/protocol/constants.go`](internal/protocol/constants.go):

| Constant                   | Default       | Meaning                                          |
|----------------------------|---------------|--------------------------------------------------|
| `ProtocolVersion`          | `1`           | Wire protocol version                            |
| `MinSupportedVersion`      | `1`           | Lowest accepted version                          |
| `HeaderSize`               | `37`          | Fixed frame-header length (bytes)               |
| `MaxFramePayload`          | `16 MiB`      | Maximum payload per frame                        |
| `HandshakeTimeWindow`      | `30 s`        | Clock-skew tolerance for handshake frames        |
| `DataTimeWindow`           | `60 s`        | Clock-skew tolerance for data frames             |
| `ReplayWindowSize`         | `1024`        | Sliding replay-window size                       |
| `HeartbeatInterval`        | `15 s`        | Heartbeat frame interval                         |
| `SessionKeyTTL`            | `1 h`         | Session-key lifetime (triggers PFS reneg.)       |
| `MaxKeyID`                 | `250`         | Highest `key_id` before forced renegotiation     |
| `PaddingBlockSize`         | `16`          | Payload padding block size (`0` disables)        |
| `MaxPaddingSize`           | `1024`        | Maximum padding overhead per frame               |
| `DummyFrameInterval`       | `10 s`        | Base interval for dummy/cover frames             |
| `DummyFrameJitter`         | `±3 s`        | Random jitter applied to the dummy interval      |
| `DefaultDummyPayloadSize`  | `64`          | Payload size of dummy frames                     |
| `MaxClockOffset`           | `5 min`       | Maximum clock offset compensated for             |
| `ForceRenegotiateInterval` | `1 h`         | Interval that forces a full PFS re-handshake     |

### Identity key files

- **Encrypted (recommended):** `scrypt(N=32768, r=8, p=1)` derives a
  32-byte AES key from the passphrase and a 16-byte random salt; the
  32-byte Ed25519 seed is wrapped with AES-256-GCM (12-byte nonce).
  File layout: `[salt 16][nonce 12][ciphertext+tag 48]`.
- **Legacy unencrypted:** a raw 32-byte Ed25519 seed. Kept only for
  backward compatibility; `genkey` prints a warning when the passphrase
  is empty, and loading an encrypted key without a passphrase fails.

## Key rotation & revocation

- **In-band rekey** (`MsgTypeRekey`): derives new traffic keys from
  `HKDF(old_traffic_secret || new_random)`. Fast and lightweight, but
  **not forward-secret** — compromise of the old traffic secret reveals
  all subsequent in-band keys. Used for nonce-space / key-lifetime
  management within a session.
- **Full renegotiation** (`MsgTypeReneg*`): a fresh X25519 exchange
  carried inside the encrypted session. The new keys are independent of
  the old session, so compromise of the old key does **not** reveal new
  traffic. This is the only PFS-preserving rotation path. It is triggered
  automatically when `key_id` reaches `MaxKeyID` or when the session key
  exceeds `SessionKeyTTL` (default 1 h).
- **Multi-pin:** `-peer-pub` accepts a comma-separated list. Both old and
  new keys are accepted during a rotation window.
- **CRL:** `-revoke` accepts a comma-separated list of public keys that
  are always rejected, regardless of pinning or TOFU.

Runbook for a smooth identity-key rotation:

1. Generate the new identity key (`genkey`).
2. Add the new public key to the peer's `-peer-pub` list (keep the old
   one).
3. Restart the peer.
4. Switch the local identity to the new key and restart.
5. Remove the old public key from the peer's `-peer-pub` list and
   optionally add it to `-revoke`.

## Testing

### Go unit tests

```sh
make test          # go test ./... -v
make vet           # go vet ./...
```

### Python black-box tests (T1–T13)

The Python suite speaks the wire protocol directly and exercises
handshake, tampering, replay, expiry, MITM, nonce reuse, concurrency,
reconnect, PFS renegotiation, padding, passphrase keys, clock offset,
and CRL/multi-pin.

```sh
pip install -r tests/requirements.txt
export SECPROTO_BIN=./build/secproto-linux-amd64
python3 tests/secproto_test.py
```

Expected output: `RESULTS: 13/13 tests passed`.

## Cross-compilation matrix (reference)

```sh
for os in linux darwin windows; do
  for arch in amd64 arm64; do
    [ "$os" = "windows" ] && ext=.exe || ext=
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
      -ldflags="-s -w" -o build/secproto-$os-$arch$ext ./cmd/secproto
  done
done
```

## License

Internal engineering artifact. No public license granted.
