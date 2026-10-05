package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/client"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/server"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/transport"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/trust"
)

// Config holds runtime configuration. Values are loaded from environment
// variables with command-line flag overrides. No long-term keys are ever
// hardcoded.
type Config struct {
	Role          string
	Addr          string
	KeyFile       string
	PeerPubHex    string // comma-separated peer Ed25519 pubkeys (hex) for pinning
	TrustStore    string // path to TOFU trust store file
	RevokeHex     string // comma-separated revoked pubkeys (hex) for CRL
	Passphrase    string // from -passphrase flag (insecure; prefer env/file)
	PassphraseEnv string // from SECPROTO_PASSPHRASE
	SessionTTL    time.Duration
	HeartbeatInt  time.Duration
	TimestampWin  time.Duration
}

func main() {
	cfg := loadConfig()

	switch cfg.Role {
	case "genkey":
		if cfg.KeyFile == "" {
			fatal("genkey requires -key <path> (or SECPROTO_KEY)")
		}
		pass := cfg.resolvePassphrase()
		if len(pass) == 0 {
			fmt.Fprintln(os.Stderr, "warning: empty passphrase; key will be stored unencrypted (legacy format)")
		}
		if err := generateKey(cfg.KeyFile, pass); err != nil {
			fatal("genkey failed: %v", err)
		}
		return
	case "server":
		if err := runServer(cfg); err != nil {
			fatal("server error: %v", err)
		}
	case "client":
		if err := runClient(cfg); err != nil {
			fatal("client error: %v", err)
		}
	default:
		fatal("usage: -role {genkey|server|client}")
	}
}

// loadConfig reads configuration from env vars and CLI flags.
// Env vars: SECPROTO_ROLE, SECPROTO_ADDR, SECPROTO_KEY, SECPROTO_PEER_PUB,
// SECPROTO_TRUST_STORE, SECPROTO_SESSION_TTL, SECPROTO_HEARTBEAT.
func loadConfig() *Config {
	cfg := &Config{
		Addr:         envOr("SECPROTO_ADDR", "127.0.0.1:8443"),
		SessionTTL:   time.Duration(protocol.SessionKeyTTL),
		HeartbeatInt: time.Duration(protocol.HeartbeatInterval),
		TimestampWin: time.Duration(protocol.DataTimeWindow),
	}

	flag.StringVar(&cfg.Role, "role", envOr("SECPROTO_ROLE", ""), "server | client | genkey")
	flag.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen/dial address")
	flag.StringVar(&cfg.KeyFile, "key", envOr("SECPROTO_KEY", ""), "path to identity key file (32-byte Ed25519 seed)")
	flag.StringVar(&cfg.PeerPubHex, "peer-pub", envOr("SECPROTO_PEER_PUB", ""), "comma-separated peer Ed25519 public keys (hex) for pinning")
	flag.StringVar(&cfg.RevokeHex, "revoke", envOr("SECPROTO_REVOKE", ""), "comma-separated revoked public keys (hex) for CRL")
	flag.StringVar(&cfg.TrustStore, "trust-store", envOr("SECPROTO_TRUST_STORE", ""), "path to TOFU trust store file")
	flag.StringVar(&cfg.Passphrase, "passphrase", "", "identity key passphrase (insecure; prefer SECPROTO_PASSPHRASE)")
	cfg.PassphraseEnv = os.Getenv("SECPROTO_PASSPHRASE")
	flag.Parse()
	return cfg
}

// resolvePassphrase returns the passphrase from the most secure available
// source. Precedence: env var > flag. Returns empty string if neither is set
// (caller decides whether to allow legacy unencrypted keys).
func (c *Config) resolvePassphrase() string {
	if c.PassphraseEnv != "" {
		return c.PassphraseEnv
	}
	return c.Passphrase
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseHexList splits a comma-separated list of hex strings and decodes each.
func parseHexList(s string) ([][]byte, error) {
	if s == "" {
		return nil, nil
	}
	var out [][]byte
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		b, err := hex.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("invalid hex %q: %w", part, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// selfCheck validates prerequisites before starting. It never prints key
// material, only file existence and permission bits.
func selfCheck(cfg *Config) error {
	if cfg.KeyFile == "" {
		return fmt.Errorf("identity key file not specified (use -key or SECPROTO_KEY)")
	}
	info, err := os.Stat(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("identity key file %q not found: %w", cfg.KeyFile, err)
	}
	// Warn (don't fail) if key file is world-readable.
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: identity key file %q is group/world-readable (mode %o); chmod 600 recommended\n",
			cfg.KeyFile, info.Mode().Perm())
	}
	// Ensure trust store directory exists if specified.
	if cfg.TrustStore != "" {
		dir := filepath.Dir(cfg.TrustStore)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create trust store directory %q: %w", dir, err)
		}
	}
	return nil
}

func generateKey(path string, passphrase string) error {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	seed := id.Private.Seed()

	var data []byte
	if len(passphrase) > 0 {
		data, err = crypto.EncryptSeed(seed, []byte(passphrase))
		if err != nil {
			return err
		}
	} else {
		// Legacy unencrypted format (32-byte seed). Kept for backward
		// compatibility; emit a warning.
		data = seed
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	fmt.Printf("wrote identity key to %s (mode 0600)\n", path)
	fmt.Printf("public key (hex): %s\n", hex.EncodeToString(id.Public))
	return nil
}

func loadIdentity(path string, passphrase string) (*crypto.IdentityKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var seed []byte
	if len(data) == ed25519.SeedSize {
		// Legacy unencrypted seed file.
		seed = data
	} else {
		// Passphrase-encrypted key file.
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("key file %q is encrypted; provide passphrase via SECPROTO_PASSPHRASE or -passphrase", path)
		}
		seed, err = crypto.DecryptSeed(data, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("decrypt key file %q: %w", path, err)
		}
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key file %q: expected %d bytes, got %d", path, ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &crypto.IdentityKey{Public: pub, Private: priv}, nil
}

func runServer(cfg *Config) error {
	if err := selfCheck(cfg); err != nil {
		return err
	}
	id, err := loadIdentity(cfg.KeyFile, cfg.resolvePassphrase())
	if err != nil {
		return err
	}
	fmt.Printf("server identity public key: %s\n", hex.EncodeToString(id.Public))

	srv := server.NewServer(id)

	// Configure trust: pinned peer keys (multi-pin) and CRL.
	pinnedKeys, err := parseHexList(cfg.PeerPubHex)
	if err != nil {
		return fmt.Errorf("invalid -peer-pub: %w", err)
	}
	revokedKeys, err := parseHexList(cfg.RevokeHex)
	if err != nil {
		return fmt.Errorf("invalid -revoke: %w", err)
	}
	if len(pinnedKeys) > 0 || len(revokedKeys) > 0 || cfg.TrustStore != "" {
		store, err := trust.NewStore(cfg.TrustStore)
		if err != nil {
			return fmt.Errorf("trust store: %w", err)
		}
		if len(pinnedKeys) > 0 {
			// Use "*" as a catch-all identifier so any connecting peer
			// must present one of the pinned keys.
			store.SetPinnedList("*", pinnedKeys)
		}
		if len(revokedKeys) > 0 {
			store.RevokeList(revokedKeys)
		}
		srv.SetTrustStore(store)
		if cfg.TrustStore != "" {
			fmt.Printf("TOFU trust store: %s\n", cfg.TrustStore)
		}
		if len(pinnedKeys) > 0 {
			fmt.Printf("pinned peer keys: %d\n", len(pinnedKeys))
		}
		if len(revokedKeys) > 0 {
			fmt.Printf("revoked keys (CRL): %d\n", len(revokedKeys))
		}
	}

	srv.OnConn = func(c *transport.Conn) {
		c.SetOnData(func(data []byte) {
			_ = c.SendData(data) // echo
		})
	}
	if err := srv.Listen(cfg.Addr); err != nil {
		return err
	}
	fmt.Printf("server listening on %s\n", cfg.Addr)
	return srv.Serve()
}

func runClient(cfg *Config) error {
	if err := selfCheck(cfg); err != nil {
		return err
	}
	id, err := loadIdentity(cfg.KeyFile, cfg.resolvePassphrase())
	if err != nil {
		return err
	}

	cli := client.NewClient(id)
	if cfg.PeerPubHex != "" {
		pub, err := hex.DecodeString(cfg.PeerPubHex)
		if err != nil {
			return fmt.Errorf("invalid peer pub hex: %w", err)
		}
		cli.SetPeerID(pub)
	}
	if cfg.TrustStore != "" {
		store, err := trust.NewStore(cfg.TrustStore)
		if err != nil {
			return fmt.Errorf("trust store: %w", err)
		}
		cli.SetTrustStore(store)
	}

	conn, err := cli.Dial(cfg.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := []byte("hello from secure client")
	if err := conn.SendData(msg); err != nil {
		return err
	}

	done := make(chan struct{})
	conn.SetOnData(func(data []byte) {
		fmt.Printf("received: %s\n", string(data))
		close(done)
	})

	go conn.ReadLoop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timed out waiting for echo")
	}
	return nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
