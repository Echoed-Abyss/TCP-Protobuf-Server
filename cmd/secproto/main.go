package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	PeerPubHex    string
	TrustStore    string // path to TOFU trust store file
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
		if err := generateKey(cfg.KeyFile); err != nil {
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
	flag.StringVar(&cfg.PeerPubHex, "peer-pub", envOr("SECPROTO_PEER_PUB", ""), "peer Ed25519 public key (hex) for pinning")
	flag.StringVar(&cfg.TrustStore, "trust-store", envOr("SECPROTO_TRUST_STORE", ""), "path to TOFU trust store file")
	flag.Parse()
	return cfg
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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

func generateKey(path string) error {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	seed := id.Private.Seed()
	if err := os.WriteFile(path, seed, 0600); err != nil {
		return err
	}
	fmt.Printf("wrote identity seed to %s (mode 0600)\n", path)
	fmt.Printf("public key (hex): %s\n", hex.EncodeToString(id.Public))
	return nil
}

func loadIdentity(path string) (*crypto.IdentityKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
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
	id, err := loadIdentity(cfg.KeyFile)
	if err != nil {
		return err
	}
	fmt.Printf("server identity public key: %s\n", hex.EncodeToString(id.Public))

	srv := server.NewServer(id)

	if cfg.TrustStore != "" {
		store, err := trust.NewStore(cfg.TrustStore)
		if err != nil {
			return fmt.Errorf("trust store: %w", err)
		}
		srv.SetTrustStore(store)
		fmt.Printf("TOFU trust store: %s\n", cfg.TrustStore)
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
	id, err := loadIdentity(cfg.KeyFile)
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
