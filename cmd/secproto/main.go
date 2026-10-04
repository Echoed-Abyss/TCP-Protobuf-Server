package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/client"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/server"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/transport"
)

// Identity file format: 32 bytes private seed (Ed25519), followed by nothing
// else. The public key is derived from the seed.

func main() {
	role := flag.String("role", "", "server | client | genkey")
	addr := flag.String("addr", "127.0.0.1:8443", "listen/dial address")
	keyFile := flag.String("key", "", "path to identity key file (32-byte seed)")
	peerPubHex := flag.String("peer-pub", "", "peer Ed25519 public key (hex), for identity pinning")
	flag.Parse()

	switch *role {
	case "genkey":
		if *keyFile == "" {
			fmt.Fprintln(os.Stderr, "genkey requires -key <path>")
			os.Exit(1)
		}
		if err := generateKey(*keyFile); err != nil {
			fmt.Fprintln(os.Stderr, "genkey failed:", err)
			os.Exit(1)
		}
		return
	case "server":
		if err := runServer(*addr, *keyFile); err != nil {
			fmt.Fprintln(os.Stderr, "server error:", err)
			os.Exit(1)
		}
	case "client":
		if err := runClient(*addr, *keyFile, *peerPubHex); err != nil {
			fmt.Fprintln(os.Stderr, "client error:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: -role {genkey|server|client} -addr <addr> -key <file> [-peer-pub <hex>]")
		os.Exit(1)
	}
}

func generateKey(path string) error {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	// Ed25519 private key as returned by GenerateKey is 64 bytes:
	// seed (32) || public (32). We store only the seed for compactness.
	seed := id.Private.Seed()
	if err := os.WriteFile(path, seed, 0600); err != nil {
		return err
	}
	fmt.Printf("wrote identity seed to %s\n", path)
	fmt.Printf("public key (hex): %s\n", hex.EncodeToString(id.Public))
	return nil
}

func loadIdentity(path string) (*crypto.IdentityKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key file: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &crypto.IdentityKey{Public: pub, Private: priv}, nil
}

func runServer(addr, keyFile string) error {
	id, err := loadIdentity(keyFile)
	if err != nil {
		return err
	}
	fmt.Printf("server identity public key: %s\n", hex.EncodeToString(id.Public))

	srv := server.NewServer(id)
	srv.OnConn = func(c *transport.Conn) {
		c.SetOnData(func(data []byte) {
			_ = c.SendData(data) // echo
		})
	}
	if err := srv.Listen(addr); err != nil {
		return err
	}
	fmt.Printf("server listening on %s\n", addr)
	return srv.Serve()
}

func runClient(addr, keyFile, peerPubHex string) error {
	id, err := loadIdentity(keyFile)
	if err != nil {
		return err
	}

	cli := client.NewClient(id)
	if peerPubHex != "" {
		pub, err := hex.DecodeString(peerPubHex)
		if err != nil {
			return fmt.Errorf("invalid peer pub hex: %w", err)
		}
		cli.SetPeerID(pub)
	}

	conn, err := cli.Dial(addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Echo demo: send a message and wait for a response.
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
	<-done
	return nil
}
