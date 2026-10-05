package transport

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
)

// pipeConn creates a connected pair of net.Conn backed by an in-memory pipe.
func pipeConn() (net.Conn, net.Conn) {
	c1, c2 := net.Pipe()
	return c1, c2
}

func TestHandshakeAndData(t *testing.T) {
	serverID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	srvRaw, cliRaw := pipeConn()
	defer srvRaw.Close()
	defer cliRaw.Close()

	srv := NewConn(srvRaw, serverID, false)
	srv.SetPeerID(clientID.Public)
	cli := NewConn(cliRaw, clientID, true)
	cli.SetPeerID(serverID.Public)

	var wg sync.WaitGroup
	var srvErr, cliErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		srvErr = srv.Handshake()
	}()
	go func() {
		defer wg.Done()
		cliErr = cli.Handshake()
	}()

	// net.Pipe is synchronous; handshake must complete within a timeout.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timed out")
	}
	if srvErr != nil {
		t.Fatalf("server handshake: %v", srvErr)
	}
	if cliErr != nil {
		t.Fatalf("client handshake: %v", cliErr)
	}

	// Client -> Server data
	msg := []byte("ping")
	var received []byte
	var dataWg sync.WaitGroup
	dataWg.Add(1)
	srv.SetOnData(func(data []byte) {
		received = data
		dataWg.Done()
	})

	go srv.ReadLoop()

	if err := cli.SendData(msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	dataDone := make(chan struct{})
	go func() { dataWg.Wait(); close(dataDone) }()
	select {
	case <-dataDone:
	case <-time.After(3 * time.Second):
		t.Fatal("data delivery timed out")
	}
	if !bytes.Equal(received, msg) {
		t.Errorf("got %q want %q", received, msg)
	}
}

func TestHandshakeRejectsWrongPeer(t *testing.T) {
	serverID, _ := crypto.GenerateIdentity()
	clientID, _ := crypto.GenerateIdentity()
	attackerID, _ := crypto.GenerateIdentity()

	srvRaw, cliRaw := pipeConn()
	defer srvRaw.Close()
	defer cliRaw.Close()

	// Server expects clientID, but client uses attackerID (different key).
	srv := NewConn(srvRaw, serverID, false)
	srv.SetPeerID(clientID.Public) // pins clientID
	cli := NewConn(cliRaw, attackerID, true)
	cli.SetPeerID(serverID.Public)

	var wg sync.WaitGroup
	var srvErr, cliErr error
	wg.Add(2)
	go func() { defer wg.Done(); srvErr = srv.Handshake() }()
	go func() { defer wg.Done(); cliErr = cli.Handshake() }()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timed out")
	}

	// At least one side should fail (server pins clientID, client presents attackerID).
	if srvErr == nil && cliErr == nil {
		t.Fatal("expected handshake to fail with mismatched peer identity")
	}
}
