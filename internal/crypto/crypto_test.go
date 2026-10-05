package crypto

import (
	"bytes"
	"testing"
)

func TestReplayWindow(t *testing.T) {
	rw := NewReplayWindow(1024)

	// Accept seqs 1..100
	for i := uint64(1); i <= 100; i++ {
		if !rw.Check(i) {
			t.Fatalf("seq %d should be accepted", i)
		}
		rw.Accept(i)
	}

	// Replay of seq 50 should be rejected
	if rw.Check(50) {
		t.Error("replayed seq 50 should be rejected")
	}

	// A fresh seq 101 should be accepted
	if !rw.Check(101) {
		t.Error("seq 101 should be accepted")
	}

	// A seq below the window should be rejected
	if rw.Check(1) {
		t.Error("seq 1 (below window) should be rejected after advancing to 100")
	}
}

func TestReplayWindowLargeJump(t *testing.T) {
	rw := NewReplayWindow(64)
	rw.Accept(10)

	// Jump far ahead; all old seqs should be cleared.
	rw.Accept(1000)

	// Seq 10 should now be rejected (below window of 1000).
	if rw.Check(10) {
		t.Error("seq 10 should be rejected after jump to 1000")
	}
	// Seq 999 should be accepted (within window).
	if !rw.Check(999) {
		t.Error("seq 999 should be accepted within window of 1000")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	np := []byte{1, 2, 3, 4}

	c, err := NewAES256GCM(key, np)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("sensitive data")
	aad := []byte("header bytes session id")

	ct := c.Encrypt(1, plaintext, aad)
	pt, err := c.Decrypt(1, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("plaintext mismatch after round trip")
	}
}

func TestAEADWrongAAD(t *testing.T) {
	key := make([]byte, 32)
	np := []byte{1, 2, 3, 4}
	c, _ := NewAES256GCM(key, np)

	ct := c.Encrypt(1, []byte("data"), []byte("aad1"))
	if _, err := c.Decrypt(1, ct, []byte("aad2")); err == nil {
		t.Error("decrypt with wrong AAD should fail")
	}
}

func TestAEADNonceUniqueness(t *testing.T) {
	key := make([]byte, 32)
	np := []byte{1, 2, 3, 4}
	c, _ := NewAES256GCM(key, np)

	// Same seq => same nonce => different ciphertext is a sign of bad practice,
	// but here we just ensure the nonce construction differs by seq.
	ct1 := c.Encrypt(1, []byte("x"), nil)
	ct2 := c.Encrypt(2, []byte("x"), nil)
	if bytes.Equal(ct1, ct2) {
		t.Error("different seq should produce different ciphertext (different nonce)")
	}
}

func TestKeyDerivationDeterministic(t *testing.T) {
	shared := make([]byte, 32)
	cr := make([]byte, 32)
	sr := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i)
	}

	k1, err := DeriveKeys(shared, cr, sr)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKeys(shared, cr, sr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.ClientWriteKey, k2.ClientWriteKey) {
		t.Error("key derivation not deterministic")
	}
	if !bytes.Equal(k1.SessionID, k2.SessionID) {
		t.Error("session id derivation not deterministic")
	}
}

func TestKeyDerivationDifferentSecrets(t *testing.T) {
	cr := make([]byte, 32)
	sr := make([]byte, 32)
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)
	s2[0] = 1

	k1, _ := DeriveKeys(s1, cr, sr)
	k2, _ := DeriveKeys(s2, cr, sr)
	if bytes.Equal(k1.ClientWriteKey, k2.ClientWriteKey) {
		t.Error("different shared secrets should produce different keys")
	}
}

func TestX25519SharedSecret(t *testing.T) {
	a, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Wipe()
	b, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Wipe()

	sa, err := a.SharedSecret(b.Public)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.SharedSecret(a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Error("X25519 shared secrets do not match")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("handshake transcript")
	sig := id.Sign(msg)
	if !VerifySignature(id.Public, msg, sig) {
		t.Error("valid signature rejected")
	}
	// Tampered message
	if VerifySignature(id.Public, []byte("tampered"), sig) {
		t.Error("signature should not verify for tampered message")
	}
}
