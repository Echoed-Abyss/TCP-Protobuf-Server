package transport

import (
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/proto/secpb"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/session"

	"google.golang.org/protobuf/proto"
)

// renegotiation holds the in-progress full re-handshake state.
//
// Full renegotiation provides forward secrecy: fresh X25519 ephemeral keys
// are exchanged (encrypted under the current session key), and the new
// session keys are derived from the new shared secret. Compromise of the old
// session key does not reveal the new session keys.
type renegotiation struct {
	initiator bool // true if we started this renegotiation

	// ephemeral keys
	eph *crypto.EphemeralKey

	// randoms
	localRandom  []byte
	remoteRandom []byte

	// transcript bytes for signature verification
	chBytes []byte // reneg client hello bytes
	shBytes []byte // reneg server hello bytes
	spBytes []byte // reneg server proof bytes

	// selected cipher suite
	cipherSuite protocol.CipherSuite

	// done is closed when renegotiation completes (nil error) or fails.
	done chan error
}

// InitiateRenegotiate starts a full re-handshake to restore forward secrecy.
// It sends a RenegClientHello (encrypted under the current key) carrying a
// fresh X25519 ephemeral key and client random, then waits for the peer to
// complete the handshake. The new session keys are derived from the fresh
// X25519 shared secret.
//
// Unlike InitiateRekey (which derives new keys from the old traffic secret
// and is NOT forward-secret), InitiateRenegotiate provides forward secrecy:
// if the old session key is later compromised, the new session keys (and any
// data sent after renegotiation) remain secure.
func (c *Conn) InitiateRenegotiate() error {
	c.renegMu.Lock()
	if c.reneg != nil {
		c.renegMu.Unlock()
		return protocol.ErrHandshake // already renegotiating
	}

	eph, err := crypto.GenerateEphemeral()
	if err != nil {
		c.renegMu.Unlock()
		return err
	}
	clientRandom := randomBytes(32)

	ch := &secpb.ClientHello{
		Version:               uint32(protocol.ProtocolVersion),
		CipherSuites:          cipherSuitesToProto(DefaultCipherSuites),
		ClientRandom:          clientRandom,
		ClientEphemeralPubkey: eph.Public[:],
		ClientIdentityPubkey:  c.identity.Public,
	}
	chBytes, err := proto.Marshal(ch)
	if err != nil {
		eph.Wipe()
		c.renegMu.Unlock()
		return err
	}

	r := &renegotiation{
		initiator:   true,
		eph:         eph,
		localRandom: clientRandom,
		chBytes:     chBytes,
		done:        make(chan error, 1),
	}
	c.reneg = r
	c.renegMu.Unlock()

	// Send the renegotiation ClientHello encrypted under the current key.
	if err := c.writeEncrypted(protocol.MsgTypeRenegClientHello, chBytes); err != nil {
		c.renegMu.Lock()
		c.reneg = nil
		c.renegMu.Unlock()
		eph.Wipe()
		return err
	}

	// Wait for the read loop to drive the rest of the handshake.
	select {
	case err := <-r.done:
		return err
	case <-time.After(time.Duration(protocol.HandshakeTimeWindow)):
		c.renegMu.Lock()
		c.reneg = nil
		c.renegMu.Unlock()
		return protocol.ErrHandshake
	}
}

// handleRenegotiationFrame processes a single renegotiation message in the
// read loop. It drives both the initiator and responder state machines.
func (c *Conn) handleRenegotiationFrame(msgType protocol.MsgType, plaintext []byte) error {
	c.renegMu.Lock()
	r := c.reneg
	c.renegMu.Unlock()

	switch msgType {
	case protocol.MsgTypeRenegClientHello:
		// We are the responder. Start the server side of renegotiation.
		return c.renegRespondClientHello(plaintext)
	case protocol.MsgTypeRenegServerHello:
		if r == nil || !r.initiator {
			return protocol.ErrHandshake
		}
		return c.renegHandleServerHello(r, plaintext)
	case protocol.MsgTypeRenegServerProof:
		if r == nil || !r.initiator {
			return protocol.ErrHandshake
		}
		return c.renegHandleServerProof(r, plaintext)
	case protocol.MsgTypeRenegClientFinished:
		if r == nil || r.initiator {
			return protocol.ErrHandshake
		}
		return c.renegHandleClientFinished(r, plaintext)
	case protocol.MsgTypeRenegServerFinished:
		if r == nil || !r.initiator {
			return protocol.ErrHandshake
		}
		return c.renegHandleServerFinished(r, plaintext)
	default:
		return protocol.ErrHandshake
	}
}

// ---------- Responder (server) side ----------

func (c *Conn) renegRespondClientHello(chBytes []byte) error {
	ch := &secpb.ClientHello{}
	if err := proto.Unmarshal(chBytes, ch); err != nil {
		return protocol.ErrHandshake
	}
	if ch.Version != uint32(protocol.ProtocolVersion) {
		return protocol.ErrHandshake
	}
	if len(ch.ClientRandom) != 32 || len(ch.ClientEphemeralPubkey) != 32 {
		return protocol.ErrHandshake
	}
	if len(ch.CipherSuites) == 0 {
		return protocol.ErrHandshake
	}

	// Verify client identity.
	if err := c.verifyPeerTrust(ch.ClientIdentityPubkey); err != nil {
		return err
	}

	selected := selectCipherSuite(ch.CipherSuites)
	if selected == protocol.CipherSuiteUnspecified {
		return protocol.ErrHandshake
	}

	eph, err := crypto.GenerateEphemeral()
	if err != nil {
		return err
	}
	serverRandom := randomBytes(32)

	sh := &secpb.ServerHello{
		Version:               uint32(protocol.ProtocolVersion),
		CipherSuite:           secpb.CipherSuite(selected),
		ServerRandom:          serverRandom,
		ServerEphemeralPubkey: eph.Public[:],
		ServerIdentityPubkey:  c.identity.Public,
	}
	shBytes, err := proto.Marshal(sh)
	if err != nil {
		eph.Wipe()
		return err
	}
	if err := c.writeEncrypted(protocol.MsgTypeRenegServerHello, shBytes); err != nil {
		eph.Wipe()
		return err
	}

	// Sign transcript = chBytes || shBytes.
	transcript1 := append(append([]byte{}, chBytes...), shBytes...)
	serverSig := c.identity.Sign(transcript1)
	sp := &secpb.ServerProof{Signature: serverSig}
	spBytes, err := proto.Marshal(sp)
	if err != nil {
		eph.Wipe()
		return err
	}
	if err := c.writeEncrypted(protocol.MsgTypeRenegServerProof, spBytes); err != nil {
		eph.Wipe()
		return err
	}

	// Store state; wait for ClientFinished.
	r := &renegotiation{
		initiator:    false,
		eph:          eph,
		localRandom:  serverRandom,
		remoteRandom: ch.ClientRandom,
		chBytes:      chBytes,
		shBytes:      shBytes,
		spBytes:      spBytes,
		cipherSuite:  selected,
	}
	c.renegMu.Lock()
	c.reneg = r
	c.renegMu.Unlock()
	return nil
}

func (c *Conn) renegHandleClientFinished(r *renegotiation, cfBytes []byte) error {
	cf := &secpb.ClientFinished{}
	if err := proto.Unmarshal(cfBytes, cf); err != nil {
		return protocol.ErrHandshake
	}
	// Extract client identity from the stored ClientHello.
	ch := &secpb.ClientHello{}
	if err := proto.Unmarshal(r.chBytes, ch); err != nil {
		return protocol.ErrHandshake
	}
	fullTranscript := append(append(append([]byte{}, r.chBytes...), r.shBytes...), r.spBytes...)
	if !crypto.VerifySignature(ch.ClientIdentityPubkey, fullTranscript, cf.Signature) {
		return protocol.ErrHandshake
	}

	// Derive new session keys from the fresh X25519 shared secret.
	var clientEphPub [32]byte
	copy(clientEphPub[:], ch.ClientEphemeralPubkey)
	shared, err := r.eph.SharedSecret(clientEphPub)
	r.eph.Wipe()
	if err != nil {
		return protocol.ErrHandshake
	}
	keys, err := crypto.DeriveKeys(shared, r.remoteRandom, r.localRandom)
	if err != nil {
		return protocol.ErrHandshake
	}
	ts, err := crypto.DeriveTrafficSecretForRekey(shared, r.remoteRandom, r.localRandom)
	if err != nil {
		return protocol.ErrHandshake
	}

	newSess, err := session.NewSession(keys, r.cipherSuite, false)
	if err != nil {
		return protocol.ErrHandshake
	}
	newSess.SetTrafficSecret(ts)

	// Swap session: wipe old key material, install new.
	c.renegMu.Lock()
	old := c.session
	c.session = newSess
	c.reneg = nil
	c.renegMu.Unlock()
	if old != nil {
		old.Wipe()
	}

	// Send ServerFinished.
	sf := &secpb.ServerFinished{Success: true}
	sfBytes, err := proto.Marshal(sf)
	if err != nil {
		return err
	}
	return c.writeEncrypted(protocol.MsgTypeRenegServerFinished, sfBytes)
}

// ---------- Initiator (client) side ----------

func (c *Conn) renegHandleServerHello(r *renegotiation, shBytes []byte) error {
	sh := &secpb.ServerHello{}
	if err := proto.Unmarshal(shBytes, sh); err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	if sh.Version != uint32(protocol.ProtocolVersion) {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	if len(sh.ServerRandom) != 32 || len(sh.ServerEphemeralPubkey) != 32 {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	if err := c.verifyPeerTrust(sh.ServerIdentityPubkey); err != nil {
		r.done <- err
		return err
	}
	r.remoteRandom = sh.ServerRandom
	r.shBytes = shBytes
	r.cipherSuite = protocol.CipherSuite(sh.CipherSuite)
	return nil
}

func (c *Conn) renegHandleServerProof(r *renegotiation, spBytes []byte) error {
	sp := &secpb.ServerProof{}
	if err := proto.Unmarshal(spBytes, sp); err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	// Verify server signature over chBytes || shBytes.
	sh := &secpb.ServerHello{}
	if err := proto.Unmarshal(r.shBytes, sh); err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	transcript1 := append(append([]byte{}, r.chBytes...), r.shBytes...)
	if !crypto.VerifySignature(sh.ServerIdentityPubkey, transcript1, sp.Signature) {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	r.spBytes = spBytes

	// Derive new session keys from fresh X25519.
	var serverEphPub [32]byte
	copy(serverEphPub[:], sh.ServerEphemeralPubkey)
	shared, err := r.eph.SharedSecret(serverEphPub)
	r.eph.Wipe()
	if err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	keys, err := crypto.DeriveKeys(shared, r.localRandom, r.remoteRandom)
	if err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	ts, err := crypto.DeriveTrafficSecretForRekey(shared, r.localRandom, r.remoteRandom)
	if err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}

	newSess, err := session.NewSession(keys, r.cipherSuite, true)
	if err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	newSess.SetTrafficSecret(ts)

	// Swap session.
	c.renegMu.Lock()
	old := c.session
	c.session = newSess
	c.renegMu.Unlock()
	if old != nil {
		old.Wipe()
	}

	// Send ClientFinished with signature over full transcript.
	fullTranscript := append(append(append([]byte{}, r.chBytes...), r.shBytes...), r.spBytes...)
	clientSig := c.identity.Sign(fullTranscript)
	cf := &secpb.ClientFinished{Signature: clientSig}
	cfBytes, err := proto.Marshal(cf)
	if err != nil {
		r.done <- err
		return err
	}
	if err := c.writeEncrypted(protocol.MsgTypeRenegClientFinished, cfBytes); err != nil {
		r.done <- err
		return err
	}
	return nil
}

func (c *Conn) renegHandleServerFinished(r *renegotiation, sfBytes []byte) error {
	sf := &secpb.ServerFinished{}
	if err := proto.Unmarshal(sfBytes, sf); err != nil {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	if !sf.Success {
		r.done <- protocol.ErrHandshake
		return protocol.ErrHandshake
	}
	c.renegMu.Lock()
	c.reneg = nil
	c.renegMu.Unlock()
	r.done <- nil
	return nil
}
