package transport

import (
	"fmt"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/proto/secpb"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/session"

	"google.golang.org/protobuf/proto"
)

// DefaultCipherSuites is the list of cipher suites offered by the client.
var DefaultCipherSuites = []protocol.CipherSuite{
	protocol.CipherSuiteAES256GCM,
	protocol.CipherSuiteChaCha20Poly1305,
}

// Handshake runs the handshake. The role (client/server) is determined by
// the isClient flag set at construction.
func (c *Conn) Handshake() error {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	if c.handshakeDone {
		return nil
	}

	if c.isClient {
		if err := c.clientHandshake(); err != nil {
			c.Close()
			return c.fail(err)
		}
	} else {
		if err := c.serverHandshake(); err != nil {
			c.Close()
			return c.fail(err)
		}
	}

	c.handshakeDone = true
	c.startHeartbeat()
	return nil
}

// ---------- Client handshake ----------

func (c *Conn) clientHandshake() error {
	// 1. Generate ephemeral key and random.
	clientEph, err := crypto.GenerateEphemeral()
	if err != nil {
		return fmt.Errorf("generate ephemeral: %w", err)
	}
	defer clientEph.Wipe()
	clientRandom := randomBytes(32)

	// 2. Build and send ClientHello.
	ch := &secpb.ClientHello{
		Version:               uint32(protocol.ProtocolVersion),
		CipherSuites:          cipherSuitesToProto(DefaultCipherSuites),
		ClientRandom:          clientRandom,
		ClientEphemeralPubkey: clientEph.Public[:],
		ClientIdentityPubkey:  c.identity.Public,
		ClientTime:            time.Now().UnixNano(),
	}
	chBytes, err := proto.Marshal(ch)
	if err != nil {
		return err
	}
	if err := c.writePlaintext(protocol.MsgTypeClientHello, chBytes); err != nil {
		return err
	}

	// 3. Receive ServerHello.
	shBytes, err := c.readPlaintext(protocol.MsgTypeServerHello)
	if err != nil {
		return err
	}
	sh := &secpb.ServerHello{}
	if err := proto.Unmarshal(shBytes, sh); err != nil {
		return protocol.ErrHandshake
	}
	if sh.Version != uint32(protocol.ProtocolVersion) {
		return protocol.ErrHandshake
	}
	if len(sh.ServerRandom) != 32 || len(sh.ServerEphemeralPubkey) != 32 {
		return protocol.ErrHandshake
	}

	// Estimate clock offset from the server's signed timestamp.
	c.estimateClockOffset(sh.ServerTime)

	// Verify server identity: pinned key, TOFU store, or accept.
	if err := c.verifyPeerTrust(sh.ServerIdentityPubkey); err != nil {
		protocol.GlobalMetrics.HandshakeFailed.Add(1)
		return err
	}

	// 4. Receive ServerProof.
	spBytes, err := c.readPlaintext(protocol.MsgTypeServerProof)
	if err != nil {
		return err
	}
	sp := &secpb.ServerProof{}
	if err := proto.Unmarshal(spBytes, sp); err != nil {
		return protocol.ErrHandshake
	}

	// 5. Verify server's signature over transcript = chBytes || shBytes.
	transcript1 := append(append([]byte{}, chBytes...), shBytes...)
	if !crypto.VerifySignature(sh.ServerIdentityPubkey, transcript1, sp.Signature) {
		return protocol.ErrHandshake
	}

	// 6. Compute shared secret and derive session keys.
	var serverEphPub [32]byte
	copy(serverEphPub[:], sh.ServerEphemeralPubkey)
	shared, err := clientEph.SharedSecret(serverEphPub)
	if err != nil {
		return protocol.ErrHandshake
	}
	keys, err := crypto.DeriveKeys(shared, clientRandom, sh.ServerRandom)
	if err != nil {
		return protocol.ErrHandshake
	}
	ts, err := crypto.DeriveTrafficSecretForRekey(shared, clientRandom, sh.ServerRandom)
	if err != nil {
		return protocol.ErrHandshake
	}

	sess, err := session.NewSession(keys, protocol.CipherSuite(sh.CipherSuite), true)
	if err != nil {
		return protocol.ErrHandshake
	}
	sess.SetTrafficSecret(ts)
	c.setSession(sess)

	// 7. Send ClientFinished (encrypted) with signature over full transcript.
	fullTranscript := append(append(append([]byte{}, chBytes...), shBytes...), spBytes...)
	clientSig := c.identity.Sign(fullTranscript)
	cf := &secpb.ClientFinished{Signature: clientSig}
	cfBytes, err := proto.Marshal(cf)
	if err != nil {
		return err
	}
	if err := c.writeEncrypted(protocol.MsgTypeClientFinished, cfBytes); err != nil {
		return err
	}

	// 8. Receive ServerFinished (encrypted).
	sfBytes, err := c.readEncrypted()
	if err != nil {
		return err
	}
	sf := &secpb.ServerFinished{}
	if err := proto.Unmarshal(sfBytes, sf); err != nil {
		return protocol.ErrHandshake
	}
	if !sf.Success {
		return protocol.ErrHandshake
	}

	return nil
}

// ---------- Server handshake ----------

func (c *Conn) serverHandshake() error {
	// 1. Receive ClientHello.
	chBytes, err := c.readPlaintext(protocol.MsgTypeClientHello)
	if err != nil {
		return err
	}
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

	// Estimate clock offset from the client's signed timestamp.
	c.estimateClockOffset(ch.ClientTime)

	// 2. Select cipher suite (prefer AES-256-GCM).
	selected := selectCipherSuite(ch.CipherSuites)
	if selected == protocol.CipherSuiteUnspecified {
		return protocol.ErrHandshake
	}

	// Verify client identity: pinned key, TOFU store, or accept.
	if err := c.verifyPeerTrust(ch.ClientIdentityPubkey); err != nil {
		protocol.GlobalMetrics.HandshakeFailed.Add(1)
		return err
	}

	// 3. Generate ephemeral key and random.
	serverEph, err := crypto.GenerateEphemeral()
	if err != nil {
		return fmt.Errorf("generate ephemeral: %w", err)
	}
	defer serverEph.Wipe()
	serverRandom := randomBytes(32)

	// 4. Build and send ServerHello.
	sh := &secpb.ServerHello{
		Version:               uint32(protocol.ProtocolVersion),
		CipherSuite:           secpb.CipherSuite(selected),
		ServerRandom:          serverRandom,
		ServerEphemeralPubkey: serverEph.Public[:],
		ServerIdentityPubkey:  c.identity.Public,
		ServerTime:            time.Now().UnixNano(),
	}
	shBytes, err := proto.Marshal(sh)
	if err != nil {
		return err
	}
	if err := c.writePlaintext(protocol.MsgTypeServerHello, shBytes); err != nil {
		return err
	}

	// 5. Sign transcript = chBytes || shBytes and send ServerProof.
	transcript1 := append(append([]byte{}, chBytes...), shBytes...)
	serverSig := c.identity.Sign(transcript1)
	sp := &secpb.ServerProof{Signature: serverSig}
	spBytes, err := proto.Marshal(sp)
	if err != nil {
		return err
	}
	if err := c.writePlaintext(protocol.MsgTypeServerProof, spBytes); err != nil {
		return err
	}

	// 6. Compute shared secret and derive keys.
	var clientEphPub [32]byte
	copy(clientEphPub[:], ch.ClientEphemeralPubkey)
	shared, err := serverEph.SharedSecret(clientEphPub)
	if err != nil {
		return protocol.ErrHandshake
	}
	keys, err := crypto.DeriveKeys(shared, ch.ClientRandom, serverRandom)
	if err != nil {
		return protocol.ErrHandshake
	}
	ts, err := crypto.DeriveTrafficSecretForRekey(shared, ch.ClientRandom, serverRandom)
	if err != nil {
		return protocol.ErrHandshake
	}

	sess, err := session.NewSession(keys, selected, false)
	if err != nil {
		return protocol.ErrHandshake
	}
	sess.SetTrafficSecret(ts)
	c.setSession(sess)

	// 7. Receive ClientFinished (encrypted) and verify client signature.
	cfBytes, err := c.readEncrypted()
	if err != nil {
		return err
	}
	cf := &secpb.ClientFinished{}
	if err := proto.Unmarshal(cfBytes, cf); err != nil {
		return protocol.ErrHandshake
	}
	fullTranscript := append(append(append([]byte{}, chBytes...), shBytes...), spBytes...)
	if !crypto.VerifySignature(ch.ClientIdentityPubkey, fullTranscript, cf.Signature) {
		protocol.GlobalMetrics.HandshakeFailed.Add(1)
		return protocol.ErrHandshake
	}

	// 8. Send ServerFinished (encrypted).
	sf := &secpb.ServerFinished{Success: true}
	sfBytes, err := proto.Marshal(sf)
	if err != nil {
		return err
	}
	if err := c.writeEncrypted(protocol.MsgTypeServerFinished, sfBytes); err != nil {
		return err
	}

	return nil
}

// ---------- Helpers ----------

func (c *Conn) setSession(s *session.Session) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	c.session = s
}

// writePlaintext sends an unencrypted handshake frame.
func (c *Conn) writePlaintext(msgType protocol.MsgType, payload []byte) error {
	f := protocol.NewFrame(msgType, 0, 0, nil, payload)
	return c.writeFrame(f)
}

// readPlaintext reads a frame and verifies its type matches expected.
// Handshake frames are unencrypted.
func (c *Conn) readPlaintext(expected protocol.MsgType) ([]byte, error) {
	f, err := c.readFrame()
	if err != nil {
		return nil, err
	}
	if f.MsgType != expected {
		return nil, protocol.ErrHandshake
	}
	if !c.checkTimeWindow(f, time.Duration(protocol.HandshakeTimeWindow)) {
		return nil, protocol.ErrExpired
	}
	return f.Payload, nil
}

// readEncrypted reads a frame, checks replay, decrypts, and returns plaintext.
func (c *Conn) readEncrypted() ([]byte, error) {
	sess := c.getSession()
	if sess == nil {
		return nil, protocol.ErrNotReady
	}

	f, err := c.readFrame()
	if err != nil {
		return nil, err
	}
	protocol.GlobalMetrics.FramesReceived.Add(1)
	if f.KeyID != sess.KeyID() {
		// key_id mismatch: either a rekey race or an attack. Reject.
		protocol.GlobalMetrics.DecryptFailed.Add(1)
		return nil, protocol.ErrDecryptFailed
	}
	// Replay check BEFORE decryption.
	if !sess.CheckReplay(f.Seq) {
		protocol.GlobalMetrics.ReplayRejected.Add(1)
		return nil, protocol.ErrReplay
	}
	if !c.checkTimeWindow(f, time.Duration(protocol.DataTimeWindow)) {
		protocol.GlobalMetrics.ExpiredRejected.Add(1)
		return nil, protocol.ErrExpired
	}

	aad := aadFor(f, sess.SessionID())
	padded, err := sess.Decrypt(f.Seq, f.Payload, aad)
	if err != nil {
		protocol.GlobalMetrics.DecryptFailed.Add(1)
		return nil, protocol.ErrDecryptFailed
	}
	plaintext, err := protocol.UnpadWithPrefix(padded)
	if err != nil {
		protocol.GlobalMetrics.DecryptFailed.Add(1)
		return nil, protocol.ErrDecryptFailed
	}
	// Mark as seen only after successful decryption.
	sess.AcceptReplay(f.Seq)
	return plaintext, nil
}

func cipherSuitesToProto(suites []protocol.CipherSuite) []secpb.CipherSuite {
	out := make([]secpb.CipherSuite, len(suites))
	for i, s := range suites {
		out[i] = secpb.CipherSuite(s)
	}
	return out
}

func selectCipherSuite(offered []secpb.CipherSuite) protocol.CipherSuite {
	// Preference order: AES-256-GCM first, then ChaCha20-Poly1305.
	for _, want := range []protocol.CipherSuite{
		protocol.CipherSuiteAES256GCM,
		protocol.CipherSuiteChaCha20Poly1305,
	} {
		for _, o := range offered {
			if protocol.CipherSuite(o) == want {
				return want
			}
		}
	}
	return protocol.CipherSuiteUnspecified
}
