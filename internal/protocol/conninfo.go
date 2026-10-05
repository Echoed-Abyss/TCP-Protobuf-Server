package protocol

import "time"

// ConnInfo is a redacted snapshot of an active connection, shared between
// the server (producer) and the admin interface (consumer). It deliberately
// exposes no keys or plaintext.
type ConnInfo struct {
	ID        uint64    `json:"id"`
	Peer      string    `json:"peer_fingerprint"`
	Addr      string    `json:"remote_addr"`
	Connected time.Time `json:"connected_at"`
	KeyID     uint8     `json:"key_id"`
	BytesSent uint64    `json:"bytes_sent"`
	BytesRecv uint64    `json:"bytes_recv"`
}
