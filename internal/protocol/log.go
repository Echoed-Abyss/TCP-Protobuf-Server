package protocol

import (
	"log"
	"os"
)

// SensitiveLogger is a logger that never writes keys, plaintext, or full
// tokens. It is used throughout the protocol stack.
type SensitiveLogger struct {
	*log.Logger
}

// NewSensitiveLogger creates a logger that writes to stderr with a prefix.
func NewSensitiveLogger(prefix string) *SensitiveLogger {
	return &SensitiveLogger{
		Logger: log.New(os.Stderr, prefix, log.LstdFlags|log.Lshortfile),
	}
}

// Redact returns a redacted representation of potentially sensitive bytes.
// Only the length is revealed; the content is replaced with a placeholder.
func Redact(b []byte) string {
	if b == nil {
		return "<nil>"
	}
	return "<redacted len=" + itoa(len(b)) + ">"
}

// itoa is a minimal int-to-string to avoid importing strconv just for this.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
