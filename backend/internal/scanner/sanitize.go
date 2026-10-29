package scanner

import (
	"regexp"
	"strings"

	"github.com/sdrscan/sdrscan/backend/internal/dastauth"
)

var urlUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@`)

// Sanitize removes URL userinfo and the given secret strings from text so it
// can safely land in scans.log_tail and logs.
func Sanitize(text string, secrets ...string) string {
	text = urlUserinfo.ReplaceAllString(text, "${1}")
	for _, s := range secrets {
		if len(s) >= 4 {
			text = strings.ReplaceAll(text, s, "[REDACTED]")
		}
	}
	return dastauth.RedactTokens(text)
}

// lastLines returns the last n non-empty lines of s.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// limitedBuffer keeps at most max bytes and drops the rest.
type limitedBuffer struct {
	max     int
	buf     []byte
	dropped bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.max - len(b.buf)
	if room > 0 {
		if len(p) <= room {
			b.buf = append(b.buf, p...)
		} else {
			b.buf = append(b.buf, p[:room]...)
			b.dropped = true
		}
	} else if len(p) > 0 {
		b.dropped = true
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return string(b.buf) }
