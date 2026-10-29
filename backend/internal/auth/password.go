// Package auth implements password hashing, token helpers and the login throttle.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/time/rate"
)

// Argon2 parameters (OWASP minimum; tune to 200-500 ms on the target server).
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	saltLen        = 16
)

// Password policy.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 128
)

// Hasher hashes and verifies passwords with bounded concurrency.
type Hasher struct {
	sem       chan struct{}
	dummyHash string
}

// NewHasher builds a Hasher allowing at most 4 concurrent verifications.
func NewHasher() *Hasher {
	h := &Hasher{sem: make(chan struct{}, 4)}
	h.dummyHash, _ = h.Hash("dummy-password-for-timing-equalisation")
	return h
}

func (h *Hasher) acquire() func() {
	h.sem <- struct{}{}
	return func() { <-h.sem }
}

// Hash returns a PHC-format Argon2id hash.
func (h *Hasher) Hash(password string) (string, error) {
	defer h.acquire()()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks password against a PHC hash. needsRehash is true when the
// stored parameters differ from the current ones.
func (h *Hasher) Verify(password, phc string) (ok, needsRehash bool) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, false
	}
	if m > 1<<20 || t > 20 || p > 16 || m == 0 || t == 0 || p == 0 { // sanity cap on attacker-controlled params
		return false, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, false
	}
	defer h.acquire()()
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, m != argonMemoryKiB || t != argonTime || p != argonThreads || len(want) != argonKeyLen
}

// BurnVerify spends the time of one verification (unknown usernames).
func (h *Hasher) BurnVerify(password string) { h.Verify(password, h.dummyHash) }

// ValidatePassword enforces the password policy. current is the existing
// password (may be empty).
func ValidatePassword(pw, username, current string) error {
	n := len([]rune(pw))
	switch {
	case n < MinPasswordLen:
		return fmt.Errorf("Password must be at least %d characters.", MinPasswordLen)
	case n > MaxPasswordLen:
		return fmt.Errorf("Password must be at most %d characters.", MaxPasswordLen)
	case strings.EqualFold(pw, username):
		return errors.New("Password must not be the same as the username.")
	case current != "" && pw == current:
		return errors.New("New password must be different from the current password.")
	}
	return nil
}

// NewToken returns n random bytes encoded as base64url without padding.
func NewToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewHexToken returns n random bytes as hex.
func NewHexToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// HashToken returns the hex SHA-256 of a token.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// ConstantEq compares two strings in constant time.
func ConstantEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// IPLimiter limits login attempts per client IP (20 per minute by default).
type IPLimiter struct {
	mu       sync.Mutex
	limiters map[string]*entry
	rate     rate.Limit
	burst    int
	lastGC   time.Time
}

type entry struct {
	l    *rate.Limiter
	seen time.Time
}

// NewIPLimiter builds a limiter allowing perMinute attempts per minute per key.
func NewIPLimiter(perMinute int) *IPLimiter {
	return &IPLimiter{limiters: map[string]*entry{}, rate: rate.Limit(float64(perMinute) / 60.0), burst: perMinute}
}

// Allow reports whether key may attempt now; when not, retryAfter says when.
func (l *IPLimiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastGC) > 5*time.Minute {
		for k, e := range l.limiters {
			if now.Sub(e.seen) > 10*time.Minute {
				delete(l.limiters, k)
			}
		}
		l.lastGC = now
	}
	e := l.limiters[key]
	if e == nil {
		e = &entry{l: rate.NewLimiter(l.rate, l.burst)}
		l.limiters[key] = e
	}
	e.seen = now
	r := e.l.ReserveN(now, 1)
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}
