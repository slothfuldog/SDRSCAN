package auth

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h := NewHasher()
	phc, err := h.Hash("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("not a PHC argon2id string: %s", phc)
	}
	if ok, rehash := h.Verify("correct-horse-battery", phc); !ok || rehash {
		t.Fatalf("verify: ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := h.Verify("wrong", phc); ok {
		t.Fatal("wrong password accepted")
	}
	// Different parameters verify but ask for a rehash.
	old := "$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$" + strings.Split(phc, "$")[5]
	if ok, _ := h.Verify("correct-horse-battery", old); ok {
		t.Fatal("tampered params must not verify")
	}
	for _, bad := range []string{"", "plain", "$argon2id$v=19$m=999999999,t=2,p=1$aa$bb", "$argon2i$v=19$m=1,t=1,p=1$aa$bb"} {
		if ok, _ := h.Verify("x", bad); ok {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
	p2, _ := h.Hash("correct-horse-battery")
	if p2 == phc {
		t.Fatal("hashes must be salted")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("short", "bob", ""); err == nil {
		t.Error("short accepted")
	}
	if err := ValidatePassword(strings.Repeat("a", 129), "bob", ""); err == nil {
		t.Error("long accepted")
	}
	if err := ValidatePassword("Bob-Bob-Bob-Bob", "bob-bob-bob-bob", ""); err == nil {
		t.Error("password equal to username accepted")
	}
	if err := ValidatePassword("correct-horse-battery", "bob", "correct-horse-battery"); err == nil {
		t.Error("same as current accepted")
	}
	if err := ValidatePassword("correct-horse-battery", "bob", ""); err != nil {
		t.Error(err)
	}
}

func TestTokens(t *testing.T) {
	a, b := NewToken(32), NewToken(32)
	if a == b || len(a) < 40 {
		t.Fatal("tokens must be random and long")
	}
	if HashToken(a) == a || len(HashToken(a)) != 64 {
		t.Fatal("HashToken must be hex sha256")
	}
}

func TestIPLimiter(t *testing.T) {
	l := NewIPLimiter(3)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("1.1.1.1"); !ok {
			t.Fatalf("attempt %d blocked", i)
		}
	}
	if ok, wait := l.Allow("1.1.1.1"); ok || wait <= 0 {
		t.Fatal("4th attempt must be limited")
	}
	if ok, _ := l.Allow("2.2.2.2"); !ok {
		t.Fatal("other IP must not be affected")
	}
}
