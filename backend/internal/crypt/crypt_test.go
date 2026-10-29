package crypt

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	b, err := New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := b.Seal([]byte("ghp_secret"))
	s2, _ := b.Seal([]byte("ghp_secret"))
	if bytes.Equal(s1, s2) {
		t.Fatal("nonce must differ per value")
	}
	if bytes.Contains(s1, []byte("ghp_secret")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := b.Open(s1)
	if err != nil || string(got) != "ghp_secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	s1[len(s1)-1] ^= 1
	if _, err := b.Open(s1); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	other, _ := New(bytes.Repeat([]byte{2}, 32))
	if _, err := other.Open(s2); err == nil {
		t.Fatal("wrong key accepted")
	}
	none, _ := New(nil)
	if none.Enabled() {
		t.Fatal("nil key must be disabled")
	}
	if _, err := none.Seal([]byte("x")); err == nil {
		t.Fatal("seal without key must fail")
	}
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}
