// Package crypt encrypts git credentials with AES-256-GCM.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// Box seals and opens small secrets with a fixed 32-byte key.
type Box struct{ aead cipher.AEAD }

// ErrNoKey is returned when no key is configured.
var ErrNoKey = errors.New("crypt: SDRSCAN_SECRET_KEY is not configured")

// New builds a Box from a 32-byte key. A nil key yields a Box that refuses work.
func New(key []byte) (*Box, error) {
	if key == nil {
		return &Box{}, nil
	}
	if len(key) != 32 {
		return nil, errors.New("crypt: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Enabled reports whether a key is configured.
func (b *Box) Enabled() bool { return b != nil && b.aead != nil }

// Seal returns nonce || ciphertext.
func (b *Box) Seal(plain []byte) ([]byte, error) {
	if !b.Enabled() {
		return nil, ErrNoKey
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, nil), nil
}

// Open reverses Seal.
func (b *Box) Open(sealed []byte) ([]byte, error) {
	if !b.Enabled() {
		return nil, ErrNoKey
	}
	n := b.aead.NonceSize()
	if len(sealed) < n+b.aead.Overhead() {
		return nil, errors.New("crypt: ciphertext too short")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], nil)
}
