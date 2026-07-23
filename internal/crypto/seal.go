package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Box encrypts and decrypts small secrets with AES-256-GCM.
type Box struct {
	gcm cipher.AEAD
}

// NewBox creates a Box from a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{gcm: gcm}, nil
}

// Seal encrypts plaintext and returns a base64 nonce||ciphertext blob.
func (b *Box) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := b.gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Open decrypts a blob produced by Seal.
func (b *Box) Open(sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("decode sealed blob: %w", err)
	}
	ns := b.gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("sealed blob too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	return b.gcm.Open(nil, nonce, ct, nil)
}
