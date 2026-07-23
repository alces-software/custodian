package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	box, err := NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")
	sealed, err := box.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}
	// Sealing twice should produce different ciphertexts (random nonce).
	sealed2, _ := box.Seal(plain)
	if sealed == sealed2 {
		t.Fatal("expected different sealed values")
	}
}

func TestNewBoxRejectsBadKey(t *testing.T) {
	if _, err := NewBox([]byte("short")); err == nil {
		t.Fatal("expected error")
	}
}
