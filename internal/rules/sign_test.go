// SPDX-License-Identifier: FSL-1.1-ALv2

package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestVerifyPackSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("name: baseline\nversion: 0.1.0\n")
	sig := ed25519.Sign(priv, payload)

	if err := VerifyPackSignature(pub, payload, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0xFF
	if err := VerifyPackSignature(pub, tampered, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered payload: want ErrBadSignature, got %v", err)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyPackSignature(otherPub, payload, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key: want ErrBadSignature, got %v", err)
	}

	if err := VerifyPackSignature(pub[:10], payload, sig); err == nil || errors.Is(err, ErrBadSignature) {
		t.Fatalf("short key: want size error, got %v", err)
	}
}

func TestParsePublicKeyBase64(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePublicKeyBase64(base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(got) {
		t.Error("round-tripped key differs")
	}

	if _, err := ParsePublicKeyBase64("not base64!!!"); err == nil {
		t.Error("want decode error for invalid base64")
	}
	if _, err := ParsePublicKeyBase64(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("want size error for short key")
	}
}
