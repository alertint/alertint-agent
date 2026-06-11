// SPDX-License-Identifier: FSL-1.1-ALv2

package rules

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// Pack signature verification for the future FeedSource: a feed serves a
// pack archive plus a detached ed25519 signature; the runtime verifies the
// signature against a pinned public key before loading the pack. Only the
// verification side lives here — signing happens in the feed's release
// pipeline, never in the runtime.

// ErrBadSignature is returned when a pack signature does not verify.
var ErrBadSignature = errors.New("rules: pack signature verification failed")

// ParsePublicKeyBase64 decodes a standard-base64 ed25519 public key, as it
// would appear in configuration.
func ParsePublicKeyBase64(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("rules: decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("rules: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// VerifyPackSignature checks a detached ed25519 signature over payload.
// Returns nil when the signature is valid, ErrBadSignature otherwise.
func VerifyPackSignature(publicKey ed25519.PublicKey, payload, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("rules: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBadSignature
	}
	return nil
}
