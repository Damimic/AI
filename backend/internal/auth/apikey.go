// Package auth handles API key generation and hashing for agent
// authentication.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const keyPrefix = "kepler_"

// GenerateAPIKey creates a new high-entropy API key. It returns the raw key
// (shown once, to the operator provisioning a host — never stored) and its
// hash (what actually gets stored, via HashAPIKey).
func GenerateAPIKey() (raw string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generating random key: %w", err)
	}
	raw = keyPrefix + hex.EncodeToString(buf)
	return raw, HashAPIKey(raw), nil
}

// HashAPIKey returns the SHA-256 hex digest of a raw API key. API keys are
// already high-entropy random secrets — unlike passwords, they don't need a
// slow, salted KDF (bcrypt/argon2); those exist to blunt brute-forcing of
// low-entropy human-chosen secrets, which doesn't apply here. A fast
// cryptographic hash plus an indexed equality lookup is standard practice
// for API-key storage.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
