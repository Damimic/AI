package auth

import (
	"strings"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	raw1, hash1, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	raw2, hash2, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	if !strings.HasPrefix(raw1, "kepler_") {
		t.Errorf("raw key %q missing kepler_ prefix", raw1)
	}
	if raw1 == raw2 {
		t.Error("two calls to GenerateAPIKey produced the same key")
	}
	if hash1 == hash2 {
		t.Error("two different keys produced the same hash")
	}
	if hash1 != HashAPIKey(raw1) {
		t.Error("GenerateAPIKey's returned hash doesn't match HashAPIKey(raw)")
	}
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	if HashAPIKey("kepler_abc") != HashAPIKey("kepler_abc") {
		t.Error("HashAPIKey is not deterministic for the same input")
	}
	if HashAPIKey("kepler_abc") == HashAPIKey("kepler_abd") {
		t.Error("different inputs produced the same hash")
	}
}
