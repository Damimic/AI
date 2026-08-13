package waitlist

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

// testStore connects to a real local kepler_marketing database — separate
// from the findings database, same convention as the other modules:
// skipped if KEPLER_TEST_MARKETING_DB_URL isn't set.
func testStore(t *testing.T) *Store {
	t.Helper()
	dbURL := os.Getenv("KEPLER_TEST_MARKETING_DB_URL")
	if dbURL == "" {
		t.Skip("KEPLER_TEST_MARKETING_DB_URL not set; create the kepler_marketing database, apply web/db/waitlist_schema.sql, and set it to enable these tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func randomEmail(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating random email: %v", err)
	}
	return "test-" + hex.EncodeToString(buf) + "@example.com"
}

func TestSignup(t *testing.T) {
	st := testStore(t)
	email := randomEmail(t)

	if err := st.Signup(context.Background(), email); err != nil {
		t.Fatalf("Signup: %v", err)
	}
}

func TestSignup_Duplicate(t *testing.T) {
	st := testStore(t)
	email := randomEmail(t)

	if err := st.Signup(context.Background(), email); err != nil {
		t.Fatalf("first Signup: %v", err)
	}
	err := st.Signup(context.Background(), email)
	if !errors.Is(err, ErrAlreadySignedUp) {
		t.Errorf("second Signup with same email: got %v, want ErrAlreadySignedUp", err)
	}
}
