package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"kepler/backend/internal/model"
)

// testStore connects to a real local Postgres for integration testing.
// Skipped if KEPLER_TEST_DB_URL isn't set — these tests need a real
// database (see backend/docker-compose.yml), not a mock, since the whole
// point is to verify the actual SQL.
func testStore(t *testing.T) *Store {
	t.Helper()
	dbURL := os.Getenv("KEPLER_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("KEPLER_TEST_DB_URL not set; run `docker compose up -d` and set it to enable store tests")
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

// randomSuffix avoids collisions between test runs without needing
// per-test transaction rollback machinery.
func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating random suffix: %v", err)
	}
	return hex.EncodeToString(buf)
}

func TestCreateHost(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	hostname := "test-host-" + randomSuffix(t)
	id, err := st.CreateHost(ctx, hostname)
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if id.String() == "" {
		t.Error("CreateHost returned a zero-value ID")
	}
}

func TestAPIKeyRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	hostID, err := st.CreateHost(ctx, "test-host-"+randomSuffix(t))
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	keyHash := "hash-" + randomSuffix(t)
	if _, err := st.CreateAPIKey(ctx, hostID, keyHash); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	gotHostID, ok, err := st.HostIDForKeyHash(ctx, keyHash)
	if err != nil {
		t.Fatalf("HostIDForKeyHash: %v", err)
	}
	if !ok {
		t.Fatal("HostIDForKeyHash: key not found immediately after creation")
	}
	if gotHostID != hostID {
		t.Errorf("HostIDForKeyHash returned %s, want %s", gotHostID, hostID)
	}

	_, ok, err = st.HostIDForKeyHash(ctx, "nonexistent-"+randomSuffix(t))
	if err != nil {
		t.Fatalf("HostIDForKeyHash (nonexistent): %v", err)
	}
	if ok {
		t.Error("HostIDForKeyHash returned ok=true for a key that was never created")
	}
}

func TestInsertFindings(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	hostID, err := st.CreateHost(ctx, "test-host-"+randomSuffix(t))
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	findings := []model.FindingInput{
		{Package: "libssl3", Version: "3.0.2-0ubuntu1.1", CVEID: "CVE-2022-3786", Severity: "HIGH", FixedVersion: "3.0.2-0ubuntu1.7"},
		{Package: "libssl3", Version: "3.0.2-0ubuntu1.1", CVEID: "CVE-2023-0464", Severity: "LOW"}, // no fixed version
	}

	ingestionID, err := st.InsertFindings(ctx, hostID, findings)
	if err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	if ingestionID.String() == "" {
		t.Error("InsertFindings returned a zero-value ingestion ID")
	}

	var count int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE ingestion_id = $1`, ingestionID).Scan(&count); err != nil {
		t.Fatalf("counting findings: %v", err)
	}
	if count != len(findings) {
		t.Errorf("stored %d findings, want %d", count, len(findings))
	}

	var lastSeen *time.Time
	if err := st.pool.QueryRow(ctx, `SELECT last_seen_at FROM hosts WHERE id = $1`, hostID).Scan(&lastSeen); err != nil {
		t.Fatalf("checking last_seen_at: %v", err)
	}
	if lastSeen == nil {
		t.Error("InsertFindings did not update hosts.last_seen_at")
	}
}
