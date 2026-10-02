package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"kepler/web/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	dbURL := os.Getenv("KEPLER_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("KEPLER_TEST_DB_URL not set; run `docker compose up -d` in backend/ and set it to enable API tests")
	}
	st, err := store.Open(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// randomSuffix is defined in landing_test.go (same package) — reused here
// rather than duplicated.

// seedFinding inserts directly via a separate raw pgx connection, same
// reasoning as internal/store's own tests: this package is read-only by
// design (store.Store exposes no write methods), so tests seed data
// themselves rather than through a write API that doesn't exist here.
func seedFinding(t *testing.T, hostname, pkg, cveID, severity string) {
	t.Helper()
	ctx := context.Background()
	dbURL := os.Getenv("KEPLER_TEST_DB_URL")

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connecting to seed test data: %v", err)
	}
	defer conn.Close(ctx)

	var hostID, ingestionID string
	if err := conn.QueryRow(ctx, `INSERT INTO hosts (hostname) VALUES ($1) RETURNING id`, hostname).Scan(&hostID); err != nil {
		t.Fatalf("seeding host: %v", err)
	}
	if err := conn.QueryRow(ctx, `INSERT INTO ingestions (host_id) VALUES ($1) RETURNING id`, hostID).Scan(&ingestionID); err != nil {
		t.Fatalf("seeding ingestion: %v", err)
	}
	if _, err := conn.Exec(ctx,
		`INSERT INTO findings (ingestion_id, host_id, package, version, cve_id, severity) VALUES ($1, $2, $3, '1.0', $4, $5)`,
		ingestionID, hostID, pkg, cveID, severity,
	); err != nil {
		t.Fatalf("seeding finding: %v", err)
	}
}

func TestFindingsAPI_ReturnsJSON(t *testing.T) {
	st := testStore(t)
	hostname := "api-test-host-" + randomSuffix(t)
	seedFinding(t, hostname, "openssl", "CVE-API-TEST-1", "HIGH")

	req := httptest.NewRequest(http.MethodGet, "/api/findings?host="+hostname, nil)
	rec := httptest.NewRecorder()
	FindingsAPI(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp findingsAPIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].CVEID != "CVE-API-TEST-1" {
		t.Errorf("unexpected findings: %+v", resp.Findings)
	}
	found := false
	for _, h := range resp.Hostnames {
		found = found || h == hostname
	}
	if !found {
		t.Errorf("hostnames missing %q: %v", hostname, resp.Hostnames)
	}
}

func TestFindingsAPI_EmptyResultIsEmptyArrayNotNull(t *testing.T) {
	st := testStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/findings?host=no-such-host-"+randomSuffix(t), nil)
	rec := httptest.NewRecorder()
	FindingsAPI(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	// A literal substring check, not just unmarshaling into a Go slice —
	// unmarshaling "null" into []model.Finding succeeds and looks
	// identical to "[]" once decoded, which would hide the exact bug this
	// test exists to catch.
	if body := rec.Body.String(); !strings.Contains(body, `"findings":[]`) {
		t.Errorf("expected findings to encode as [], got: %s", body)
	}
}
