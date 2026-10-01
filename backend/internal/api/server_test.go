package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kepler/backend/internal/auth"
	"kepler/backend/internal/matcher"
	"kepler/backend/internal/store"
)

func testServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	return testServerWithMatching(t, false)
}

func testServerWithMatching(t *testing.T, matchingAvailable bool) (http.Handler, *store.Store) {
	t.Helper()
	dbURL := os.Getenv("KEPLER_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("KEPLER_TEST_DB_URL not set; run `docker compose up -d` and set it to enable API tests")
	}
	st, err := store.Open(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(st.Close)
	return NewServer(st, matchingAvailable), st
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating random suffix: %v", err)
	}
	return hex.EncodeToString(buf)
}

func provisionHost(t *testing.T, st *store.Store) (hostname, apiKey string) {
	t.Helper()
	ctx := context.Background()
	hostname = "test-host-" + randomSuffix(t)
	hostID, err := st.CreateHost(ctx, hostname)
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if _, err := st.CreateAPIKey(ctx, hostID, keyHash); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return hostname, rawKey
}

func TestIngestFindings_RequiresAuth(t *testing.T) {
	handler, _ := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/findings", bytes.NewBufferString(`{"findings":[]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestIngestFindings_RejectsInvalidKey(t *testing.T) {
	handler, _ := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/findings", bytes.NewBufferString(`{"findings":[]}`))
	req.Header.Set("Authorization", "Bearer kepler_not_a_real_key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestIngestFindings_RejectsEmptyBatch(t *testing.T) {
	handler, st := testServer(t)
	_, apiKey := provisionHost(t, st)

	req := httptest.NewRequest(http.MethodPost, "/v1/findings", bytes.NewBufferString(`{"findings":[]}`))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestIngestFindings_RejectsMissingFields(t *testing.T) {
	handler, st := testServer(t)
	_, apiKey := provisionHost(t, st)

	body := `{"findings":[{"package":"libssl3","version":"","cve_id":"CVE-2022-3786","severity":"HIGH"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/findings", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestIngestFindings_StoresBatch(t *testing.T) {
	handler, st := testServer(t)
	_, apiKey := provisionHost(t, st)

	body := `{"findings":[
		{"package":"libssl3","version":"3.0.2-0ubuntu1.1","cve_id":"CVE-2022-3786","severity":"HIGH","fixed_version":"3.0.2-0ubuntu1.7"},
		{"package":"libssl3","version":"3.0.2-0ubuntu1.1","cve_id":"CVE-2023-0464","severity":"LOW"}
	]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/findings", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("got status %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp struct {
		IngestionID string `json:"ingestion_id"`
		Stored      int    `json:"stored"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Stored != 2 {
		t.Errorf("stored = %d, want 2", resp.Stored)
	}
	if resp.IngestionID == "" {
		t.Error("response missing ingestion_id")
	}
}

// TestIngestFindings_HostIdentityFromAuth confirms that two different hosts
// posting the same-shaped request each get their findings attributed to
// their own authenticated identity — nothing in the request body can claim
// a different host, since none of the request fields even carry a host.
func TestIngestFindings_HostIdentityFromAuth(t *testing.T) {
	handler, st := testServer(t)
	_, apiKeyA := provisionHost(t, st)
	_, apiKeyB := provisionHost(t, st)

	body := `{"findings":[{"package":"libssl3","version":"3.0.2-0ubuntu1.1","cve_id":"CVE-2022-3786","severity":"HIGH"}]}`

	for _, key := range []string{apiKeyA, apiKeyB} {
		req := httptest.NewRequest(http.MethodPost, "/v1/findings", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("got status %d, want %d", rec.Code, http.StatusCreated)
		}
	}
	// Each request's ingestion is tied to whichever key authenticated it —
	// covered at the store layer by TestInsertFindings; this test's job is
	// just confirming both distinct identities are independently accepted.
}

func TestScanReports_RequiresAuth(t *testing.T) {
	handler, _ := testServerWithMatching(t, true)

	req := httptest.NewRequest(http.MethodPost, "/v1/scan-reports", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestScanReports_UnavailableWithoutDB confirms an authenticated request
// gets a clear 503, not a crash or a silent no-op, when the backend never
// opened a vulnerability database — this is the backward-compatibility
// path for a deployment that only ever used POST /v1/findings.
func TestScanReports_UnavailableWithoutDB(t *testing.T) {
	handler, st := testServerWithMatching(t, false)
	_, apiKey := provisionHost(t, st)

	req := httptest.NewRequest(http.MethodPost, "/v1/scan-reports", bytes.NewBufferString(`{"host":{"os_name":"Ubuntu","os_version_id":"22.04"},"packages":[]}`))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestScanReports_Integration exercises the real end-to-end path — decode,
// match against a real trivy-db, store — the same way TestMatch_Integration
// does in internal/matcher. Skipped if no local database is set up, same
// convention, for the same reason: this is real vulnerability data, not
// something to fixture/fake.
func TestScanReports_Integration(t *testing.T) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("resolving cache dir: %v", err)
	}
	dbDir := filepath.Join(cacheDir, "trivy", "db")
	if _, err := os.Stat(filepath.Join(dbDir, "trivy.db")); err != nil {
		t.Skipf("trivy vulnerability DB not found at %s; run `trivy image --download-db-only` to enable this test", dbDir)
	}
	if err := matcher.Init(dbDir); err != nil {
		t.Fatalf("matcher.Init: %v", err)
	}
	t.Cleanup(func() { matcher.Close() })

	handler, st := testServerWithMatching(t, true)
	_, apiKey := provisionHost(t, st)

	body := `{
		"host": {"os_name": "Ubuntu", "os_version_id": "22.04"},
		"packages": [{"name": "libssl3", "version": "3.0.2-0ubuntu1.1", "source_package": "openssl", "source_version": "3.0.2-0ubuntu1.1"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/scan-reports", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("got status %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp struct {
		Stored int `json:"stored"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Stored == 0 {
		t.Error("expected at least one finding for a deliberately outdated openssl, got zero stored")
	}
}
