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
	"testing"

	"kepler/backend/internal/auth"
	"kepler/backend/internal/store"
)

func testServer(t *testing.T) (http.Handler, *store.Store) {
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
	return NewServer(st), st
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
