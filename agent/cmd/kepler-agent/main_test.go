// This only tests reportToBackend — the HTTP client logic that posts a
// scan report to a backend. Collection itself (CollectOSInfo,
// CollectPackages, ...) is Linux-only and already tested on its own with
// fixture data in internal/collector; reportToBackend is plain net/http
// code with no OS dependency, so it's testable anywhere, including on the
// non-Linux machine this was written on.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kepler/agent/internal/model"
)

func TestReportToBackend_Success(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	var gotBody model.ScanReport

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("server: decoding request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"ingestion_id": "test-ingestion", "stored": 2})
	}))
	defer srv.Close()

	report := model.ScanReport{
		Host:     model.HostInfo{Hostname: "test-host", OSName: "Ubuntu", OSVersionID: "22.04"},
		Packages: []model.Package{{Name: "openssl", Version: "1.1.1"}},
	}

	if err := reportToBackend(t.Context(), srv.URL, "test-api-key", report); err != nil {
		t.Fatalf("reportToBackend: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/scan-reports" {
		t.Errorf("path = %q, want /v1/scan-reports", gotPath)
	}
	if gotAuth != "Bearer test-api-key" {
		t.Errorf("Authorization = %q, want \"Bearer test-api-key\"", gotAuth)
	}
	if gotBody.Host.Hostname != "test-host" || len(gotBody.Packages) != 1 {
		t.Errorf("server received unexpected body: %+v", gotBody)
	}
}

func TestReportToBackend_RejectedByServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid or revoked API key", http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := reportToBackend(t.Context(), srv.URL, "bad-key", model.ScanReport{})
	if err == nil {
		t.Fatal("expected an error when the backend rejects the report, got nil")
	}
}

func TestReportToBackend_UnreachableServer(t *testing.T) {
	// A server that immediately closes the connection, rather than a
	// made-up URL — keeps this hermetic (no real DNS/network lookup) while
	// still exercising the actual "server unreachable" error path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter doesn't support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijacking connection: %v", err)
		}
		conn.Close()
	}))
	defer srv.Close()

	err := reportToBackend(t.Context(), srv.URL, "test-api-key", model.ScanReport{})
	if err == nil {
		t.Fatal("expected an error when the connection is dropped, got nil")
	}
}
