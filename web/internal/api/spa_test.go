package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kepler/web/internal/waitlist"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating dir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestSPAHandler_ServesRealFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<html>index</html>")
	writeFile(t, filepath.Join(dir, "assets", "app.js"), "console.log('hi')")

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	rec := httptest.NewRecorder()
	spaHandler(dir).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	if rec.Body.String() != "console.log('hi')" {
		t.Errorf("served wrong content: %q", rec.Body.String())
	}
}

func TestSPAHandler_FallsBackToIndexForClientRoutes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<html>spa shell</html>")

	// /dashboard isn't a real file — the frontend's own router handles it
	// client-side, so the server must still return index.html, not 404.
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	spaHandler(dir).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	if rec.Body.String() != "<html>spa shell</html>" {
		t.Errorf("expected index.html fallback, got: %q", rec.Body.String())
	}
}

func TestDashboardAPIProxy_ForwardsRequests(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	proxy, err := dashboardAPIProxy(upstream.URL, false)
	if err != nil {
		t.Fatalf("dashboardAPIProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "proxied" {
		t.Errorf("proxy didn't forward correctly: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if gotPath != "/api/findings" {
		t.Errorf("upstream saw path %q, want /api/findings", gotPath)
	}
}

func TestNewLandingServer_NoFrontendServesPlainTemplate(t *testing.T) {
	// No real waitlist store needed — this path never touches it.
	handler, err := NewLandingServer(&waitlist.Store{}, LandingOptions{})
	if err != nil {
		t.Fatalf("NewLandingServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	if !contains(rec.Body.String(), "Kepler") {
		t.Error("expected the plain landing template to render")
	}
}

func TestNewLandingServer_ServesSPAWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<html>spa</html>")

	handler, err := NewLandingServer(&waitlist.Store{}, LandingOptions{FrontendDistDir: dir})
	if err != nil {
		t.Fatalf("NewLandingServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "<html>spa</html>" {
		t.Errorf("expected the SPA shell to render, got status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestNewLandingServer_RejectsMalformedDashboardURL(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<html>spa</html>")

	_, err := NewLandingServer(&waitlist.Store{}, LandingOptions{
		FrontendDistDir: dir,
		DashboardAPIURL: "://not-a-url",
	})
	if err == nil {
		t.Fatal("expected an error for a malformed KEPLER_DASHBOARD_API_URL, got nil")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
