package api

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
)

func insecureTransport() http.RoundTripper {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}

// spaHandler serves a built single-page-app's static files, falling back
// to index.html for any path that isn't a real file on disk — standard
// SPA routing support, since the frontend's own router (not the server)
// decides what "/dashboard" or "/login" mean.
//
// distDir is a plain directory on disk, not a go:embed'd tree: the
// frontend lives in a separate top-level module (frontend/) that Go's
// embed can't reach across (embed paths can't cross a module boundary),
// and decoupling the two build steps — build the frontend whenever,
// point kepler-landing at wherever it landed — is simpler than wiring up
// a copy-then-embed step just to avoid a runtime directory flag.
func spaHandler(distDir string) http.Handler {
	fileServer := http.FileServer(http.Dir(distDir))
	indexPath := filepath.Join(distDir, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join(distDir, filepath.Clean(r.URL.Path))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, indexPath)
	})
}

// dashboardAPIProxy reverse-proxies /api/* to kepler-web's dashboard API —
// the production equivalent of the frontend's own Vite dev-server proxy
// (see frontend/vite.config.ts), so the SPA can always call relative
// `/api/...` paths regardless of whether it's running against Vite's dev
// server or this handler. Keeping the proxy in Go rather than requiring
// browser-side CORS means kepler-web's auth model (Basic Auth, credentials
// attached by the SPA itself) doesn't need any cross-origin carve-out.
//
// insecureSkipVerify exists for local development against kepler-web's
// self-signed dev cert — same explicit, logged-warning override pattern as
// every other insecure-* flag in this codebase. Never set in production.
func dashboardAPIProxy(targetURL string, insecureSkipVerify bool) (http.Handler, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	if insecureSkipVerify {
		log.Println("WARNING: proxying /api to the dashboard backend with TLS verification disabled — local development only.")
		proxy.Transport = insecureTransport()
	}
	return proxy, nil
}
