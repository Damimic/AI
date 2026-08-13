// Package integration proves the actual v1 promise end to end: a findings
// payload shaped like kepler-matcher's real output, ingested by a real
// kepler-backend binary over authenticated HTTPS, stored in Postgres, and
// rendered by a real kepler-web binary's dashboard.
//
// It deliberately drives compiled binaries as subprocesses over real TCP
// connections, not in-process function calls — that's the only way to
// actually exercise the TLS handshake, Basic Auth over the wire, and the
// process boundary between the two services, rather than assuming they
// compose correctly because their unit tests pass in isolation.
//
// This module has no dependency on backend/web's internal packages (Go
// doesn't allow importing another module's internal/ packages anyway); the
// JSON request/response shapes below are a deliberate second copy of the
// wire contract, not a shared type — see backend/internal/model's own
// comment on why the JSON contract, not a shared Go type, is what agent and
// backend actually agree on.
//
// Skipped cleanly if KEPLER_TEST_DB_URL isn't set, same convention as
// backend and web's own store tests.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type findingInput struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	CVEID        string `json:"cve_id"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

type ingestRequest struct {
	Findings []findingInput `json:"findings"`
}

type ingestResponse struct {
	IngestionID string `json:"ingestion_id"`
	Stored      int    `json:"stored"`
}

func TestEndToEnd(t *testing.T) {
	baseDBURL := os.Getenv("KEPLER_TEST_DB_URL")
	if baseDBURL == "" {
		t.Skip("KEPLER_TEST_DB_URL not set; run `docker compose up -d` in backend/ and set it to enable the end-to-end test")
	}
	ctx := context.Background()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	backendDir := filepath.Join(repoRoot, "backend")
	webDir := filepath.Join(repoRoot, "web")
	schemaPath := filepath.Join(backendDir, "db", "schema.sql")

	dbName := fmt.Sprintf("kepler_it_%d", time.Now().UnixNano())
	testDBURL := createTestDatabase(t, ctx, baseDBURL, dbName, schemaPath)

	tmpDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, tmpDir)

	backendBin := buildBinary(t, backendDir, "kepler-backend", tmpDir)
	adminBin := buildBinary(t, backendDir, "kepler-backend-admin", tmpDir)
	webBin := buildBinary(t, webDir, "kepler-web", tmpDir)
	webAdminBin := buildBinary(t, webDir, "kepler-web-admin", tmpDir)

	backendAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   10 * time.Second,
	}

	// --- backend: ingest a real findings payload over authenticated HTTPS ---

	startProcess(t, "kepler-backend", backendBin, nil, []string{
		"KEPLER_DB_URL=" + testDBURL,
		"KEPLER_TLS_CERT=" + certPath,
		"KEPLER_TLS_KEY=" + keyPath,
		"KEPLER_LISTEN_ADDR=" + backendAddr,
	})
	waitForTCP(t, backendAddr, 10*time.Second)

	hostname := "it-test-host"
	apiKey := createHost(t, adminBin, testDBURL, hostname)

	findings := []findingInput{
		{Package: "openssl", Version: "1.1.1", CVEID: "CVE-2023-99999", Severity: "CRITICAL", FixedVersion: "1.1.1a"},
		{Package: "curl", Version: "7.68.0", CVEID: "CVE-2023-88888", Severity: "MEDIUM"},
	}
	body, err := json.Marshal(ingestRequest{Findings: findings})
	if err != nil {
		t.Fatalf("marshaling findings: %v", err)
	}

	ingestResp := postFindings(t, client, backendAddr, apiKey, body)
	if ingestResp.Stored != len(findings) {
		t.Errorf("ingest: expected %d stored, got %d", len(findings), ingestResp.Stored)
	}

	// An unauthenticated ingestion request must be rejected — the whole
	// point of API-key auth is that this endpoint isn't open.
	unauthReq, err := http.NewRequest(http.MethodPost, "https://"+backendAddr+"/v1/findings", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building unauthenticated request: %v", err)
	}
	unauthResp, err := client.Do(unauthReq)
	if err != nil {
		t.Fatalf("posting without auth: %v", err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ingest without API key: expected 401, got %d", unauthResp.StatusCode)
	}

	// --- web: the dashboard must render exactly what was just ingested ---

	dashboardUser := "operator"
	dashboardPassword := "it-test-operator-password"
	passwordHash := hashPassword(t, webAdminBin, dashboardPassword)

	startProcess(t, "kepler-web", webBin, nil, []string{
		"KEPLER_DB_URL=" + testDBURL,
		"KEPLER_DASHBOARD_USER=" + dashboardUser,
		"KEPLER_DASHBOARD_PASSWORD_HASH=" + passwordHash,
		"KEPLER_TLS_CERT=" + certPath,
		"KEPLER_TLS_KEY=" + keyPath,
		"KEPLER_LISTEN_ADDR=" + webAddr,
	})
	waitForTCP(t, webAddr, 10*time.Second)

	dashReq, err := http.NewRequest(http.MethodGet, "https://"+webAddr+"/?host="+hostname, nil)
	if err != nil {
		t.Fatalf("building dashboard request: %v", err)
	}
	dashReq.SetBasicAuth(dashboardUser, dashboardPassword)
	dashResp, err := client.Do(dashReq)
	if err != nil {
		t.Fatalf("fetching dashboard: %v", err)
	}
	defer dashResp.Body.Close()
	dashBody, err := io.ReadAll(dashResp.Body)
	if err != nil {
		t.Fatalf("reading dashboard body: %v", err)
	}
	if dashResp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard: expected 200, got %d: %s", dashResp.StatusCode, dashBody)
	}

	page := string(dashBody)
	for _, want := range []string{"openssl", "CVE-2023-99999", "CRITICAL", "curl", "CVE-2023-88888", "MEDIUM"} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard page missing %q", want)
		}
	}

	// The dashboard must refuse to render anything without the operator
	// credential — findings are security-sensitive data.
	noAuthReq, err := http.NewRequest(http.MethodGet, "https://"+webAddr+"/", nil)
	if err != nil {
		t.Fatalf("building unauthenticated dashboard request: %v", err)
	}
	noAuthResp, err := client.Do(noAuthReq)
	if err != nil {
		t.Fatalf("fetching dashboard without auth: %v", err)
	}
	noAuthResp.Body.Close()
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("dashboard without credentials: expected 401, got %d", noAuthResp.StatusCode)
	}
}

func postFindings(t *testing.T, client *http.Client, backendAddr, apiKey string, body []byte) ingestResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+backendAddr+"/v1/findings", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building ingest request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("posting findings: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading ingest response: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("ingest: expected 201, got %d: %s", resp.StatusCode, respBody)
	}

	var ingestResp ingestResponse
	if err := json.Unmarshal(respBody, &ingestResp); err != nil {
		t.Fatalf("decoding ingest response: %v (body: %s)", err, respBody)
	}
	return ingestResp
}

// createTestDatabase creates a fresh, uniquely-named database on the same
// Postgres instance KEPLER_TEST_DB_URL points at, applies the backend
// schema to it, and registers a cleanup to drop it — so this test never
// collides with or pollutes data from backend/web's own store tests
// running against the same instance.
func createTestDatabase(t *testing.T, ctx context.Context, baseDBURL, dbName, schemaPath string) string {
	t.Helper()

	// CREATE DATABASE cannot run as a prepared statement — force the
	// simple query protocol for this connection.
	adminCfg, err := pgx.ParseConfig(baseDBURL)
	if err != nil {
		t.Fatalf("parsing KEPLER_TEST_DB_URL: %v", err)
	}
	adminCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	adminConn, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("connecting to set up test database: %v", err)
	}
	defer adminConn.Close(ctx)

	if _, err := adminConn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("creating test database %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		dctx := context.Background()
		cfg, err := pgx.ParseConfig(baseDBURL)
		if err != nil {
			t.Logf("cleanup: parsing db URL: %v", err)
			return
		}
		cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		dropConn, err := pgx.ConnectConfig(dctx, cfg)
		if err != nil {
			t.Logf("cleanup: connecting to drop test database %s: %v", dbName, err)
			return
		}
		defer dropConn.Close(dctx)
		if _, err := dropConn.Exec(dctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("cleanup: dropping test database %s: %v", dbName, err)
		}
	})

	testURL := withDatabase(t, baseDBURL, dbName)

	testCfg, err := pgx.ParseConfig(testURL)
	if err != nil {
		t.Fatalf("parsing test database URL: %v", err)
	}
	testCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	testConn, err := pgx.ConnectConfig(ctx, testCfg)
	if err != nil {
		t.Fatalf("connecting to test database %s: %v", dbName, err)
	}
	defer testConn.Close(ctx)

	schemaSQL, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading schema %s: %v", schemaPath, err)
	}
	if _, err := testConn.Exec(ctx, string(schemaSQL)); err != nil {
		t.Fatalf("applying schema to %s: %v", dbName, err)
	}

	return testURL
}

func withDatabase(t *testing.T, rawURL, dbName string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing db URL: %v", err)
	}
	u.Path = "/" + dbName
	return u.String()
}

// buildBinary compiles cmdName from moduleDir's ./cmd/<cmdName> package
// into outDir, using the real go build a developer or CI would run — this
// test exercises the actual compiled artifact, not a package imported
// in-process.
func buildBinary(t *testing.T, moduleDir, cmdName, outDir string) string {
	t.Helper()
	outPath := filepath.Join(outDir, cmdName)
	cmd := exec.Command("go", "build", "-o", outPath, "./cmd/"+cmdName)
	cmd.Dir = moduleDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", cmdName, err, out)
	}
	return outPath
}

// startProcess starts binPath as a subprocess with the given extra env
// vars appended to the current environment, and registers a cleanup that
// kills it and (on test failure) logs its combined output for debugging.
func startProcess(t *testing.T, name, binPath string, stdin io.Reader, extraEnv []string) {
	t.Helper()
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = stdin
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", name, err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		if t.Failed() {
			t.Logf("%s output:\n%s", name, out.String())
		}
	})
}

// createHost runs kepler-backend-admin as a one-shot subprocess and parses
// the API key it prints, the same way a real operator would provision a
// host.
func createHost(t *testing.T, adminBin, dbURL, hostname string) string {
	t.Helper()
	cmd := exec.Command(adminBin, "create-host", hostname)
	cmd.Env = append(os.Environ(), "KEPLER_DB_URL="+dbURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kepler-backend-admin create-host: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if key, ok := strings.CutPrefix(line, "api_key: "); ok {
			return strings.TrimSpace(key)
		}
	}
	t.Fatalf("no api_key line in kepler-backend-admin output:\n%s", out)
	return ""
}

// hashPassword runs kepler-web-admin as a one-shot subprocess and returns
// the bcrypt hash it prints, the same way a real operator would generate
// KEPLER_DASHBOARD_PASSWORD_HASH.
func hashPassword(t *testing.T, webAdminBin, password string) string {
	t.Helper()
	cmd := exec.Command(webAdminBin, "hash-password")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kepler-web-admin hash-password: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// freePort asks the OS for an unused TCP port. There's an inherent small
// race between closing this listener and the child process binding the
// port, but that's the standard pattern for test-local port allocation and
// collisions are effectively negligible for a single test process.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocating free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to accept connections", addr)
}

// generateSelfSignedCert writes a throwaway self-signed cert/key pair to
// dir, valid for localhost and 127.0.0.1 only. Generated on the fly (not
// backend/dev-certs, which is gitignored and may not exist) so this test
// is self-contained and needs no manual setup step beyond a running
// Postgres.
func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating TLS key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating cert serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPath = filepath.Join(dir, "test.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
	certOut.Close()

	keyPath = filepath.Join(dir, "test.key")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	keyOut.Close()

	return certPath, keyPath
}
