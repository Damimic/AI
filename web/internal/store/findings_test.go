package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// testStore connects to a real local Postgres for integration testing,
// same convention as the backend module: skipped if KEPLER_TEST_DB_URL
// isn't set, since these tests verify real SQL, not a mock.
func testStore(t *testing.T) *Store {
	t.Helper()
	dbURL := os.Getenv("KEPLER_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("KEPLER_TEST_DB_URL not set; run `docker compose up -d` in backend/ and set it to enable store tests")
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

func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating random suffix: %v", err)
	}
	return hex.EncodeToString(buf)
}

// seedFinding inserts a host, an ingestion, and one finding directly via
// SQL — this package is read-only by design (writes belong to the backend
// module), so tests seed data themselves rather than through the package's
// own API.
func seedFinding(t *testing.T, st *Store, hostname, pkg, version, cveID, severity, fixedVersion string) {
	t.Helper()
	ctx := context.Background()

	var hostID, ingestionID string
	if err := st.pool.QueryRow(ctx, `INSERT INTO hosts (hostname) VALUES ($1) RETURNING id`, hostname).Scan(&hostID); err != nil {
		t.Fatalf("seeding host: %v", err)
	}
	if err := st.pool.QueryRow(ctx, `INSERT INTO ingestions (host_id) VALUES ($1) RETURNING id`, hostID).Scan(&ingestionID); err != nil {
		t.Fatalf("seeding ingestion: %v", err)
	}
	_, err := st.pool.Exec(ctx,
		`INSERT INTO findings (ingestion_id, host_id, package, version, cve_id, severity, fixed_version)
		 VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))`,
		ingestionID, hostID, pkg, version, cveID, severity, fixedVersion,
	)
	if err != nil {
		t.Fatalf("seeding finding: %v", err)
	}
}

func TestListFindings_Unfiltered(t *testing.T) {
	st := testStore(t)
	hostname := "test-host-" + randomSuffix(t)
	seedFinding(t, st, hostname, "libssl3", "3.0.2-0ubuntu1.1", "CVE-2022-3786", "HIGH", "3.0.2-0ubuntu1.7")

	findings, err := st.ListFindings(context.Background(), FindingFilter{})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Host == hostname && f.CVEID == "CVE-2022-3786" {
			found = true
			if f.Severity != "HIGH" || f.FixedVersion != "3.0.2-0ubuntu1.7" {
				t.Errorf("finding fields wrong: %+v", f)
			}
		}
	}
	if !found {
		t.Error("seeded finding not present in unfiltered ListFindings result")
	}
}

func TestListFindings_FilterByHost(t *testing.T) {
	st := testStore(t)
	hostA := "test-host-a-" + randomSuffix(t)
	hostB := "test-host-b-" + randomSuffix(t)
	seedFinding(t, st, hostA, "libssl3", "1.0", "CVE-AAAA", "LOW", "")
	seedFinding(t, st, hostB, "libssl3", "1.0", "CVE-BBBB", "LOW", "")

	findings, err := st.ListFindings(context.Background(), FindingFilter{Host: hostA})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	for _, f := range findings {
		if f.Host != hostA {
			t.Errorf("filtering by host=%s returned a finding for host %s", hostA, f.Host)
		}
	}
	if len(findings) != 1 || findings[0].CVEID != "CVE-AAAA" {
		t.Errorf("expected exactly the one finding for %s, got %+v", hostA, findings)
	}
}

func TestListFindings_FilterBySeverity(t *testing.T) {
	st := testStore(t)
	hostname := "test-host-" + randomSuffix(t)
	seedFinding(t, st, hostname, "pkg-a", "1.0", "CVE-HIGH1", "HIGH", "")
	seedFinding(t, st, hostname, "pkg-b", "1.0", "CVE-LOW1", "LOW", "")

	findings, err := st.ListFindings(context.Background(), FindingFilter{Host: hostname, Severity: "HIGH"})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].CVEID != "CVE-HIGH1" {
		t.Errorf("expected only the HIGH finding, got %+v", findings)
	}
}

func TestListFindings_OrderedBySeverity(t *testing.T) {
	st := testStore(t)
	hostname := "test-host-" + randomSuffix(t)
	seedFinding(t, st, hostname, "pkg-low", "1.0", "CVE-ORD-LOW", "LOW", "")
	seedFinding(t, st, hostname, "pkg-crit", "1.0", "CVE-ORD-CRIT", "CRITICAL", "")
	seedFinding(t, st, hostname, "pkg-med", "1.0", "CVE-ORD-MED", "MEDIUM", "")

	findings, err := st.ListFindings(context.Background(), FindingFilter{Host: hostname})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	if findings[0].Severity != "CRITICAL" || findings[1].Severity != "MEDIUM" || findings[2].Severity != "LOW" {
		t.Errorf("findings not ordered by severity rank: %+v", findings)
	}
}

func TestListHostnames(t *testing.T) {
	st := testStore(t)
	hostname := "test-host-" + randomSuffix(t)
	seedFinding(t, st, hostname, "pkg", "1.0", "CVE-X", "LOW", "")

	hostnames, err := st.ListHostnames(context.Background())
	if err != nil {
		t.Fatalf("ListHostnames: %v", err)
	}
	found := false
	for _, h := range hostnames {
		if h == hostname {
			found = true
		}
	}
	if !found {
		t.Errorf("seeded host %s not present in ListHostnames result", hostname)
	}
}
