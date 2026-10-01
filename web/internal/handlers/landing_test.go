package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"kepler/web/internal/waitlist"
)

// randomSuffix avoids email collisions between test runs, same convention
// as every other test in this codebase — these tests don't clean up after
// themselves (see web/internal/store/findings_test.go's own comment on
// why), so a fixed, deterministic email would collide with a prior run's
// leftover row in the shared test database and fail nondeterministically
// depending on what ran before it.
func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating random suffix: %v", err)
	}
	return hex.EncodeToString(buf)
}

func testWaitlistStore(t *testing.T) *waitlist.Store {
	t.Helper()
	dbURL := os.Getenv("KEPLER_TEST_MARKETING_DB_URL")
	if dbURL == "" {
		t.Skip("KEPLER_TEST_MARKETING_DB_URL not set; enable this the same way as internal/waitlist's tests")
	}
	st, err := waitlist.Open(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func postForm(t *testing.T, handler http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/waitlist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestWaitlist_ValidEmail(t *testing.T) {
	st := testWaitlistStore(t)
	handler := Waitlist(st)

	rec := postForm(t, handler, url.Values{"email": {"new-signup-" + randomSuffix(t) + "@example.com"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/?status=success" {
		t.Errorf("got redirect %q, want /?status=success", loc)
	}
}

func TestWaitlist_DuplicateEmail(t *testing.T) {
	st := testWaitlistStore(t)
	handler := Waitlist(st)
	email := "dup-" + t.Name() + "@example.com"

	postForm(t, handler, url.Values{"email": {email}})
	rec := postForm(t, handler, url.Values{"email": {email}})

	if loc := rec.Header().Get("Location"); loc != "/?status=duplicate" {
		t.Errorf("got redirect %q, want /?status=duplicate", loc)
	}
}

func TestWaitlist_InvalidEmail(t *testing.T) {
	st := testWaitlistStore(t)
	handler := Waitlist(st)

	rec := postForm(t, handler, url.Values{"email": {"not-an-email"}})

	if loc := rec.Header().Get("Location"); loc != "/?status=invalid" {
		t.Errorf("got redirect %q, want /?status=invalid", loc)
	}
}

func TestWaitlist_Honeypot(t *testing.T) {
	st := testWaitlistStore(t)
	handler := Waitlist(st)
	email := "bot-" + randomSuffix(t) + "@example.com"

	rec := postForm(t, handler, url.Values{
		"email":           {email},
		"company_website": {"http://spam.example"},
	})

	// Pretends success so a bot doesn't learn the honeypot tripped it.
	if loc := rec.Header().Get("Location"); loc != "/?status=success" {
		t.Errorf("got redirect %q, want /?status=success", loc)
	}

	// The real assertion: nothing was actually inserted. If the honeypot
	// path had (incorrectly) written the row, this direct Signup would
	// fail with ErrAlreadySignedUp instead of succeeding.
	if err := st.Signup(context.Background(), email); err != nil {
		t.Errorf("expected honeypot submission to leave no row behind, but Signup for the same email failed: %v", err)
	}
}

func TestLanding_Renders(t *testing.T) {
	handler := Landing()

	for _, status := range []string{"", "success", "duplicate", "invalid", "garbage"} {
		req := httptest.NewRequest(http.MethodGet, "/?status="+status, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status=%q: got code %d, want 200", status, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Kepler") {
			t.Errorf("status=%q: rendered page doesn't mention Kepler", status)
		}
	}
}
