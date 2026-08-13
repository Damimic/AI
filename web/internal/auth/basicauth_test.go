package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func testPasswordHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost) // MinCost: tests don't need real work factor
	if err != nil {
		t.Fatalf("hashing test password: %v", err)
	}
	return string(hash)
}

func TestRequireBasicAuth(t *testing.T) {
	passwordHash := testPasswordHash(t, "correct-horse-battery-staple")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireBasicAuth("operator", passwordHash, inner)

	cases := []struct {
		name       string
		setAuth    bool
		user, pass string
		wantStatus int
	}{
		{"no credentials", false, "", "", http.StatusUnauthorized},
		{"wrong username", true, "someone-else", "correct-horse-battery-staple", http.StatusUnauthorized},
		{"wrong password", true, "operator", "wrong-password", http.StatusUnauthorized},
		{"correct credentials", true, "operator", "correct-horse-battery-staple", http.StatusOK},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.setAuth {
				req.SetBasicAuth(c.user, c.pass)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, c.wantStatus)
			}
		})
	}
}
