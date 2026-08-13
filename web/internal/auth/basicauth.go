// Package auth handles dashboard authentication: a single operator
// credential via HTTP Basic Auth. This is a deliberately minimal v1
// mechanism — no user accounts, no multi-tenancy — appropriate while
// there's no multi-user model yet (see backend's auth for the equivalent
// tradeoff on the agent-facing side). Revisit before this supports
// multiple real operators.
package auth

import (
	"crypto/subtle"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// RequireBasicAuth wraps a handler with HTTP Basic Auth, checked against a
// single configured username and bcrypt-hashed password. Unlike the
// backend's API keys (high-entropy random secrets, fast-hashed), this is a
// human-chosen password, so it uses bcrypt deliberately — a slow, salted
// hash is exactly what blunts brute-forcing a low-entropy secret.
func RequireBasicAuth(username, passwordHash string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 {
			unauthorized(w)
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(pass)) != nil {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Kepler Dashboard"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
