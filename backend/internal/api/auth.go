package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"kepler/backend/internal/auth"
	"kepler/backend/internal/store"
)

type contextKey int

const hostIDContextKey contextKey = iota

// requireAPIKey resolves the host identity from the Authorization header
// and rejects the request if it's missing, malformed, or doesn't match a
// live (non-revoked) key. The resolved host ID is attached to the request
// context — handlers must use it, not anything from the request body, as
// the source of truth for which host a request is acting on.
func requireAPIKey(st *store.Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			http.Error(w, "missing or malformed Authorization header (expected: Bearer <api-key>)", http.StatusUnauthorized)
			return
		}

		hostID, found, err := st.HostIDForKeyHash(r.Context(), auth.HashAPIKey(raw))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "invalid or revoked API key", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), hostIDContextKey, hostID)
		next(w, r.WithContext(ctx))
	}
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if token == "" {
		return "", false
	}
	return token, true
}

func hostIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(hostIDContextKey).(uuid.UUID)
	return id, ok
}
