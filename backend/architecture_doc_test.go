// Package backend_test is not a real test — it's a compile-time tripwire
// for ARCHITECTURE.md's module-responsibility table. It references every
// symbol that table lists for this module, so renaming or removing one of
// them fails the build here instead of the doc silently going stale. See
// ARCHITECTURE.md's "Keeping this honest" section for why this exists per
// module rather than as one whole-repo version of the same check.
package backend_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"kepler/backend/internal/api"
	"kepler/backend/internal/auth"
	"kepler/backend/internal/model"
	"kepler/backend/internal/store"
)

func TestArchitectureDoc_Backend(t *testing.T) {
	// internal/api — NewServer.
	var _ func(*store.Store) http.Handler = api.NewServer

	// internal/auth — GenerateAPIKey, HashAPIKey.
	var (
		_ func() (string, string, error) = auth.GenerateAPIKey
		_ func(string) string            = auth.HashAPIKey
	)

	// internal/store — Open, CreateHost, CreateAPIKey, HostIDForKeyHash,
	// InsertFindings. Methods are referenced via a nil *Store value rather
	// than a method-expression var, which is simpler for a pointer-receiver
	// method set.
	var _ func(context.Context, string) (*store.Store, error) = store.Open
	var st *store.Store
	_ = func() {
		_, _ = st.CreateHost(context.Background(), "")
		_, _ = st.CreateAPIKey(context.Background(), uuid.UUID{}, "")
		_, _, _ = st.HostIDForKeyHash(context.Background(), "")
		_, _ = st.InsertFindings(context.Background(), uuid.UUID{}, nil)
	}

	// internal/model — the wire contract the table names.
	_ = model.FindingInput{}
	_ = model.IngestRequest{}
	_ = model.IngestResponse{}
}
