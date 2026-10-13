// Package web_test is not a real test — it's a compile-time tripwire for
// ARCHITECTURE.md's module-responsibility table. It references every
// symbol that table lists for this module, so renaming or removing one of
// them fails the build here instead of the doc silently going stale. See
// ARCHITECTURE.md's "Keeping this honest" section for why this exists per
// module rather than as one whole-repo version of the same check.
package web_test

import (
	"context"
	"html/template"
	"net/http"
	"testing"

	"kepler/web/internal/api"
	"kepler/web/internal/auth"
	"kepler/web/internal/handlers"
	"kepler/web/internal/store"
	"kepler/web/internal/templates"
	"kepler/web/internal/waitlist"
)

func TestArchitectureDoc_Web(t *testing.T) {
	// internal/api — NewServer, NewLandingServer.
	var (
		_ func(*store.Store, string, string) http.Handler                 = api.NewServer
		_ func(*waitlist.Store, api.LandingOptions) (http.Handler, error) = api.NewLandingServer
	)

	// internal/auth — RequireBasicAuth.
	var _ func(string, string, http.Handler) http.Handler = auth.RequireBasicAuth

	// internal/store — Open, ListFindings, ListHostnames.
	var _ func(context.Context, string) (*store.Store, error) = store.Open
	var st *store.Store
	_ = func() {
		_, _ = st.ListFindings(context.Background(), store.FindingFilter{})
		_, _ = st.ListHostnames(context.Background())
	}

	// internal/waitlist — Open, Signup, ErrAlreadySignedUp.
	var _ func(context.Context, string) (*waitlist.Store, error) = waitlist.Open
	var wst *waitlist.Store
	_ = func() { _ = wst.Signup(context.Background(), "") }
	_ = waitlist.ErrAlreadySignedUp

	// internal/handlers — Findings, FindingsAPI, Waitlist, Landing.
	var (
		_ func(*store.Store) http.HandlerFunc    = handlers.Findings
		_ func(*store.Store) http.HandlerFunc    = handlers.FindingsAPI
		_ func(*waitlist.Store) http.HandlerFunc = handlers.Waitlist
		_ func() http.HandlerFunc                = handlers.Landing
	)

	// internal/templates — Findings, Landing.
	var _ *template.Template = templates.Findings
	var _ *template.Template = templates.Landing
}
