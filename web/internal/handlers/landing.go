package handlers

import (
	"errors"
	"log"
	"net/http"
	"net/mail"
	"strings"

	"kepler/web/internal/templates"
	"kepler/web/internal/waitlist"
)

type landingPage struct {
	Status string
}

// Landing renders the marketing page. Status is read from a query param
// set by Waitlist's redirect (POST-redirect-GET) — the template only ever
// compares it against a fixed set of known values, never renders it as
// text, so there's nothing to sanitize even though it's user-reachable.
func Landing() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := landingPage{Status: r.URL.Query().Get("status")}
		if err := templates.Landing.Execute(w, data); err != nil {
			log.Printf("rendering landing template: %v", err)
		}
	}
}

// Waitlist handles the signup form. No JS: a plain POST, redirecting back
// to the landing page with a status so a page refresh can't resubmit.
func Waitlist(st *waitlist.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/?status=invalid", http.StatusSeeOther)
			return
		}

		// Honeypot: a field hidden from real users via CSS, that a
		// naive bot filling in every field will populate. If it's set,
		// pretend success rather than confirming to the bot that this
		// field is being checked.
		if r.FormValue("company_website") != "" {
			http.Redirect(w, r, "/?status=success", http.StatusSeeOther)
			return
		}

		email := strings.TrimSpace(r.FormValue("email"))
		if _, err := mail.ParseAddress(email); err != nil {
			http.Redirect(w, r, "/?status=invalid", http.StatusSeeOther)
			return
		}

		err := st.Signup(r.Context(), email)
		switch {
		case err == nil:
			http.Redirect(w, r, "/?status=success", http.StatusSeeOther)
		case errors.Is(err, waitlist.ErrAlreadySignedUp):
			http.Redirect(w, r, "/?status=duplicate", http.StatusSeeOther)
		default:
			log.Printf("waitlist signup: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}
}
