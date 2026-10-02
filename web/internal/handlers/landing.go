package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"mime"
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

// Waitlist handles the signup form, in two flavors depending on the
// request's Content-Type: a plain form POST (no JS — redirects back to the
// landing page with a status, so a page refresh can't resubmit) or a JSON
// body (the frontend SPA — responds with a JSON status instead of a
// redirect). Same validation, same honeypot, same store call either way.
func Waitlist(st *waitlist.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isJSONRequest(r) {
			waitlistJSON(st, w, r)
			return
		}
		waitlistForm(st, w, r)
	}
}

func isJSONRequest(r *http.Request) bool {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && ct == "application/json"
}

func waitlistForm(st *waitlist.Store, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?status=invalid", http.StatusSeeOther)
		return
	}

	// Honeypot: a field hidden from real users via CSS, that a naive bot
	// filling in every field will populate. If it's set, pretend success
	// rather than confirming to the bot that this field is being checked.
	if r.FormValue("company_website") != "" {
		http.Redirect(w, r, "/?status=success", http.StatusSeeOther)
		return
	}

	// Lowercased so the same address in different casing (e.g. mobile
	// autocapitalization) dedupes against itself instead of silently
	// bypassing the unique-email constraint and ErrAlreadySignedUp check
	// below.
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
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

type waitlistJSONRequest struct {
	Email string `json:"email"`
	// CompanyWebsite is the honeypot, same field name and purpose as the
	// form's hidden input — a real frontend never sets this.
	CompanyWebsite string `json:"company_website,omitempty"`
}

type waitlistJSONResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func waitlistJSON(st *waitlist.Store, w http.ResponseWriter, r *http.Request) {
	var req waitlistJSONRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, waitlistJSONResponse{Status: "invalid", Message: "malformed request body"})
		return
	}

	if req.CompanyWebsite != "" {
		// Pretend success — same reasoning as the form path's honeypot.
		writeJSON(w, http.StatusCreated, waitlistJSONResponse{Status: "success"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if _, err := mail.ParseAddress(email); err != nil {
		writeJSON(w, http.StatusBadRequest, waitlistJSONResponse{Status: "invalid", Message: "not a valid email address"})
		return
	}

	err := st.Signup(r.Context(), email)
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, waitlistJSONResponse{Status: "success"})
	case errors.Is(err, waitlist.ErrAlreadySignedUp):
		writeJSON(w, http.StatusConflict, waitlistJSONResponse{Status: "duplicate", Message: "this email is already on the waitlist"})
	default:
		log.Printf("waitlist signup: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
