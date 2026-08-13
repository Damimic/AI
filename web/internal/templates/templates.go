// Package templates embeds and parses the dashboard and marketing site's
// HTML templates.
//
// Deliberately html/template, not text/template: html/template
// context-aware-escapes every value it renders, which matters here because
// finding data (package names, versions) ultimately originates from
// package metadata on scanned hosts — data Kepler doesn't control and
// shouldn't trust as pre-sanitized.
package templates

import (
	"embed"
	"html/template"
)

//go:embed *.tmpl
var files embed.FS

var Findings = template.Must(template.ParseFS(files, "findings.html.tmpl"))
var Landing = template.Must(template.ParseFS(files, "landing.html.tmpl"))
