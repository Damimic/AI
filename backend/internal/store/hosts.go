package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// CreateHost registers a new host and returns its ID. hostname must be
// non-empty: web/internal/store's FindingFilter uses "" as its sentinel for
// "no filter on this dimension" (see FindingFilter.Host), so a host actually
// named "" would be indistinguishable from "all hosts" in the dashboard's
// filter — silently widening a filter meant to isolate one host's findings
// into showing every host's.
func (s *Store) CreateHost(ctx context.Context, hostname string) (uuid.UUID, error) {
	if strings.TrimSpace(hostname) == "" {
		return uuid.UUID{}, fmt.Errorf("hostname must not be empty")
	}

	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO hosts (hostname) VALUES ($1) RETURNING id`, hostname,
	).Scan(&id)
	return id, err
}
