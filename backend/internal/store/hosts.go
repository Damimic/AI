package store

import (
	"context"

	"github.com/google/uuid"
)

// CreateHost registers a new host and returns its ID.
func (s *Store) CreateHost(ctx context.Context, hostname string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO hosts (hostname) VALUES ($1) RETURNING id`, hostname,
	).Scan(&id)
	return id, err
}
