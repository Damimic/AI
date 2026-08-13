package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateAPIKey stores a pre-hashed API key for a host. The raw key itself
// is never passed here and never stored — see internal/auth.
func (s *Store) CreateAPIKey(ctx context.Context, hostID uuid.UUID, keyHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO api_keys (host_id, key_hash) VALUES ($1, $2) RETURNING id`, hostID, keyHash,
	).Scan(&id)
	return id, err
}

// HostIDForKeyHash resolves the host that owns a non-revoked API key hash.
// ok is false (with a nil error) if the key doesn't exist or was revoked —
// callers should treat that as "unauthenticated", not a server error.
func (s *Store) HostIDForKeyHash(ctx context.Context, keyHash string) (hostID uuid.UUID, ok bool, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT host_id FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL`, keyHash,
	).Scan(&hostID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.UUID{}, false, nil
		}
		return uuid.UUID{}, false, err
	}
	return hostID, true, nil
}
