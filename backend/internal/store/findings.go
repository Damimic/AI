package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"kepler/backend/internal/model"
)

// InsertFindings records a batch of findings for a host as a single
// ingestion event, in one transaction: either the whole batch lands, or
// none of it does. Also refreshes the host's last_seen_at.
func (s *Store) InsertFindings(ctx context.Context, hostID uuid.UUID, findings []model.FindingInput) (ingestionID uuid.UUID, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.UUID{}, err
	}
	defer tx.Rollback(ctx) // no-op once committed

	if err := tx.QueryRow(ctx,
		`INSERT INTO ingestions (host_id) VALUES ($1) RETURNING id`, hostID,
	).Scan(&ingestionID); err != nil {
		return uuid.UUID{}, err
	}

	batch := &pgx.Batch{}
	for _, f := range findings {
		batch.Queue(
			`INSERT INTO findings (ingestion_id, host_id, package, version, cve_id, severity, fixed_version)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			ingestionID, hostID, f.Package, f.Version, f.CVEID, f.Severity, nullIfEmpty(f.FixedVersion),
		)
	}
	br := tx.SendBatch(ctx, batch)
	for range findings {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return uuid.UUID{}, err
		}
	}
	if err := br.Close(); err != nil {
		return uuid.UUID{}, err
	}

	if _, err := tx.Exec(ctx, `UPDATE hosts SET last_seen_at = now() WHERE id = $1`, hostID); err != nil {
		return uuid.UUID{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.UUID{}, err
	}
	return ingestionID, nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
