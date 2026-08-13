// Package waitlist is the marketing site's data access — deliberately its
// own store, its own package, and its own database (kepler_marketing, not
// the findings database). It has no import path to internal/store
// (findings) and never will: a compromised or abused public signup form
// should have no path to customer vulnerability data.
package waitlist

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAlreadySignedUp means the email is already on the list — not an
// error condition for the caller, just a fact worth distinguishing from a
// fresh signup so the response can say so.
var ErrAlreadySignedUp = errors.New("email already on waitlist")

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

// Signup records an email on the waitlist. Returns ErrAlreadySignedUp
// (not a hard error) if that email is already recorded.
func (s *Store) Signup(ctx context.Context, email string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO waitlist_signups (email) VALUES ($1)`, email)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return ErrAlreadySignedUp
		}
		return err
	}
	return nil
}
