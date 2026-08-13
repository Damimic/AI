package store

import (
	"context"

	"kepler/web/internal/model"
)

// FindingFilter narrows ListFindings. An empty field means "no filter on
// that dimension" — always passed as a bound query parameter, never
// interpolated into the SQL string, regardless of whether it's empty.
type FindingFilter struct {
	Host     string
	Severity string
}

// ListFindings returns findings matching the filter, most severe and most
// recent first.
func (s *Store) ListFindings(ctx context.Context, filter FindingFilter) ([]model.Finding, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.hostname, f.package, f.version, f.cve_id, f.severity,
		       coalesce(f.fixed_version, ''), f.created_at
		FROM findings f
		JOIN hosts h ON h.id = f.host_id
		WHERE ($1 = '' OR h.hostname = $1)
		  AND ($2 = '' OR f.severity = $2)
		ORDER BY
		  CASE f.severity
		    WHEN 'CRITICAL' THEN 1
		    WHEN 'HIGH' THEN 2
		    WHEN 'MEDIUM' THEN 3
		    WHEN 'LOW' THEN 4
		    ELSE 5
		  END,
		  f.created_at DESC
	`, filter.Host, filter.Severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []model.Finding
	for rows.Next() {
		var f model.Finding
		if err := rows.Scan(&f.Host, &f.Package, &f.Version, &f.CVEID, &f.Severity, &f.FixedVersion, &f.ReportedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// ListHostnames returns all known hostnames, for populating the host
// filter control.
func (s *Store) ListHostnames(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT hostname FROM hosts ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hostnames []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hostnames = append(hostnames, h)
	}
	return hostnames, rows.Err()
}
