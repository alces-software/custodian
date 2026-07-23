package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AccessKey is a client-held capability secret (raw secret never stored).
type AccessKey struct {
	ID          uuid.UUID
	KeyHash     string
	Description string
	CreatedAt   time.Time
	CreatedBy   string
	RevokedAt   *time.Time
	CertCount   int // populated on list when requested
}

// ErrRevoked is returned when an access key exists but is revoked.
var ErrRevoked = errors.New("access key revoked")

// ErrConflict is returned when registration conflicts with a revoked key.
var ErrConflict = errors.New("conflict")

const (
	minAccessKeyLen     = 16
	maxDescriptionRunes = 500
)

// HashAccessKey returns hex SHA-256 of the raw access key.
func HashAccessKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ValidateAccessKeySecret checks length of a client-supplied secret.
func ValidateAccessKeySecret(raw string) error {
	raw = strings.TrimSpace(raw)
	if len(raw) < minAccessKeyLen {
		return fmt.Errorf("access_key must be at least %d characters", minAccessKeyLen)
	}
	return nil
}

// NormalizeDescription trims and caps description length.
func NormalizeDescription(desc string) string {
	desc = strings.TrimSpace(desc)
	if utf8.RuneCountInString(desc) <= maxDescriptionRunes {
		return desc
	}
	runes := []rune(desc)
	return string(runes[:maxDescriptionRunes])
}

// RegisterAccessKey creates or returns an existing active access key (idempotent).
// If the key is revoked, returns ErrConflict.
// If created is false and description is non-empty, updates description.
func (s *Store) RegisterAccessKey(ctx context.Context, rawKey, description, createdBy string) (*AccessKey, bool, error) {
	if err := ValidateAccessKeySecret(rawKey); err != nil {
		return nil, false, err
	}
	description = NormalizeDescription(description)
	hash := HashAccessKey(strings.TrimSpace(rawKey))

	existing, err := s.GetAccessKeyByHash(ctx, hash, false)
	if err == nil {
		if existing.RevokedAt != nil {
			return nil, false, ErrConflict
		}
		if description != "" && description != existing.Description {
			_ = s.UpdateAccessKeyDescription(ctx, existing.ID, description)
			existing.Description = description
		}
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO access_keys (key_hash, description, created_by)
		VALUES ($1, $2, $3)
		RETURNING id, key_hash, description, created_at, created_by, revoked_at`,
		hash, description, createdBy)
	ak, err := scanAccessKey(row)
	if err != nil {
		// race: unique violation → re-fetch
		if existing, err2 := s.GetAccessKeyByHash(ctx, hash, false); err2 == nil {
			if existing.RevokedAt != nil {
				return nil, false, ErrConflict
			}
			return existing, false, nil
		}
		return nil, false, err
	}
	return ak, true, nil
}

// GetAccessKeyByHash looks up by hash. If activeOnly, revoked rows return ErrNotFound.
func (s *Store) GetAccessKeyByHash(ctx context.Context, hash string, activeOnly bool) (*AccessKey, error) {
	q := `
		SELECT id, key_hash, description, created_at, created_by, revoked_at
		FROM access_keys WHERE key_hash = $1`
	if activeOnly {
		q += ` AND revoked_at IS NULL`
	}
	row := s.pool.QueryRow(ctx, q, hash)
	ak, err := scanAccessKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return ak, err
}

// GetAccessKeyByID returns metadata by id.
func (s *Store) GetAccessKeyByID(ctx context.Context, id uuid.UUID) (*AccessKey, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, key_hash, description, created_at, created_by, revoked_at
		FROM access_keys WHERE id = $1`, id)
	ak, err := scanAccessKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return ak, err
}

// GetActiveAccessKeyByID returns a non-revoked key by id.
func (s *Store) GetActiveAccessKeyByID(ctx context.Context, id uuid.UUID) (*AccessKey, error) {
	ak, err := s.GetAccessKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if ak.RevokedAt != nil {
		return nil, ErrRevoked
	}
	return ak, nil
}

// ListAccessKeys returns all keys with certificate counts (admin).
func (s *Store) ListAccessKeys(ctx context.Context) ([]AccessKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.key_hash, a.description, a.created_at, a.created_by, a.revoked_at,
		       (SELECT COUNT(*) FROM certificates c
		        WHERE c.access_key_id = a.id AND c.status != $1)::int
		FROM access_keys a
		ORDER BY a.created_at DESC`, StatusDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessKey
	for rows.Next() {
		var ak AccessKey
		var revoked *time.Time
		if err := rows.Scan(&ak.ID, &ak.KeyHash, &ak.Description, &ak.CreatedAt, &ak.CreatedBy, &revoked, &ak.CertCount); err != nil {
			return nil, err
		}
		ak.RevokedAt = revoked
		out = append(out, ak)
	}
	return out, rows.Err()
}

// UpdateAccessKeyDescription sets description.
func (s *Store) UpdateAccessKeyDescription(ctx context.Context, id uuid.UUID, description string) error {
	description = NormalizeDescription(description)
	_, err := s.pool.Exec(ctx, `UPDATE access_keys SET description = $2 WHERE id = $1`, id, description)
	return err
}

// RevokeAccessKey soft-revokes a key (idempotent).
func (s *Store) RevokeAccessKey(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE access_keys SET revoked_at = COALESCE(revoked_at, now())
		WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanAccessKey(row scannable) (*AccessKey, error) {
	var ak AccessKey
	var revoked *time.Time
	err := row.Scan(&ak.ID, &ak.KeyHash, &ak.Description, &ak.CreatedAt, &ak.CreatedBy, &revoked)
	if err != nil {
		return nil, err
	}
	ak.RevokedAt = revoked
	return &ak, nil
}
