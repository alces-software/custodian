package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaFS embed.FS

// Status values for certificates.
const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusFailed  = "failed"
	StatusDeleted = "deleted"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store is the Postgres persistence layer.
type Store struct {
	pool *pgxpool.Pool
}

// LEAccount is a Let's Encrypt ACME account.
type LEAccount struct {
	ID              uuid.UUID
	Email           string
	PrivateKeyEnc   string
	RegistrationURI string
	DirectoryURL    string
	CreatedAt       time.Time
}

// Certificate is a managed TLS certificate.
type Certificate struct {
	ID             uuid.UUID
	CommonName     string
	SANs           []string
	Status         string
	PrivateKeyEnc  string
	CertificatePEM string
	ChainPEM       string
	NotBefore      *time.Time
	NotAfter       *time.Time
	Serial         string
	Issuer         string
	DNSZone        string
	AccessKeyID    *uuid.UUID
	ACMEOrderURL   string
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	RenewedAt      *time.Time
}

const certSelectCols = `
	id, common_name, sans, status, private_key_enc, certificate_pem, chain_pem,
	not_before, not_after, serial, issuer, dns_zone, access_key_id, acme_order_url, last_error,
	created_at, updated_at, renewed_at`

// New connects to Postgres and applies schema.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) migrate(ctx context.Context) error {
	sqlBytes, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, string(sqlBytes))
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// GetLEAccountByDirectory returns the LE account for a directory URL.
func (s *Store) GetLEAccountByDirectory(ctx context.Context, directoryURL string) (*LEAccount, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, email, private_key_enc, registration_uri, directory_url, created_at
		FROM le_accounts WHERE directory_url = $1`, directoryURL)
	var a LEAccount
	err := row.Scan(&a.ID, &a.Email, &a.PrivateKeyEnc, &a.RegistrationURI, &a.DirectoryURL, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpsertLEAccount inserts or updates the LE account for a directory.
func (s *Store) UpsertLEAccount(ctx context.Context, email, privateKeyEnc, registrationURI, directoryURL string) (*LEAccount, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO le_accounts (email, private_key_enc, registration_uri, directory_url)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (directory_url) DO UPDATE SET
			email = EXCLUDED.email,
			private_key_enc = EXCLUDED.private_key_enc,
			registration_uri = EXCLUDED.registration_uri
		RETURNING id, email, private_key_enc, registration_uri, directory_url, created_at`,
		email, privateKeyEnc, registrationURI, directoryURL)
	var a LEAccount
	if err := row.Scan(&a.ID, &a.Email, &a.PrivateKeyEnc, &a.RegistrationURI, &a.DirectoryURL, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateCertificate inserts a pending certificate row.
func (s *Store) CreateCertificate(ctx context.Context, cn string, sans []string, dnsZone string, accessKeyID uuid.UUID) (*Certificate, error) {
	if sans == nil {
		sans = []string{}
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO certificates (common_name, sans, status, dns_zone, access_key_id)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+certSelectCols,
		cn, sans, StatusPending, dnsZone, accessKeyID)
	return scanCert(row)
}

// GetCertificate returns a certificate by ID.
func (s *Store) GetCertificate(ctx context.Context, id uuid.UUID) (*Certificate, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+certSelectCols+` FROM certificates WHERE id = $1`, id)
	c, err := scanCert(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// FindActiveByNames finds an active cert with the same CN and SAN set.
func (s *Store) FindActiveByNames(ctx context.Context, cn string, sans []string) (*Certificate, error) {
	if sans == nil {
		sans = []string{}
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+certSelectCols+`
		FROM certificates
		WHERE status = $1 AND common_name = $2
		  AND sans @> $3::text[] AND $3::text[] @> sans
		ORDER BY not_after DESC NULLS LAST
		LIMIT 1`, StatusActive, cn, sans)
	c, err := scanCert(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ListCertificates returns non-deleted certificates, newest first.
func (s *Store) ListCertificates(ctx context.Context) ([]Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+certSelectCols+`
		FROM certificates
		WHERE status != $1
		ORDER BY created_at DESC`, StatusDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ListCertificatesByAccessKey returns non-deleted certs for one access key.
func (s *Store) ListCertificatesByAccessKey(ctx context.Context, accessKeyID uuid.UUID) ([]Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+certSelectCols+`
		FROM certificates
		WHERE status != $1 AND access_key_id = $2
		ORDER BY created_at DESC`, StatusDeleted, accessKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ListDueForRenewal returns active certs expiring within the window.
func (s *Store) ListDueForRenewal(ctx context.Context, before time.Time) ([]Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+certSelectCols+`
		FROM certificates
		WHERE status = $1 AND not_after IS NOT NULL AND not_after < $2
		ORDER BY not_after ASC`, StatusActive, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// SetDNSZone updates the stored Cloud DNS zone for a certificate.
func (s *Store) SetDNSZone(ctx context.Context, id uuid.UUID, zone string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificates SET dns_zone = $2, updated_at = now() WHERE id = $1`, id, zone)
	return err
}

// MarkFailed records an issuance/renewal failure.
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, lastError string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificates SET status = $2, last_error = $3, updated_at = now()
		WHERE id = $1`, id, StatusFailed, truncate(lastError, 2000))
	return err
}

// SaveIssued writes successful certificate material.
func (s *Store) SaveIssued(ctx context.Context, id uuid.UUID, privateKeyEnc, certPEM, chainPEM, serial, issuer string, notBefore, notAfter time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificates SET
			status = $2,
			private_key_enc = $3,
			certificate_pem = $4,
			chain_pem = $5,
			serial = $6,
			issuer = $7,
			not_before = $8,
			not_after = $9,
			last_error = NULL,
			updated_at = now(),
			renewed_at = now()
		WHERE id = $1`,
		id, StatusActive, privateKeyEnc, certPEM, chainPEM, serial, issuer, notBefore, notAfter)
	return err
}

// SoftDelete marks a certificate deleted.
func (s *Store) SoftDelete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE certificates SET status = $2, updated_at = now()
		WHERE id = $1 AND status != $2`, id, StatusDeleted)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// InsertAudit records an audit event.
func (s *Store) InsertAudit(ctx context.Context, action string, certID *uuid.UUID, actor, detail string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_events (action, certificate_id, actor, detail)
		VALUES ($1, $2, $3, $4)`, action, certID, actor, truncate(detail, 2000))
	return err
}

// TryAdvisoryLock attempts a session-level advisory lock. Unlock with UnlockAdvisory.
func (s *Store) TryAdvisoryLock(ctx context.Context, key int64) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok)
	return ok, err
}

// UnlockAdvisory releases a session advisory lock.
func (s *Store) UnlockAdvisory(ctx context.Context, key int64) error {
	_, err := s.pool.Exec(ctx, `SELECT pg_advisory_unlock($1)`, key)
	return err
}

// AcquireConnLock gets a dedicated connection and holds an advisory lock on it.
// Caller must call the returned unlock function.
func (s *Store) AcquireConnLock(ctx context.Context, key int64) (unlock func(), err error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		conn.Release()
		return nil, err
	}
	if !ok {
		conn.Release()
		return nil, fmt.Errorf("could not acquire lock")
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		conn.Release()
	}, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanCert(row scannable) (*Certificate, error) {
	var c Certificate
	var sans []string
	var priv, cert, chain, serial, issuer, dnsZone, orderURL, lastErr *string
	var accessKeyID *uuid.UUID
	err := row.Scan(
		&c.ID, &c.CommonName, &sans, &c.Status,
		&priv, &cert, &chain,
		&c.NotBefore, &c.NotAfter, &serial, &issuer, &dnsZone, &accessKeyID, &orderURL, &lastErr,
		&c.CreatedAt, &c.UpdatedAt, &c.RenewedAt,
	)
	if err != nil {
		return nil, err
	}
	c.SANs = sans
	if c.SANs == nil {
		c.SANs = []string{}
	}
	c.PrivateKeyEnc = deref(priv)
	c.CertificatePEM = deref(cert)
	c.ChainPEM = deref(chain)
	c.Serial = deref(serial)
	c.Issuer = deref(issuer)
	c.DNSZone = deref(dnsZone)
	c.AccessKeyID = accessKeyID
	c.ACMEOrderURL = deref(orderURL)
	c.LastError = deref(lastErr)
	return &c, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// NamesKey returns a stable string key for CN+SANs (for locking).
func NamesKey(cn string, sans []string) string {
	parts := append([]string{strings.ToLower(cn)}, sans...)
	return strings.Join(parts, ",")
}
