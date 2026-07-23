package acme

import (
	"context"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/google/uuid"

	"github.com/markt/custodian/internal/domains"
	sealer "github.com/markt/custodian/internal/crypto"
	"github.com/markt/custodian/internal/store"
)

// Service orchestrates allowlist checks, ACME issuance, and persistence.
type Service struct {
	store       *store.Store
	issuer      *Issuer
	box         *sealer.Box
	catalog     *domains.Catalog
	renewBefore time.Duration
}

// NewService builds the certificate service.
func NewService(st *store.Store, issuer *Issuer, box *sealer.Box, catalog *domains.Catalog, renewBeforeDays int) *Service {
	return &Service{
		store:       st,
		issuer:      issuer,
		box:         box,
		catalog:     catalog,
		renewBefore: time.Duration(renewBeforeDays) * 24 * time.Hour,
	}
}

// IssueRequest is the input for issuing a certificate.
type IssueRequest struct {
	CommonName  string
	SANs        []string
	Force       bool
	Actor       string
	AccessKeyID uuid.UUID
}

// Issue obtains a certificate (or returns an existing valid one unless Force).
func (s *Service) Issue(ctx context.Context, req IssueRequest) (*store.Certificate, bool, error) {
	if req.AccessKeyID == uuid.Nil {
		return nil, false, fmt.Errorf("access_key_id is required")
	}
	ns, err := s.catalog.ValidateNames(req.CommonName, req.SANs)
	if err != nil {
		return nil, false, err
	}
	cn := ns.Names[0]
	sans := ns.Names[1:]

	if !req.Force {
		existing, err := s.store.FindActiveByNames(ctx, cn, sans)
		if err == nil && existing.NotAfter != nil && existing.NotAfter.After(time.Now().UTC().Add(s.renewBefore)) {
			// Only return existing if owned by same access key (or leave for admin force).
			if existing.AccessKeyID != nil && *existing.AccessKeyID == req.AccessKeyID {
				return existing, false, nil
			}
		}
		if err != nil && err != store.ErrNotFound {
			return nil, false, err
		}
	}

	unlock, err := s.lockNames(ctx, cn, sans)
	if err != nil {
		return nil, false, fmt.Errorf("busy: another ACME operation holds the lock: %w", err)
	}
	defer unlock()

	// Re-check after lock
	if !req.Force {
		existing, err := s.store.FindActiveByNames(ctx, cn, sans)
		if err == nil && existing.NotAfter != nil && existing.NotAfter.After(time.Now().UTC().Add(s.renewBefore)) {
			if existing.AccessKeyID != nil && *existing.AccessKeyID == req.AccessKeyID {
				return existing, false, nil
			}
		}
	}

	certRow, err := s.store.CreateCertificate(ctx, cn, sans, ns.Zone, req.AccessKeyID)
	if err != nil {
		return nil, false, err
	}
	id := certRow.ID
	_ = s.store.InsertAudit(ctx, "issue.start", &id, req.Actor, cn)

	result, err := s.issuer.Obtain(ctx, ns.Names, ns.Zone)
	if err != nil {
		_ = s.store.MarkFailed(ctx, id, err.Error())
		_ = s.store.InsertAudit(ctx, "issue.fail", &id, req.Actor, err.Error())
		return nil, false, err
	}

	encKey, err := s.box.Seal([]byte(result.PrivateKeyPEM))
	if err != nil {
		_ = s.store.MarkFailed(ctx, id, err.Error())
		return nil, false, err
	}
	if err := s.store.SaveIssued(ctx, id, encKey, result.CertificatePEM, result.ChainPEM, result.Serial, result.Issuer, result.NotBefore, result.NotAfter); err != nil {
		return nil, false, err
	}
	_ = s.store.InsertAudit(ctx, "issue.ok", &id, req.Actor, result.Serial)

	out, err := s.store.GetCertificate(ctx, id)
	return out, true, err
}

// RenewOne force-renews a certificate by ID.
func (s *Service) RenewOne(ctx context.Context, id uuid.UUID, actor string) (*store.Certificate, error) {
	cert, err := s.store.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	if cert.Status == store.StatusDeleted {
		return nil, fmt.Errorf("certificate is deleted")
	}
	ns, err := s.catalog.ValidateNames(cert.CommonName, cert.SANs)
	if err != nil {
		return nil, err
	}

	unlock, err := s.lockNames(ctx, cert.CommonName, cert.SANs)
	if err != nil {
		return nil, fmt.Errorf("busy: %w", err)
	}
	defer unlock()

	_ = s.store.InsertAudit(ctx, "renew.start", &id, actor, cert.CommonName)
	result, err := s.issuer.Obtain(ctx, ns.Names, ns.Zone)
	if err != nil {
		_ = s.store.MarkFailed(ctx, id, err.Error())
		_ = s.store.InsertAudit(ctx, "renew.fail", &id, actor, err.Error())
		return nil, err
	}
	encKey, err := s.box.Seal([]byte(result.PrivateKeyPEM))
	if err != nil {
		_ = s.store.MarkFailed(ctx, id, err.Error())
		return nil, err
	}
	if err := s.store.SaveIssued(ctx, id, encKey, result.CertificatePEM, result.ChainPEM, result.Serial, result.Issuer, result.NotBefore, result.NotAfter); err != nil {
		return nil, err
	}
	// refresh zone if resolved differently
	_ = s.store.SetDNSZone(ctx, id, ns.Zone)
	_ = s.store.InsertAudit(ctx, "renew.ok", &id, actor, result.Serial)
	return s.store.GetCertificate(ctx, id)
}

// RenewResult is the summary of a bulk renew run.
type RenewResult struct {
	Renewed []RenewItem  `json:"renewed"`
	Skipped []RenewItem  `json:"skipped"`
	Failed  []FailedItem `json:"failed"`
}

// RenewItem identifies a certificate in renew output.
type RenewItem struct {
	ID         string `json:"id"`
	CommonName string `json:"common_name"`
}

// FailedItem is a failed renewal.
type FailedItem struct {
	ID         string `json:"id"`
	CommonName string `json:"common_name"`
	Error      string `json:"error"`
}

// RenewDue renews all active certificates within the expiry window.
func (s *Service) RenewDue(ctx context.Context, actor string) (*RenewResult, error) {
	cutoff := time.Now().UTC().Add(s.renewBefore)
	due, err := s.store.ListDueForRenewal(ctx, cutoff)
	if err != nil {
		return nil, err
	}
	out := &RenewResult{
		Renewed: []RenewItem{},
		Skipped: []RenewItem{},
		Failed:  []FailedItem{},
	}
	for _, c := range due {
		_, err := s.RenewOne(ctx, c.ID, actor)
		item := RenewItem{ID: c.ID.String(), CommonName: c.CommonName}
		if err != nil {
			out.Failed = append(out.Failed, FailedItem{ID: c.ID.String(), CommonName: c.CommonName, Error: err.Error()})
			continue
		}
		out.Renewed = append(out.Renewed, item)
	}
	return out, nil
}

// DecryptPrivateKey returns the PEM private key for a certificate.
func (s *Service) DecryptPrivateKey(cert *store.Certificate) (string, error) {
	if cert.PrivateKeyEnc == "" {
		return "", fmt.Errorf("no private key stored")
	}
	raw, err := s.box.Open(cert.PrivateKeyEnc)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *Service) lockNames(ctx context.Context, cn string, sans []string) (func(), error) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(store.NamesKey(cn, sans)))
	key := int64(h.Sum64())
	if key == 0 {
		key = 1
	}
	return s.store.AcquireConnLock(ctx, key)
}
