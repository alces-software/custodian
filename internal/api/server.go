// =============================================================================
// Copyright (C) 2026-present Alces Software Ltd.
//
// This file is part of Custodian.
//
// This program and the accompanying materials are made available under
// the terms of the Eclipse Public License 2.0 which is available at
// <https://www.eclipse.org/legal/epl-2.0>, or alternative license
// terms made available by Alces Software Ltd - please direct inquiries
// about licensing to licensing@alces-flight.com.
//
// Custodian is distributed in the hope that it will be useful, but
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
// IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
// OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
// PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
// details.
//
// You should have received a copy of the Eclipse Public License 2.0
// along with Custodian. If not, see:
//
//  https://opensource.org/licenses/EPL-2.0
//
// For more information on Custodian, please visit:
// https://github.com/alces-software/custodian
// ==============================================================================

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"alces/custodian/internal/acme"
	"alces/custodian/internal/authz"
	"alces/custodian/internal/store"
)

// Server is the HTTP API.
type Server struct {
	store *store.Store
	svc   *acme.Service
	auth  *authz.Authenticator
	log   *slog.Logger
}

// New constructs the API server.
func New(st *store.Store, svc *acme.Service, auth *authz.Authenticator, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: st, svc: svc, auth: auth, log: log}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(s.logRequests)

	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)

	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Post("/v1/access-keys", s.handleRegisterAccessKey)
		r.Get("/v1/access-keys", s.handleListAccessKeys)
		r.Get("/v1/access-keys/{id}", s.handleGetAccessKey)
		r.Patch("/v1/access-keys/{id}", s.handleUpdateAccessKey)
		r.Delete("/v1/access-keys/{id}", s.handleRevokeAccessKey)

		r.Post("/v1/certificates", s.handleIssue)
		r.Get("/v1/certificates", s.handleList)
		r.Get("/v1/certificates/{id}", s.handleGet)
		r.Get("/v1/certificates/{id}/bundle", s.handleBundle)
		r.Post("/v1/certificates/{id}/renew", s.handleRenewOne)
		r.Delete("/v1/certificates/{id}", s.handleDelete)
		r.Post("/v1/renew", s.handleRenewDue)
	})
	return r
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
			"actor", actorLabel(r.Context()),
		)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid Authorization header")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		p, err := s.auth.Authenticate(r.Context(), token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type principalKey struct{}

func principalFrom(ctx context.Context) *authz.Principal {
	if v, ok := ctx.Value(principalKey{}).(*authz.Principal); ok {
		return v
	}
	return nil
}

func actorLabel(ctx context.Context) string {
	if p := principalFrom(ctx); p != nil {
		return p.Label
	}
	return ""
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// --- access keys ---

type registerAccessKeyBody struct {
	AccessKey   string `json:"access_key"`
	Description string `json:"description"`
}

func (s *Server) handleRegisterAccessKey(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !authz.CanRegisterAccessKey(p) {
		writeError(w, http.StatusForbidden, "forbidden", "admin or registrar key required")
		return
	}
	var body registerAccessKeyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	ak, created, err := s.store.RegisterAccessKey(r.Context(), body.AccessKey, body.Description, string(p.Role))
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "access key was revoked; create a new key")
			return
		}
		if strings.Contains(err.Error(), "access_key must") {
			writeError(w, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
		s.log.Error("register access key", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "register failed")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, accessKeyMeta(ak, created))
}

func (s *Server) handleListAccessKeys(w http.ResponseWriter, r *http.Request) {
	if !authz.CanManageAccessKeys(principalFrom(r.Context())) {
		writeError(w, http.StatusForbidden, "forbidden", "admin key required")
		return
	}
	list, err := s.store.ListAccessKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for i := range list {
		out = append(out, accessKeyMeta(&list[i], false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_keys": out})
}

func (s *Server) handleGetAccessKey(w http.ResponseWriter, r *http.Request) {
	if !authz.CanManageAccessKeys(principalFrom(r.Context())) {
		writeError(w, http.StatusForbidden, "forbidden", "admin key required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid id")
		return
	}
	ak, err := s.store.GetAccessKeyByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "access key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	writeJSON(w, http.StatusOK, accessKeyMeta(ak, false))
}

type updateAccessKeyBody struct {
	Description *string `json:"description"`
}

func (s *Server) handleUpdateAccessKey(w http.ResponseWriter, r *http.Request) {
	if !authz.CanManageAccessKeys(principalFrom(r.Context())) {
		writeError(w, http.StatusForbidden, "forbidden", "admin key required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid id")
		return
	}
	var body updateAccessKeyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if body.Description == nil {
		writeError(w, http.StatusBadRequest, "validation_error", "description is required")
		return
	}
	if err := s.store.UpdateAccessKeyDescription(r.Context(), id, *body.Description); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "access key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "update failed")
		return
	}
	ak, err := s.store.GetAccessKeyByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	_ = s.store.InsertAudit(r.Context(), "access_key.update", nil, actorLabel(r.Context()), id.String())
	writeJSON(w, http.StatusOK, accessKeyMeta(ak, false))
}

func (s *Server) handleRevokeAccessKey(w http.ResponseWriter, r *http.Request) {
	if !authz.CanManageAccessKeys(principalFrom(r.Context())) {
		writeError(w, http.StatusForbidden, "forbidden", "admin key required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid id")
		return
	}
	if err := s.store.RevokeAccessKey(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "access key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "revoke failed")
		return
	}
	_ = s.store.InsertAudit(r.Context(), "access_key.revoke", nil, actorLabel(r.Context()), id.String())
	w.WriteHeader(http.StatusNoContent)
}

func accessKeyMeta(ak *store.AccessKey, created bool) map[string]any {
	m := map[string]any{
		"id":          ak.ID.String(),
		"description": ak.Description,
		"created_at":  ak.CreatedAt,
		"created_by":  ak.CreatedBy,
		"revoked_at":  ak.RevokedAt,
	}
	if created {
		m["created"] = true
	} else {
		m["created"] = false
	}
	if ak.CertCount > 0 || true {
		m["cert_count"] = ak.CertCount
	}
	return m
}

// --- certificates ---

type issueBody struct {
	CommonName  string   `json:"common_name"`
	SANs        []string `json:"sans"`
	Force       bool     `json:"force"`
	AccessKey   string   `json:"access_key"`
	AccessKeyID string   `json:"access_key_id"`
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !authz.CanIssueCertificates(p) {
		writeError(w, http.StatusForbidden, "forbidden", "access key or admin required to issue certificates")
		return
	}
	var body issueBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	accessKeyID, err := s.resolveIssueAccessKey(r.Context(), p, body)
	if err != nil {
		code := http.StatusBadRequest
		errCode := "validation_error"
		msg := err.Error()
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrRevoked) {
			code = http.StatusBadRequest
			errCode = "invalid_access_key"
			msg = "access key not registered or revoked; POST /v1/access-keys first"
		}
		writeError(w, code, errCode, msg)
		return
	}

	cert, created, err := s.svc.Issue(r.Context(), acme.IssueRequest{
		CommonName:  body.CommonName,
		SANs:        body.SANs,
		Force:       body.Force,
		Actor:       p.Label,
		AccessKeyID: accessKeyID,
	})
	if err != nil {
		s.writeIssueError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, certToMeta(cert))
}

func (s *Server) resolveIssueAccessKey(ctx context.Context, p *authz.Principal, body issueBody) (uuid.UUID, error) {
	if p.IsAccessKey() {
		if body.AccessKey != "" {
			hash := store.HashAccessKey(strings.TrimSpace(body.AccessKey))
			ak, err := s.store.GetAccessKeyByHash(ctx, hash, true)
			if err != nil {
				return uuid.Nil, err
			}
			if ak.ID != p.AccessKeyID {
				return uuid.Nil, fmtError("access_key in body does not match Authorization bearer")
			}
		}
		if body.AccessKeyID != "" {
			id, err := uuid.Parse(body.AccessKeyID)
			if err != nil || id != p.AccessKeyID {
				return uuid.Nil, fmtError("access_key_id does not match Authorization bearer")
			}
		}
		return p.AccessKeyID, nil
	}
	// admin
	if body.AccessKeyID != "" {
		id, err := uuid.Parse(body.AccessKeyID)
		if err != nil {
			return uuid.Nil, fmtError("invalid access_key_id")
		}
		ak, err := s.store.GetActiveAccessKeyByID(ctx, id)
		if err != nil {
			return uuid.Nil, err
		}
		return ak.ID, nil
	}
	if body.AccessKey != "" {
		hash := store.HashAccessKey(strings.TrimSpace(body.AccessKey))
		ak, err := s.store.GetAccessKeyByHash(ctx, hash, true)
		if err != nil {
			return uuid.Nil, err
		}
		return ak.ID, nil
	}
	return uuid.Nil, fmtError("admin issue requires access_key or access_key_id of a registered key")
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

func fmtError(s string) error { return simpleError(s) }

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.IsRegistrar() {
		writeError(w, http.StatusForbidden, "forbidden", "registrar cannot list certificates")
		return
	}
	var (
		certs []store.Certificate
		err   error
	)
	if p.IsAdmin() {
		certs, err = s.store.ListCertificates(r.Context())
	} else {
		certs, err = s.store.ListCertificatesByAccessKey(r.Context(), p.AccessKeyID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	out := make([]certMeta, 0, len(certs))
	for i := range certs {
		out = append(out, certToMeta(&certs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.loadAuthorizedCert(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, certToMeta(cert))
}

func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.loadAuthorizedCert(w, r)
	if !ok {
		return
	}
	if cert.Status != store.StatusActive || cert.CertificatePEM == "" {
		writeError(w, http.StatusConflict, "not_ready", "certificate not available")
		return
	}
	keyPEM, err := s.svc.DecryptPrivateKey(cert)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "decrypt failed")
		return
	}
	fullchain := cert.CertificatePEM
	if cert.ChainPEM != "" {
		fullchain = strings.TrimRight(cert.CertificatePEM, "\n") + "\n" + strings.TrimLeft(cert.ChainPEM, "\n")
	}

	if r.URL.Query().Get("format") == "pem" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="`+cert.CommonName+`.pem"`)
		_, _ = w.Write([]byte(keyPEM))
		if !strings.HasSuffix(keyPEM, "\n") {
			_, _ = w.Write([]byte("\n"))
		}
		_, _ = w.Write([]byte(fullchain))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":              cert.ID.String(),
		"common_name":     cert.CommonName,
		"private_key_pem": keyPEM,
		"certificate_pem": cert.CertificatePEM,
		"chain_pem":       cert.ChainPEM,
		"fullchain_pem":   fullchain,
	})
}

func (s *Server) handleRenewOne(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.loadAuthorizedCert(w, r)
	if !ok {
		return
	}
	out, err := s.svc.RenewOne(r.Context(), cert.ID, actorLabel(r.Context()))
	if err != nil {
		s.writeIssueError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, certToMeta(out))
}

func (s *Server) handleRenewDue(w http.ResponseWriter, r *http.Request) {
	if !authz.CanBulkRenew(principalFrom(r.Context())) {
		writeError(w, http.StatusForbidden, "forbidden", "bulk renew requires an admin API key")
		return
	}
	result, err := s.svc.RenewDue(r.Context(), actorLabel(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.loadAuthorizedCert(w, r)
	if !ok {
		return
	}
	if err := s.store.SoftDelete(r.Context(), cert.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "certificate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	id := cert.ID
	_ = s.store.InsertAudit(r.Context(), "delete", &id, actorLabel(r.Context()), "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadAuthorizedCert(w http.ResponseWriter, r *http.Request) (*store.Certificate, bool) {
	p := principalFrom(r.Context())
	if p.IsRegistrar() {
		writeError(w, http.StatusForbidden, "forbidden", "registrar cannot access certificates")
		return nil, false
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid id")
		return nil, false
	}
	cert, err := s.store.GetCertificate(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "certificate not found")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "internal", "get failed")
		return nil, false
	}
	if !authz.CanAccessCert(p, cert) {
		writeError(w, http.StatusNotFound, "not_found", "certificate not found")
		return nil, false
	}
	return cert, true
}

func (s *Server) writeIssueError(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not allowlisted"),
		strings.Contains(msg, "invalid"),
		strings.Contains(msg, "required"),
		strings.Contains(msg, "too many"),
		strings.Contains(msg, "multiple Cloud DNS zones"):
		writeError(w, http.StatusBadRequest, "validation_error", msg)
	case strings.Contains(msg, "busy"):
		writeError(w, http.StatusConflict, "busy", msg)
	default:
		s.log.Error("acme operation failed", "err", msg)
		writeError(w, http.StatusBadGateway, "acme_error", msg)
	}
}

type certMeta struct {
	ID          string     `json:"id"`
	CommonName  string     `json:"common_name"`
	SANs        []string   `json:"sans"`
	Status      string     `json:"status"`
	DNSZone     string     `json:"dns_zone,omitempty"`
	AccessKeyID string     `json:"access_key_id,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Serial      string     `json:"serial,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	RenewedAt   *time.Time `json:"renewed_at,omitempty"`
}

func certToMeta(c *store.Certificate) certMeta {
	m := certMeta{
		ID:         c.ID.String(),
		CommonName: c.CommonName,
		SANs:       c.SANs,
		Status:     c.Status,
		DNSZone:    c.DNSZone,
		NotBefore:  c.NotBefore,
		NotAfter:   c.NotAfter,
		Serial:     c.Serial,
		Issuer:     c.Issuer,
		LastError:  c.LastError,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
		RenewedAt:  c.RenewedAt,
	}
	if c.AccessKeyID != nil {
		m.AccessKeyID = c.AccessKeyID.String()
	}
	return m
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
