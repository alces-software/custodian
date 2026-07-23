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

	"github.com/markt/custodian/internal/acme"
	"github.com/markt/custodian/internal/authz"
	"github.com/markt/custodian/internal/store"
)

// Server is the HTTP API.
type Server struct {
	store *store.Store
	svc   *acme.Service
	authz *authz.Registry
	log   *slog.Logger
}

// New constructs the API server.
func New(st *store.Store, svc *acme.Service, reg *authz.Registry, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: st, svc: svc, authz: reg, log: log}
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
		r.Use(s.requireAPIKey)
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
			"client_id", clientIDFrom(r.Context()),
		)
	})
}

func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid Authorization header")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		client, err := s.authz.Authenticate(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), clientKey{}, client)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type clientKey struct{}

func clientFrom(ctx context.Context) *authz.Client {
	if v, ok := ctx.Value(clientKey{}).(*authz.Client); ok {
		return v
	}
	return nil
}

func clientIDFrom(ctx context.Context) string {
	if c := clientFrom(ctx); c != nil {
		return c.ID
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

type issueBody struct {
	CommonName string   `json:"common_name"`
	SANs       []string `json:"sans"`
	Force      bool     `json:"force"`
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var body issueBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	client := clientFrom(r.Context())
	// Pre-check scope on requested names (catalog validation happens in service).
	names := append([]string{body.CommonName}, body.SANs...)
	// Filter empty SANs for authz pre-check
	clean := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n != "" {
			clean = append(clean, n)
		}
	}
	if len(clean) == 0 || !s.authz.CanAccessNames(client, clean) {
		writeError(w, http.StatusForbidden, "forbidden", "key is not authorized for the requested domain(s)")
		return
	}

	cert, created, err := s.svc.Issue(r.Context(), acme.IssueRequest{
		CommonName: body.CommonName,
		SANs:       body.SANs,
		Force:      body.Force,
		Actor:      client.ID,
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

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	client := clientFrom(r.Context())
	certs, err := s.store.ListCertificates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	out := make([]certMeta, 0, len(certs))
	for i := range certs {
		if !s.authz.CanAccessCert(client, &certs[i]) {
			continue
		}
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
	client := clientFrom(r.Context())
	out, err := s.svc.RenewOne(r.Context(), cert.ID, client.ID)
	if err != nil {
		s.writeIssueError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, certToMeta(out))
}

func (s *Server) handleRenewDue(w http.ResponseWriter, r *http.Request) {
	client := clientFrom(r.Context())
	if !client.IsAdmin() {
		writeError(w, http.StatusForbidden, "forbidden", "bulk renew requires an admin API key")
		return
	}
	result, err := s.svc.RenewDue(r.Context(), client.ID)
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
	client := clientFrom(r.Context())
	if err := s.store.SoftDelete(r.Context(), cert.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "certificate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	id := cert.ID
	_ = s.store.InsertAudit(r.Context(), "delete", &id, client.ID, "")
	w.WriteHeader(http.StatusNoContent)
}

// loadAuthorizedCert loads by id and returns 404 if missing or out of scope.
func (s *Server) loadAuthorizedCert(w http.ResponseWriter, r *http.Request) (*store.Certificate, bool) {
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
	if !s.authz.CanAccessCert(clientFrom(r.Context()), cert) {
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
	ID         string     `json:"id"`
	CommonName string     `json:"common_name"`
	SANs       []string   `json:"sans"`
	Status     string     `json:"status"`
	DNSZone    string     `json:"dns_zone,omitempty"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
	Serial     string     `json:"serial,omitempty"`
	Issuer     string     `json:"issuer,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	RenewedAt  *time.Time `json:"renewed_at,omitempty"`
}

func certToMeta(c *store.Certificate) certMeta {
	return certMeta{
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
