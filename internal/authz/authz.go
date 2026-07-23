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

package authz

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"alces/custodian/internal/store"
)

// Role identifies the principal kind.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleRegistrar Role = "registrar"
	RoleAccessKey Role = "access_key"
)

// Principal is an authenticated caller.
type Principal struct {
	Role        Role
	AccessKeyID uuid.UUID // set when RoleAccessKey
	Label       string    // for audit: "admin", "registrar", or access key id
}

// IsAdmin reports admin role.
func (p *Principal) IsAdmin() bool { return p != nil && p.Role == RoleAdmin }

// IsRegistrar reports registrar role.
func (p *Principal) IsRegistrar() bool { return p != nil && p.Role == RoleRegistrar }

// IsAccessKey reports access-key role.
func (p *Principal) IsAccessKey() bool { return p != nil && p.Role == RoleAccessKey }

// Authenticator resolves Bearer tokens to principals.
type Authenticator struct {
	adminKeys     []string
	registrarKeys []string
	store         *store.Store
}

// NewAuthenticator builds an authenticator.
func NewAuthenticator(adminKeys, registrarKeys []string, st *store.Store) (*Authenticator, error) {
	if len(adminKeys) == 0 {
		return nil, fmt.Errorf("at least one admin API key is required")
	}
	return &Authenticator{
		adminKeys:     adminKeys,
		registrarKeys: registrarKeys,
		store:         st,
	}, nil
}

// HasRegistrar reports whether any registrar key is configured.
func (a *Authenticator) HasRegistrar() bool {
	return len(a.registrarKeys) > 0
}

// Authenticate resolves a bearer token.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (*Principal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	if matchKey(token, a.adminKeys) {
		return &Principal{Role: RoleAdmin, Label: "admin"}, nil
	}
	if matchKey(token, a.registrarKeys) {
		return &Principal{Role: RoleRegistrar, Label: "registrar"}, nil
	}
	hash := store.HashAccessKey(token)
	ak, err := a.store.GetAccessKeyByHash(ctx, hash, true)
	if err == store.ErrNotFound {
		return nil, fmt.Errorf("invalid API key")
	}
	if err != nil {
		return nil, err
	}
	return &Principal{
		Role:        RoleAccessKey,
		AccessKeyID: ak.ID,
		Label:       "access_key:" + ak.ID.String(),
	}, nil
}

func matchKey(token string, keys []string) bool {
	tb := []byte(token)
	found := false
	for _, k := range keys {
		kb := []byte(k)
		if len(tb) != len(kb) {
			continue
		}
		if subtle.ConstantTimeCompare(tb, kb) == 1 {
			found = true
		}
	}
	return found
}

// CanAccessCert reports whether p may access cert.
func CanAccessCert(p *Principal, cert *store.Certificate) bool {
	if p == nil || cert == nil {
		return false
	}
	if p.IsAdmin() {
		return true
	}
	if p.IsAccessKey() {
		return cert.AccessKeyID != nil && *cert.AccessKeyID == p.AccessKeyID
	}
	return false
}

// CanRegisterAccessKey reports whether p may POST /v1/access-keys.
func CanRegisterAccessKey(p *Principal) bool {
	return p != nil && (p.IsAdmin() || p.IsRegistrar())
}

// CanManageAccessKeys reports list/get/revoke of access keys.
func CanManageAccessKeys(p *Principal) bool {
	return p != nil && p.IsAdmin()
}

// CanBulkRenew reports POST /v1/renew.
func CanBulkRenew(p *Principal) bool {
	return p != nil && p.IsAdmin()
}

// CanIssueCertificates reports whether p may call issue (access key or admin).
func CanIssueCertificates(p *Principal) bool {
	return p != nil && (p.IsAdmin() || p.IsAccessKey())
}
