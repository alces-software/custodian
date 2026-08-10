// =============================================================================
// Copyright (C) 2026 Alces Software Ltd.
//
// This file is part of Custodian CLI.
//
// This program and the accompanying materials are made available under
// the terms of the Eclipse Public License 2.0 which is available at
// <https://www.eclipse.org/legal/epl-2.0>, or alternative license
// terms made available by Alces Software Ltd - please direct inquiries
// about licensing to licensing@alces-flight.com.
//
// Custodian CLI is distributed in the hope that it will be useful, but
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
// IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
// OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
// PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
// details.
//
// You should have received a copy of the Eclipse Public License 2.0
// along with Custodian CLI. If not, see:
//
//  https://opensource.org/licenses/EPL-2.0
//
// For more information on Custodian CLI, please visit:
// https://github.com/alces-software/custodian-cli
// ==============================================================================

package client

import "time"

// Certificate is API certificate metadata.
type Certificate struct {
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

// ListCertificatesResponse is GET /v1/certificates.
type ListCertificatesResponse struct {
	Certificates []Certificate `json:"certificates"`
}

// IssueRequest is POST /v1/certificates body.
type IssueRequest struct {
	CommonName  string   `json:"common_name"`
	SANs        []string `json:"sans"`
	Force       bool     `json:"force"`
	AccessKey   string   `json:"access_key,omitempty"`
	AccessKeyID string   `json:"access_key_id,omitempty"`
}

// Bundle is GET /v1/certificates/{id}/bundle JSON.
type Bundle struct {
	ID             string `json:"id"`
	CommonName     string `json:"common_name"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem"`
	FullchainPEM   string `json:"fullchain_pem"`
}

// RenewResult is POST /v1/renew.
type RenewResult struct {
	Renewed []RenewItem  `json:"renewed"`
	Skipped []RenewItem  `json:"skipped"`
	Failed  []FailedItem `json:"failed"`
}

// RenewItem identifies a cert in renew output.
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

// AccessKey is access-key metadata (raw secret is never returned by the API).
type AccessKey struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	RevokedAt   *time.Time `json:"revoked_at"`
	CertCount   int        `json:"cert_count"`
	Created     bool       `json:"created,omitempty"`
}

// ListAccessKeysResponse is GET /v1/access-keys.
type ListAccessKeysResponse struct {
	AccessKeys []AccessKey `json:"access_keys"`
}

// RegisterAccessKeyRequest is POST /v1/access-keys body.
type RegisterAccessKeyRequest struct {
	AccessKey   string `json:"access_key"`
	Description string `json:"description"`
}

// UpdateAccessKeyRequest is PATCH /v1/access-keys/{id} body.
type UpdateAccessKeyRequest struct {
	Description *string `json:"description"`
}

// StatusResponse is healthz/readyz.
type StatusResponse struct {
	Status string `json:"status"`
}
