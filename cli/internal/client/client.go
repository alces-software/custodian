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

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a Custodian server.
type Client struct {
	baseURL    string
	authKey    string
	httpClient *http.Client
}

// APIError is a Custodian API error body.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// New builds a client. timeout <= 0 means 120s.
func New(baseURL, authKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		authKey: authKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.baseURL + path
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, auth bool, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.authKey)
	}
	req.Header.Set("Accept", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return parseAPIError(res.StatusCode, data)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func parseAPIError(status int, data []byte) error {
	var eb errorBody
	if err := json.Unmarshal(data, &eb); err == nil && (eb.Error.Code != "" || eb.Error.Message != "") {
		return &APIError{StatusCode: status, Code: eb.Error.Code, Message: eb.Error.Message}
	}
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		return &APIError{StatusCode: status}
	}
	return &APIError{StatusCode: status, Message: msg}
}

// Healthz calls GET /healthz.
func (c *Client) Healthz(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/healthz", nil, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Readyz calls GET /readyz.
func (c *Client) Readyz(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/readyz", nil, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListCertificates calls GET /v1/certificates.
func (c *Client) ListCertificates(ctx context.Context) (*ListCertificatesResponse, error) {
	var out ListCertificatesResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/certificates", nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetCertificate calls GET /v1/certificates/{id}.
func (c *Client) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	var out Certificate
	if err := c.doJSON(ctx, http.MethodGet, "/v1/certificates/"+id, nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Issue calls POST /v1/certificates.
func (c *Client) Issue(ctx context.Context, req IssueRequest) (*Certificate, error) {
	if req.SANs == nil {
		req.SANs = []string{}
	}
	var out Certificate
	if err := c.doJSON(ctx, http.MethodPost, "/v1/certificates", req, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RenewOne calls POST /v1/certificates/{id}/renew.
func (c *Client) RenewOne(ctx context.Context, id string) (*Certificate, error) {
	var out Certificate
	if err := c.doJSON(ctx, http.MethodPost, "/v1/certificates/"+id+"/renew", nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RenewDue calls POST /v1/renew.
func (c *Client) RenewDue(ctx context.Context) (*RenewResult, error) {
	var out RenewResult
	if err := c.doJSON(ctx, http.MethodPost, "/v1/renew", nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteCertificate calls DELETE /v1/certificates/{id}.
func (c *Client) DeleteCertificate(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/certificates/"+id, nil, true, nil)
}

// GetBundle calls GET /v1/certificates/{id}/bundle (JSON).
func (c *Client) GetBundle(ctx context.Context, id string) (*Bundle, error) {
	var out Bundle
	if err := c.doJSON(ctx, http.MethodGet, "/v1/certificates/"+id+"/bundle", nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetBundlePEM calls GET /v1/certificates/{id}/bundle?format=pem.
func (c *Client) GetBundlePEM(ctx context.Context, id string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/certificates/"+id+"/bundle?format=pem"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.authKey)
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, parseAPIError(res.StatusCode, data)
	}
	return data, nil
}

// RegisterAccessKey calls POST /v1/access-keys (admin or registrar).
func (c *Client) RegisterAccessKey(ctx context.Context, req RegisterAccessKeyRequest) (*AccessKey, error) {
	var out AccessKey
	if err := c.doJSON(ctx, http.MethodPost, "/v1/access-keys", req, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAccessKeys calls GET /v1/access-keys (admin).
func (c *Client) ListAccessKeys(ctx context.Context) (*ListAccessKeysResponse, error) {
	var out ListAccessKeysResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/access-keys", nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAccessKey calls GET /v1/access-keys/{id} (admin).
func (c *Client) GetAccessKey(ctx context.Context, id string) (*AccessKey, error) {
	var out AccessKey
	if err := c.doJSON(ctx, http.MethodGet, "/v1/access-keys/"+id, nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateAccessKeyDescription calls PATCH /v1/access-keys/{id} (admin).
func (c *Client) UpdateAccessKeyDescription(ctx context.Context, id, description string) (*AccessKey, error) {
	body := UpdateAccessKeyRequest{Description: &description}
	var out AccessKey
	if err := c.doJSON(ctx, http.MethodPatch, "/v1/access-keys/"+id, body, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeAccessKey calls DELETE /v1/access-keys/{id} (admin).
func (c *Client) RevokeAccessKey(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/access-keys/"+id, nil, true, nil)
}
