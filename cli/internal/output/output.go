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

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"alces/custodian-cli/internal/client"
)

// Printer writes human or JSON output.
type Printer struct {
	Out  io.Writer
	Err  io.Writer
	JSON bool
}

// New returns a printer writing to stdout/stderr.
func New(jsonMode bool) *Printer {
	return &Printer{Out: os.Stdout, Err: os.Stderr, JSON: jsonMode}
}

// PrintJSON encodes v as indented JSON.
func (p *Printer) PrintJSON(v any) error {
	enc := json.NewEncoder(p.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// PrintCertList prints a certificate table or JSON list.
func (p *Printer) PrintCertList(certs []client.Certificate) error {
	if p.JSON {
		return p.PrintJSON(client.ListCertificatesResponse{Certificates: certs})
	}
	w := tabwriter.NewWriter(p.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCOMMON_NAME\tSTATUS\tNOT_AFTER\tDNS_ZONE\tACCESS_KEY_ID")
	for _, c := range certs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.ID, c.CommonName, c.Status, formatTime(c.NotAfter), c.DNSZone, c.AccessKeyID)
	}
	return w.Flush()
}

// PrintCert prints one certificate's metadata.
func (p *Printer) PrintCert(c *client.Certificate) error {
	if p.JSON {
		return p.PrintJSON(c)
	}
	fmt.Fprintf(p.Out, "ID:            %s\n", c.ID)
	fmt.Fprintf(p.Out, "Common Name:   %s\n", c.CommonName)
	fmt.Fprintf(p.Out, "SANs:          %v\n", c.SANs)
	fmt.Fprintf(p.Out, "Status:        %s\n", c.Status)
	if c.DNSZone != "" {
		fmt.Fprintf(p.Out, "DNS Zone:      %s\n", c.DNSZone)
	}
	if c.AccessKeyID != "" {
		fmt.Fprintf(p.Out, "Access Key ID: %s\n", c.AccessKeyID)
	}
	fmt.Fprintf(p.Out, "Not Before:    %s\n", formatTime(c.NotBefore))
	fmt.Fprintf(p.Out, "Not After:     %s\n", formatTime(c.NotAfter))
	fmt.Fprintf(p.Out, "Serial:        %s\n", c.Serial)
	fmt.Fprintf(p.Out, "Issuer:        %s\n", c.Issuer)
	if c.LastError != "" {
		fmt.Fprintf(p.Out, "Last Error:    %s\n", c.LastError)
	}
	fmt.Fprintf(p.Out, "Created At:    %s\n", c.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(p.Out, "Updated At:    %s\n", c.UpdatedAt.UTC().Format(time.RFC3339))
	if c.RenewedAt != nil {
		fmt.Fprintf(p.Out, "Renewed At:    %s\n", c.RenewedAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// PrintAccessKeyList prints access keys as a table or JSON.
func (p *Printer) PrintAccessKeyList(keys []client.AccessKey) error {
	if p.JSON {
		return p.PrintJSON(client.ListAccessKeysResponse{AccessKeys: keys})
	}
	w := tabwriter.NewWriter(p.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tDESCRIPTION\tCERTS\tCREATED_BY\tREVOKED_AT")
	for _, k := range keys {
		revoked := "-"
		if k.RevokedAt != nil {
			revoked = k.RevokedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
			k.ID, k.Description, k.CertCount, k.CreatedBy, revoked)
	}
	return w.Flush()
}

// PrintAccessKey prints one access key's metadata.
func (p *Printer) PrintAccessKey(k *client.AccessKey) error {
	if p.JSON {
		return p.PrintJSON(k)
	}
	fmt.Fprintf(p.Out, "ID:          %s\n", k.ID)
	fmt.Fprintf(p.Out, "Description: %s\n", k.Description)
	fmt.Fprintf(p.Out, "Created By:  %s\n", k.CreatedBy)
	fmt.Fprintf(p.Out, "Created At:  %s\n", k.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(p.Out, "Cert Count:  %d\n", k.CertCount)
	if k.RevokedAt != nil {
		fmt.Fprintf(p.Out, "Revoked At:  %s\n", k.RevokedAt.UTC().Format(time.RFC3339))
	}
	if k.Created {
		fmt.Fprintf(p.Out, "Created:     true\n")
	}
	return nil
}

// PrintRenewResult prints a bulk renew summary.
func (p *Printer) PrintRenewResult(r *client.RenewResult) error {
	if p.JSON {
		return p.PrintJSON(r)
	}
	fmt.Fprintf(p.Out, "Renewed: %d\n", len(r.Renewed))
	for _, i := range r.Renewed {
		fmt.Fprintf(p.Out, "  + %s %s\n", i.ID, i.CommonName)
	}
	fmt.Fprintf(p.Out, "Skipped: %d\n", len(r.Skipped))
	for _, i := range r.Skipped {
		fmt.Fprintf(p.Out, "  · %s %s\n", i.ID, i.CommonName)
	}
	fmt.Fprintf(p.Out, "Failed:  %d\n", len(r.Failed))
	for _, i := range r.Failed {
		fmt.Fprintf(p.Out, "  ! %s %s: %s\n", i.ID, i.CommonName, i.Error)
	}
	return nil
}

func formatTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
