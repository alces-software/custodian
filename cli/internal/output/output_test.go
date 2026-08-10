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

package output_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"alces/custodian-cli/internal/client"
	"alces/custodian-cli/internal/output"
)

func TestPrintCertList_Table(t *testing.T) {
	var buf bytes.Buffer
	p := &output.Printer{Out: &buf, JSON: false}
	na := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if err := p.PrintCertList([]client.Certificate{{
		ID: "id1", CommonName: "a.com", Status: "active", NotAfter: &na, Issuer: "LE",
	}}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "a.com") || !strings.Contains(s, "ID") {
		t.Fatalf("output %q", s)
	}
}

func TestPrintJSON(t *testing.T) {
	var buf bytes.Buffer
	p := &output.Printer{Out: &buf, JSON: true}
	if err := p.PrintJSON(map[string]string{"status": "ok"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"status"`) {
		t.Fatalf("%q", buf.String())
	}
}
