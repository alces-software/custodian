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

package domains

import "testing"

func TestResolveMostSpecific(t *testing.T) {
	cat, err := NewCatalog([]Entry{
		{Pattern: "*.example.com", Zone: "zone-wild"},
		{Pattern: "api.example.com", Zone: "zone-api"},
		{Pattern: "*.apps.example.com", Zone: "zone-apps"},
	}, 10)
	if err != nil {
		t.Fatal(err)
	}

	_, zone, err := cat.Resolve("api.example.com")
	if err != nil || zone != "zone-api" {
		t.Fatalf("api zone=%q err=%v", zone, err)
	}
	_, zone, err = cat.Resolve("foo.example.com")
	if err != nil || zone != "zone-wild" {
		t.Fatalf("foo zone=%q err=%v", zone, err)
	}
	_, zone, err = cat.Resolve("x.apps.example.com")
	if err != nil || zone != "zone-apps" {
		t.Fatalf("apps zone=%q err=%v", zone, err)
	}
	if _, _, err := cat.Resolve("evil.com"); err == nil {
		t.Fatal("expected reject")
	}
}

func TestValidateNamesSameZone(t *testing.T) {
	cat, err := NewCatalog([]Entry{
		{Pattern: "*.example.com", Zone: "z1"},
		{Pattern: "*.other.com", Zone: "z2"},
	}, 5)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := cat.ValidateNames("a.example.com", []string{"b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if ns.Zone != "z1" || len(ns.Names) != 2 {
		t.Fatalf("%+v", ns)
	}
	if _, err := cat.ValidateNames("a.example.com", []string{"b.other.com"}); err == nil {
		t.Fatal("expected multi-zone error")
	}
}

func TestPatternsCoverAll(t *testing.T) {
	scope := []string{"*.pay.example.com", "pay.example.com"}
	if !PatternsCoverAll(scope, []string{"a.pay.example.com", "pay.example.com"}) {
		t.Fatal("expected cover")
	}
	if PatternsCoverAll(scope, []string{"other.example.com"}) {
		t.Fatal("expected not cover")
	}
}
