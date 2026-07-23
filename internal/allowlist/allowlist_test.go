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

package allowlist

import "testing"

func TestAllowed(t *testing.T) {
	l, err := New([]string{"*.apps.example.com", "example.com", "api.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"api.example.com", true},
		{"foo.apps.example.com", true},
		{"FOO.APPS.EXAMPLE.COM", true},
		{"a.b.apps.example.com", false},
		{"apps.example.com", false},
		{"evil.com", false},
		{"", false},
		{"1.2.3.4", false},
	}
	for _, tc := range cases {
		if got := l.Allowed(tc.name); got != tc.want {
			t.Errorf("Allowed(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestValidateNames(t *testing.T) {
	l, err := New([]string{"*.example.com", "example.com"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	names, err := l.ValidateNames("app.example.com", []string{"www.example.com", "app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("names = %#v", names)
	}

	if _, err := l.ValidateNames("not-allowed.com", nil); err == nil {
		t.Fatal("expected error")
	}
	if _, err := l.ValidateNames("a.example.com", []string{"b.example.com", "c.example.com", "d.example.com"}); err == nil {
		t.Fatal("expected too many SANs")
	}
}
