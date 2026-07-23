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

package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	box, err := NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")
	sealed, err := box.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}
	// Sealing twice should produce different ciphertexts (random nonce).
	sealed2, _ := box.Seal(plain)
	if sealed == sealed2 {
		t.Fatal("expected different sealed values")
	}
}

func TestNewBoxRejectsBadKey(t *testing.T) {
	if _, err := NewBox([]byte("short")); err == nil {
		t.Fatal("expected error")
	}
}
