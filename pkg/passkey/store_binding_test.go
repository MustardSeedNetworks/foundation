// SPDX-License-Identifier: BUSL-1.1

package passkey

import "testing"

func TestStoreRegistrationRequiresAccountBinding(t *testing.T) {
	t.Parallel()
	_, session, err := newTestService(t).BeginRegistration(testUser{})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	for _, account := range []string{"", "another-account"} {
		binding := Binding{Browser: browserBinding.Browser, Purpose: Registration, AccountID: account}
		if _, err := store.Add(*session, binding); err == nil {
			t.Fatal("accepted wrong enrollment owner")
		}
	}
	binding := Binding{Browser: browserBinding.Browser, Purpose: Registration, AccountID: string(testUser{}.WebAuthnID())}
	id, err := store.Add(*session, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Take(id, binding); !ok {
		t.Fatal("rejected enrolled account binding")
	}
}

func TestStoreRejectsInvalidSessionAndBinding(t *testing.T) {
	t.Parallel()
	store := NewStore()
	if _, err := store.Add(Session{}, browserBinding); err == nil {
		t.Fatal("accepted zero session")
	}
	for _, binding := range []Binding{
		{}, {Browser: "short", Purpose: Login},
		{Browser: browserBinding.Browser, Purpose: Registration},
		{Browser: browserBinding.Browser, Purpose: Login, AccountID: "unexpected"},
	} {
		if _, err := store.Add(loginSession(t), binding); err == nil {
			t.Fatal("accepted invalid binding")
		}
	}
	if _, ok := store.Take("unknown", browserBinding); ok {
		t.Fatal("accepted unknown ceremony")
	}
}
