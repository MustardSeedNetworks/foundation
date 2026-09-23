// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStoreConsumesOnce(t *testing.T) {
	t.Parallel()
	store := NewStore()
	id := addLogin(t, store, browserBinding)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			if _, ok := store.Take(id, browserBinding); ok {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("consumed %d times", accepted.Load())
	}
}

func TestStoreBindingFailuresDoNotConsume(t *testing.T) {
	t.Parallel()
	store := NewStore()
	id := addLogin(t, store, browserBinding)
	for _, binding := range []Binding{
		{Browser: "another-browser-secret-with-32-bytes", Purpose: Login},
		{Browser: browserBinding.Browser, Purpose: Registration},
		{Browser: browserBinding.Browser, Purpose: Login, AccountID: "foreign"},
	} {
		if _, ok := store.Take(id, binding); ok {
			t.Fatal("accepted wrong binding")
		}
	}
	if _, ok := store.Take(id, browserBinding); !ok {
		t.Fatal("wrong binding consumed valid ceremony")
	}
}

func TestStoreParallelBeginsRemainIndependent(t *testing.T) {
	t.Parallel()
	store := NewStore()
	a, b := addLogin(t, store, browserBinding), addLogin(t, store, browserBinding)
	if a == b {
		t.Fatal("ceremony IDs collide")
	}
	for _, id := range []string{a, b} {
		if _, ok := store.Take(id, browserBinding); !ok {
			t.Fatal("parallel begin overwritten")
		}
	}
}

func TestStoreExpiresAndClears(t *testing.T) {
	t.Parallel()
	store := NewStore()
	id := addLogin(t, store, browserBinding)
	entry := store.pending[id]
	entry.session.data.Expires = time.Now().Add(-time.Second)
	store.pending[id] = entry
	if _, ok := store.Take(id, browserBinding); ok {
		t.Fatal("accepted expired ceremony")
	}
	id = addLogin(t, store, browserBinding)
	store.Clear()
	if _, ok := store.Take(id, browserBinding); ok {
		t.Fatal("accepted cleared ceremony")
	}
}

func TestStoreBoundsOutstandingCeremonies(t *testing.T) {
	t.Parallel()
	store := NewStore()
	for range maxPending {
		if _, err := store.Add(loginSession(t), browserBinding); err != nil {
			t.Fatal(err)
		}
	}
	session := loginSession(t)
	if _, err := store.Add(session, browserBinding); err == nil {
		t.Fatal("unbounded ceremony store")
	}
	for id, entry := range store.pending {
		entry.session.data.Expires = time.Now().Add(-time.Second)
		store.pending[id] = entry
	}
	if _, err := store.Add(session, browserBinding); err != nil {
		t.Fatal("expired entries retain capacity")
	}
}

var browserBinding = Binding{Browser: "test-browser-secret-at-least-32-bytes", Purpose: Login}

func loginSession(t *testing.T) Session {
	t.Helper()
	_, session, err := newTestService(t).BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	return *session
}

func addLogin(t *testing.T, store *Store, binding Binding) string {
	t.Helper()
	id, err := store.Add(loginSession(t), binding)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
