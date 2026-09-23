// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestStoreRejectsRepeatedChallengeAcrossStores(t *testing.T) {
	t.Parallel()
	session := loginSession(t)
	store := NewStore()
	id, err := store.Add(session, browserBinding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore().Add(session, browserBinding); err == nil {
		t.Fatal("copied session admitted twice")
	}
	if _, ok := store.Take(id, browserBinding); !ok {
		t.Fatal("initial ceremony rejected")
	}
	store.Clear()
	if _, err := store.Add(session, browserBinding); err == nil {
		t.Fatal("consumed challenge re-admitted")
	}
}

func TestStoreConcurrentAdmissionAcceptsOnlyOnce(t *testing.T) {
	t.Parallel()
	session := loginSession(t)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			if _, err := NewStore().Add(session, browserBinding); err == nil {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("admitted challenge %d times", accepted.Load())
	}
}
