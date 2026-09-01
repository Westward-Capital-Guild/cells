// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"errors"
	"testing"
	"time"
)

func TestFlowStoreConsumesStateOnce(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	store := NewFlowStore(5*time.Minute, func() time.Time { return now })
	flow, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if flow.State == "" || flow.Nonce == "" || flow.PKCEVerifier == "" {
		t.Fatalf("Begin() returned incomplete flow: %#v", flow)
	}

	consumed, err := store.Consume(flow.State)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != flow {
		t.Fatalf("Consume() = %#v, want %#v", consumed, flow)
	}
	if _, err := store.Consume(flow.State); err == nil {
		t.Fatal("Consume() accepted a replayed state")
	}
}

func TestFlowStoreRejectsExpiredState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	store := NewFlowStore(time.Minute, func() time.Time { return now })
	flow, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := store.Consume(flow.State); err == nil {
		t.Fatal("Consume() accepted an expired state")
	}
}

func TestFlowStoreRejectsNewFlowsAtCapacity(t *testing.T) {
	t.Parallel()

	store := NewFlowStore(5*time.Minute, time.Now, 1)
	if _, err := store.Begin(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("Begin() error = %v, want ErrFlowCapacity", err)
	}
}
