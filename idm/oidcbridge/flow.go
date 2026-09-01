// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

package oidcbridge

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const DefaultMaxPendingFlows = 10000

var (
	ErrInvalidFlowState = errors.New("invalid or expired OIDC flow state")
	ErrFlowCapacity     = errors.New("OIDC flow capacity reached")
)

type Flow struct {
	State        string
	Nonce        string
	PKCEVerifier string
	ExpiresAt    time.Time
}

type FlowStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	now   func() time.Time
	flows map[string]Flow
}

func NewFlowStore(ttl time.Duration, now func() time.Time, maximum ...int) *FlowStore {
	max := DefaultMaxPendingFlows
	if len(maximum) > 0 && maximum[0] > 0 {
		max = maximum[0]
	}
	return &FlowStore{ttl: ttl, max: max, now: now, flows: make(map[string]Flow)}
}

func (s *FlowStore) Begin() (Flow, error) {
	state, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	flow := Flow{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ExpiresAt:    s.now().Add(s.ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteExpiredLocked()
	if len(s.flows) >= s.max {
		return Flow{}, ErrFlowCapacity
	}
	s.flows[state] = flow
	return flow, nil
}

func (s *FlowStore) Consume(state string) (Flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	flow, ok := s.flows[state]
	delete(s.flows, state)
	if !ok || !s.now().Before(flow.ExpiresAt) {
		return Flow{}, ErrInvalidFlowState
	}
	return flow, nil
}

func (s *FlowStore) deleteExpiredLocked() {
	now := s.now()
	for state, flow := range s.flows {
		if !now.Before(flow.ExpiresAt) {
			delete(s.flows, state)
		}
	}
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
