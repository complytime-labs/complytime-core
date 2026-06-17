// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"strings"
	"testing"

	gemara "github.com/gemaraproj/go-gemara"

	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// fakeTrustedPublisherStore implements TrustedPublisherLookup for tests.
type fakeTrustedPublisherStore struct {
	publishers map[string][]requirements.TrustedPublisherRow
}

func (f *fakeTrustedPublisherStore) GetTrustedPublishers(_ context.Context, targetID string) ([]requirements.TrustedPublisherRow, error) {
	if f.publishers == nil {
		return nil, nil
	}
	return f.publishers[targetID], nil
}

// Satisfy the full TrustedPublisherStore interface so the store can be used in Stores{}.
func (f *fakeTrustedPublisherStore) InsertTrustedPublishers(_ context.Context, _ []requirements.TrustedPublisherRow) error {
	return nil
}

func (f *fakeTrustedPublisherStore) RemoveTrustedPublishers(_ context.Context, _ string, _ []requirements.TrustedPublisherKey, _ uint64) error {
	return nil
}

func TestHandleEvidenceIngestJS_UnauthorizedPublisher(t *testing.T) {
	t.Parallel()
	tracker := NewIngestTracker()
	tracker.Create("job-1")

	store := &fakeEvidenceStore{}
	trustedPubs := &fakeTrustedPublisherStore{
		publishers: map[string][]requirements.TrustedPublisherRow{
			"test-target": {
				{
					TargetID:   "test-target",
					Issuer:     "https://token.actions.githubusercontent.com",
					SubPattern: "repo:acme/scanner:*",
				},
			},
		},
	}

	ref := bus.IngestRef{
		JobID:    "job-1",
		LogIndex: 0,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer:   "https://token.actions.githubusercontent.com",
			Sub:      "repo:evil/attacker:ref:refs/heads/main",
			Type:     "pipeline",
			Verified: true,
		},
	}

	result := handleEvidenceIngestJS(
		context.Background(), ref, []byte(minimalEvalLog),
		gemara.EvaluationLogArtifact, store, trustedPubs, nil, tracker,
	)

	if result != outcomeTerm {
		t.Fatalf("expected outcomeTerm for unauthorized publisher, got %d", result)
	}

	st := tracker.Get("job-1")
	if st == nil || st.Status != "failed" {
		t.Fatalf("expected failed job, got %+v", st)
	}
	if !strings.Contains(st.Error, "publisher not authorized") {
		t.Fatalf("expected authorization error, got %q", st.Error)
	}
	if len(store.inserted) != 0 {
		t.Fatalf("expected no records inserted, got %d", len(store.inserted))
	}
}

func TestHandleEvidenceIngestJS_AuthorizedPublisher(t *testing.T) {
	t.Parallel()
	tracker := NewIngestTracker()
	tracker.Create("job-2")

	store := &fakeEvidenceStore{}
	trustedPubs := &fakeTrustedPublisherStore{
		publishers: map[string][]requirements.TrustedPublisherRow{
			"test-target": {
				{
					TargetID:   "test-target",
					Issuer:     "https://token.actions.githubusercontent.com",
					SubPattern: "repo:complytime/scanner:*",
				},
			},
		},
	}

	ref := bus.IngestRef{
		JobID:    "job-2",
		LogIndex: 0,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer:   "https://token.actions.githubusercontent.com",
			Sub:      "repo:complytime/scanner:ref:refs/heads/main",
			Type:     "pipeline",
			Verified: true,
		},
	}

	result := handleEvidenceIngestJS(
		context.Background(), ref, []byte(minimalEvalLog),
		gemara.EvaluationLogArtifact, store, trustedPubs, nil, tracker,
	)

	if result != outcomeAck {
		t.Fatalf("expected outcomeAck for authorized publisher, got %d", result)
	}

	st := tracker.Get("job-2")
	if st == nil || st.Status != "completed" {
		t.Fatalf("expected completed job, got %+v", st)
	}
	if len(store.inserted) == 0 {
		t.Fatal("expected records to be inserted")
	}
}

func TestHandleEvidenceIngestJS_NoTrustedPublishers_AllowsAll(t *testing.T) {
	t.Parallel()
	tracker := NewIngestTracker()
	tracker.Create("job-3")

	store := &fakeEvidenceStore{}
	// No trusted publishers configured for "test-target"
	trustedPubs := &fakeTrustedPublisherStore{
		publishers: map[string][]requirements.TrustedPublisherRow{},
	}

	ref := bus.IngestRef{
		JobID:    "job-3",
		LogIndex: 0,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer:   "https://token.actions.githubusercontent.com",
			Sub:      "repo:anyone/anything:ref:refs/heads/main",
			Type:     "pipeline",
			Verified: true,
		},
	}

	result := handleEvidenceIngestJS(
		context.Background(), ref, []byte(minimalEvalLog),
		gemara.EvaluationLogArtifact, store, trustedPubs, nil, tracker,
	)

	if result != outcomeAck {
		t.Fatalf("expected outcomeAck when no trusted publishers configured, got %d", result)
	}

	st := tracker.Get("job-3")
	if st == nil || st.Status != "completed" {
		t.Fatalf("expected completed job, got %+v", st)
	}
	if len(store.inserted) == 0 {
		t.Fatal("expected records to be inserted when no trusted publishers configured")
	}
}

func TestHandleEvidenceIngestJS_NilTrustedPublisherStore_AllowsAll(t *testing.T) {
	t.Parallel()
	tracker := NewIngestTracker()
	tracker.Create("job-4")

	store := &fakeEvidenceStore{}

	ref := bus.IngestRef{
		JobID:    "job-4",
		LogIndex: 0,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer:   "https://token.actions.githubusercontent.com",
			Sub:      "repo:anyone/anything:ref:refs/heads/main",
			Type:     "pipeline",
			Verified: true,
		},
	}

	result := handleEvidenceIngestJS(
		context.Background(), ref, []byte(minimalEvalLog),
		gemara.EvaluationLogArtifact, store, nil, nil, tracker,
	)

	if result != outcomeAck {
		t.Fatalf("expected outcomeAck when trustedPubs is nil, got %d", result)
	}

	st := tracker.Get("job-4")
	if st == nil || st.Status != "completed" {
		t.Fatalf("expected completed job, got %+v", st)
	}
}

func TestHandleEvidenceIngestJS_EnforcementLog_UnauthorizedPublisher(t *testing.T) {
	t.Parallel()
	tracker := NewIngestTracker()
	tracker.Create("job-5")

	store := &fakeEvidenceStore{}
	trustedPubs := &fakeTrustedPublisherStore{
		publishers: map[string][]requirements.TrustedPublisherRow{
			"test-target": {
				{
					TargetID:   "test-target",
					Issuer:     "https://token.actions.githubusercontent.com",
					SubPattern: "repo:acme/scanner:*",
				},
			},
		},
	}

	ref := bus.IngestRef{
		JobID:    "job-5",
		LogIndex: 0,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer:   "https://accounts.google.com",
			Sub:      "unauthorized@example.com",
			Type:     "service",
			Verified: true,
		},
	}

	result := handleEvidenceIngestJS(
		context.Background(), ref, []byte(minimalEnfLog),
		gemara.EnforcementLogArtifact, store, trustedPubs, nil, tracker,
	)

	if result != outcomeTerm {
		t.Fatalf("expected outcomeTerm for unauthorized enforcement publisher, got %d", result)
	}

	st := tracker.Get("job-5")
	if st == nil || st.Status != "failed" {
		t.Fatalf("expected failed job, got %+v", st)
	}
	if !strings.Contains(st.Error, "publisher not authorized") {
		t.Fatalf("expected authorization error, got %q", st.Error)
	}
}
