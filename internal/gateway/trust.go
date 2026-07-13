package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

// TrustEntry represents a trusted publisher for a subject.
type TrustEntry struct {
	Issuer string `json:"issuer"`
	Sub    string `json:"sub"`
}

// TrustStore provides publisher trust lookups and updates against NATS KV.
type TrustStore struct {
	js            jetstream.JetStream
	publisherKV   jetstream.KeyValue
	subjectKV     jetstream.KeyValue
}

// NewTrustStore creates a new TrustStore backed by NATS KV buckets.
// The buckets must already exist (created via nats.EnsureInfrastructure).
func NewTrustStore(js jetstream.JetStream) (*TrustStore, error) {
	publisherKV, err := js.KeyValue(context.Background(), natsinfra.PublisherTrustBucket)
	if err != nil {
		return nil, fmt.Errorf("accessing publisher trust KV: %w", err)
	}

	subjectKV, err := js.KeyValue(context.Background(), natsinfra.SubjectRegistryBucket)
	if err != nil {
		return nil, fmt.Errorf("accessing subject registry KV: %w", err)
	}

	return &TrustStore{
		js:          js,
		publisherKV: publisherKV,
		subjectKV:   subjectKV,
	}, nil
}

// IsPublisherTrusted checks if a publisher (issuer + sub) is trusted for a subject.
// Returns true if trusted, false if not trusted, and an error only for lookup failures.
// Fail-closed: any KV error other than key-not-found returns false + error.
//
// This satisfies the authz.TrustLookupFunc interface:
// func(ctx context.Context, subjectID, issuer, sub string) (bool, error)
func (s *TrustStore) IsPublisherTrusted(ctx context.Context, subjectID, issuer, sub string) (bool, error) {
	key := subjectKey(subjectID)

	entry, err := s.publisherKV.Get(ctx, key)
	if err != nil {
		// Key not found means no trust configured for this subject
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return false, nil
		}
		// Any other error is a lookup failure — fail closed
		return false, fmt.Errorf("trust lookup failed for subject %s: %w", subjectID, err)
	}

	// Parse trust list
	var trustList []TrustEntry
	if err := json.Unmarshal(entry.Value(), &trustList); err != nil {
		return false, fmt.Errorf("parsing trust list for subject %s: %w", subjectID, err)
	}

	// Check if issuer+sub combination is in the trust list
	for _, t := range trustList {
		if t.Issuer == issuer && t.Sub == sub {
			return true, nil
		}
	}

	return false, nil
}

// SetPublisherTrust updates the trust list for a subject.
// Replaces the entire trust list with the provided entries.
func (s *TrustStore) SetPublisherTrust(ctx context.Context, subjectID string, publishers []TrustEntry) error {
	key := subjectKey(subjectID)

	data, err := json.Marshal(publishers)
	if err != nil {
		return fmt.Errorf("marshaling trust list: %w", err)
	}

	if _, err := s.publisherKV.Put(ctx, key, data); err != nil {
		return fmt.Errorf("setting trust for subject %s: %w", subjectID, err)
	}

	return nil
}

// RegisterSubject registers a subject in the subject registry.
// This creates an empty entry in the subject registry KV to indicate the subject exists.
func (s *TrustStore) RegisterSubject(ctx context.Context, subjectID string) error {
	// Store a minimal JSON object as the value
	value := []byte("{}")

	if _, err := s.subjectKV.Put(ctx, subjectID, value); err != nil {
		return fmt.Errorf("registering subject %s: %w", subjectID, err)
	}

	return nil
}

// subjectKey formats the KV key for publisher trust lookups.
// Format: subjects.{subject_id}
func subjectKey(subjectID string) string {
	return fmt.Sprintf("subjects.%s", subjectID)
}
