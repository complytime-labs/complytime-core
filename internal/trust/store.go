package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

// TrustEntry represents a trusted publisher for a subject.
type TrustEntry struct {
	Issuer string `json:"issuer"`
	Sub    string `json:"sub"`
}

// JWKRecord holds a stored static JWK and its expiry.
type JWKRecord struct {
	JWK      json.RawMessage `json:"jwk"`
	NotAfter time.Time       `json:"not_after"`
}

// TrustStore provides publisher trust lookups and updates against NATS KV.
type TrustStore struct {
	js          jetstream.JetStream
	publisherKV jetstream.KeyValue
	subjectKV   jetstream.KeyValue
	jwkKV       jetstream.KeyValue
	jtiKV       jetstream.KeyValue
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

	jwkKV, err := js.KeyValue(context.Background(), natsinfra.StaticJWKBucket)
	if err != nil {
		return nil, fmt.Errorf("accessing static JWK KV: %w", err)
	}

	jtiKV, err := js.KeyValue(context.Background(), natsinfra.JTIReplayBucket)
	if err != nil {
		return nil, fmt.Errorf("accessing JTI replay KV: %w", err)
	}

	return &TrustStore{
		js:          js,
		publisherKV: publisherKV,
		subjectKV:   subjectKV,
		jwkKV:       jwkKV,
		jtiKV:       jtiKV,
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

// SetPublisherTrust updates the trust list for a subject using compare-and-swap.
// On first write uses Create; subsequent writes use Update with the current revision.
// Returns an error on concurrent modification.
func (s *TrustStore) SetPublisherTrust(ctx context.Context, subjectID string, publishers []TrustEntry) error {
	key := subjectKey(subjectID)

	data, err := json.Marshal(publishers)
	if err != nil {
		return fmt.Errorf("marshaling trust list: %w", err)
	}

	entry, err := s.publisherKV.Get(ctx, key)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			if _, err := s.publisherKV.Create(ctx, key, data); err != nil {
				return fmt.Errorf("creating trust for subject %s: %w", subjectID, err)
			}
			return nil
		}
		return fmt.Errorf("reading current trust for subject %s: %w", subjectID, err)
	}

	if _, err := s.publisherKV.Update(ctx, key, data, entry.Revision()); err != nil {
		return fmt.Errorf("updating trust for subject %s (concurrent modification): %w", subjectID, err)
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

// SubjectExists checks whether a subject has been registered in the subject registry.
func (s *TrustStore) SubjectExists(ctx context.Context, subjectID string) (bool, error) {
	_, err := s.subjectKV.Get(ctx, subjectID)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("checking subject existence %s: %w", subjectID, err)
	}
	return true, nil
}

// subjectKey formats the KV key for publisher trust lookups.
// Format: subjects.{subject_id}
func subjectKey(subjectID string) string {
	return fmt.Sprintf("subjects.%s", subjectID)
}

// StoreJWK stores a static JWK for a scanner issuer.
// issuerID is the stable scanner identity (used as both iss and sub in scanner tokens).
func (s *TrustStore) StoreJWK(ctx context.Context, issuerID string, jwk json.RawMessage, notAfter time.Time) error {
	rec := JWKRecord{JWK: jwk, NotAfter: notAfter.UTC()}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling JWK record: %w", err)
	}
	if _, err := s.jwkKV.Put(ctx, issuerID, data); err != nil {
		return fmt.Errorf("storing JWK for issuer %s: %w", issuerID, err)
	}
	return nil
}

// ClaimJTI atomically claims a JTI for replay prevention.
// Returns an error if the JTI has already been claimed (replay attempt).
// The TTL is informational; the bucket TTL (15 minutes) governs actual expiry.
func (s *TrustStore) ClaimJTI(ctx context.Context, jti string, _ time.Duration) error {
	_, err := s.jtiKV.Create(ctx, jti, []byte("1"))
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			return fmt.Errorf("token jti %q already used (replay attempt)", jti)
		}
		return fmt.Errorf("claiming jti: %w", err)
	}
	return nil
}

// GetJWK retrieves a static JWK record for an issuer.
// Returns nil, nil if not found. Returns nil, nil if the not_after has passed.
func (s *TrustStore) GetJWK(ctx context.Context, issuerID string) (*JWKRecord, error) {
	entry, err := s.jwkKV.Get(ctx, issuerID)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching JWK for issuer %s: %w", issuerID, err)
	}

	var rec JWKRecord
	if err := json.Unmarshal(entry.Value(), &rec); err != nil {
		return nil, fmt.Errorf("parsing JWK record for issuer %s: %w", issuerID, err)
	}

	if time.Now().UTC().After(rec.NotAfter) {
		return nil, nil // expired
	}

	return &rec, nil
}
