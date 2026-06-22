// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/complytime-labs/complytime-core/internal/requirements"
	"github.com/nats-io/nats.go/jetstream"
)

const publisherTrustBucket = "publisher-trust"

// PublisherTrustKV implements requirements.TrustedPublisherStore backed by NATS KV.
type PublisherTrustKV struct {
	kv jetstream.KeyValue
}

func NewPublisherTrustKV(ctx context.Context, js jetstream.JetStream) (*PublisherTrustKV, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  publisherTrustBucket,
		History: 10,
	})
	if err != nil {
		return nil, fmt.Errorf("create publisher trust KV bucket: %w", err)
	}
	return &PublisherTrustKV{kv: kv}, nil
}

func (s *PublisherTrustKV) InsertTrustedPublishers(ctx context.Context, rows []requirements.TrustedPublisherRow) error {
	byTarget := make(map[string][]requirements.TrustedPublisherRow)
	for _, r := range rows {
		byTarget[r.TargetID] = append(byTarget[r.TargetID], r)
	}

	for targetID, newRows := range byTarget {
		existing, err := s.GetTrustedPublishers(ctx, targetID)
		if err != nil {
			return err
		}

		merged := upsertPublishers(existing, newRows)

		data, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("marshal publishers for %s: %w", targetID, err)
		}
		if _, err := s.kv.Put(ctx, kvKey(targetID), data); err != nil {
			return fmt.Errorf("put publishers for %s: %w", targetID, err)
		}
	}
	return nil
}

func (s *PublisherTrustKV) GetTrustedPublishers(ctx context.Context, targetID string) ([]requirements.TrustedPublisherRow, error) {
	entry, err := s.kv.Get(ctx, kvKey(targetID))
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get publishers for %s: %w", targetID, err)
	}

	var rows []requirements.TrustedPublisherRow
	if err := json.Unmarshal(entry.Value(), &rows); err != nil {
		return nil, fmt.Errorf("unmarshal publishers for %s: %w", targetID, err)
	}
	return rows, nil
}

func (s *PublisherTrustKV) RemoveTrustedPublishers(ctx context.Context, targetID string, keys []requirements.TrustedPublisherKey, logIndex uint64) error {
	existing, err := s.GetTrustedPublishers(ctx, targetID)
	if err != nil {
		return err
	}

	remove := make(map[string]bool)
	for _, k := range keys {
		remove[k.Issuer+"\x00"+k.SubPattern] = true
	}

	var kept []requirements.TrustedPublisherRow
	for _, r := range existing {
		if !remove[r.Issuer+"\x00"+r.SubPattern] {
			kept = append(kept, r)
		}
	}

	if len(kept) == 0 {
		if err := s.kv.Delete(ctx, kvKey(targetID)); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
			return fmt.Errorf("delete publishers for %s: %w", targetID, err)
		}
		return nil
	}

	data, err := json.Marshal(kept)
	if err != nil {
		return fmt.Errorf("marshal publishers for %s: %w", targetID, err)
	}
	if _, err := s.kv.Put(ctx, kvKey(targetID), data); err != nil {
		return fmt.Errorf("put publishers for %s: %w", targetID, err)
	}
	return nil
}

func kvKey(targetID string) string {
	return "targets." + targetID
}

func upsertPublishers(existing, incoming []requirements.TrustedPublisherRow) []requirements.TrustedPublisherRow {
	idx := make(map[string]int)
	for i, r := range existing {
		idx[r.Issuer+"\x00"+r.SubPattern] = i
	}
	for _, r := range incoming {
		key := r.Issuer + "\x00" + r.SubPattern
		if i, ok := idx[key]; ok {
			existing[i] = r
		} else {
			existing = append(existing, r)
		}
	}
	return existing
}
