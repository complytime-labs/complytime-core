// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/complytime-labs/complytime-core/internal/requirements"
	"github.com/nats-io/nats.go/jetstream"
)

const targetRegistryBucket = "targets-registry"

// TargetStoreKV implements requirements.TargetStore backed by NATS KV.
type TargetStoreKV struct {
	kv jetstream.KeyValue
}

func NewTargetStoreKV(ctx context.Context, js jetstream.JetStream) (*TargetStoreKV, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  targetRegistryBucket,
		History: 5,
	})
	if err != nil {
		return nil, fmt.Errorf("create target registry KV bucket: %w", err)
	}
	return &TargetStoreKV{kv: kv}, nil
}

func (s *TargetStoreKV) InsertTarget(ctx context.Context, t requirements.TargetRow) error {
	data, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal target %s: %w", t.TargetID, err)
	}
	if _, err := s.kv.Put(ctx, t.TargetID, data); err != nil {
		return fmt.Errorf("put target %s: %w", t.TargetID, err)
	}
	return nil
}

func (s *TargetStoreKV) GetLatestTarget(ctx context.Context, targetID string, _ time.Time) (*requirements.TargetRow, error) {
	entry, err := s.kv.Get(ctx, targetID)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get target %s: %w", targetID, err)
	}

	var row requirements.TargetRow
	if err := json.Unmarshal(entry.Value(), &row); err != nil {
		return nil, fmt.Errorf("unmarshal target %s: %w", targetID, err)
	}
	return &row, nil
}

func (s *TargetStoreKV) ListTargets(ctx context.Context) ([]requirements.TargetRow, error) {
	keys, err := s.kv.Keys(ctx)
	if err != nil {
		if errors.Is(err, jetstream.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("list target keys: %w", err)
	}

	var targets []requirements.TargetRow
	for _, key := range keys {
		entry, err := s.kv.Get(ctx, key)
		if err != nil {
			continue
		}
		var row requirements.TargetRow
		if err := json.Unmarshal(entry.Value(), &row); err != nil {
			continue
		}
		targets = append(targets, row)
	}
	return targets, nil
}
