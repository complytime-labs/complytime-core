package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const (
	// Stream names
	StreamIngest = "INGEST"

	// KV bucket names
	PublisherTrustBucket = "publisher-trust"
	SubjectRegistryBucket = "subjects-registry"

	// Consumer names
	ConsumerIngestWorker = "ingest-worker"
)

// IngestStreamConfig returns the JetStream stream configuration.
// Designed for production: file storage, dedup window, work-queue retention.
// Replicas should be increased to 3 for a production NATS cluster.
func IngestStreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:            StreamIngest,
		Description:     "Evidence ingest work queue — gateway enqueues, worker seals into locker",
		Subjects:        []string{SubjectIngest},
		Retention:       jetstream.WorkQueuePolicy,
		MaxConsumers:    -1,
		MaxMsgs:         -1,
		MaxBytes:        -1,
		MaxAge:          72 * time.Hour,
		Storage:         jetstream.FileStorage,
		Replicas:        1,
		Discard:         jetstream.DiscardOld,
		Duplicates:      2 * time.Minute,
		MaxMsgSize:      4 * 1024 * 1024, // 4 MiB per message
	}
}

// IngestConsumerConfig returns the durable pull consumer configuration
// for the ingest worker.
func IngestConsumerConfig() jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Durable:       ConsumerIngestWorker,
		Description:   "Seals receipts into the locker and publishes CloudEvents",
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    5,
		FilterSubject: SubjectIngest,
	}
}

// PublisherTrustKVConfig returns the KV bucket configuration for publisher trust.
// Values are JSON arrays of trusted publisher entries per subject.
func PublisherTrustKVConfig() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:      PublisherTrustBucket,
		Description: "Publisher trust allowlist per subject — key: subjects.{subject_id}",
		Storage:     jetstream.FileStorage,
		History:     10,
		Replicas:    1,
	}
}

// SubjectRegistryKVConfig returns the KV bucket configuration for subject registration.
func SubjectRegistryKVConfig() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:      SubjectRegistryBucket,
		Description: "Registered subjects — key: {subject_id}",
		Storage:     jetstream.FileStorage,
		History:     5,
		Replicas:    1,
	}
}

// EnsureInfrastructure creates or updates all NATS streams and KV buckets.
// Idempotent — safe to call on every service startup.
func EnsureInfrastructure(ctx context.Context, js jetstream.JetStream) error {
	if _, err := js.CreateOrUpdateStream(ctx, IngestStreamConfig()); err != nil {
		return fmt.Errorf("ensuring ingest stream: %w", err)
	}

	for _, kv := range []jetstream.KeyValueConfig{
		PublisherTrustKVConfig(),
		SubjectRegistryKVConfig(),
	} {
		if _, err := js.CreateOrUpdateKeyValue(ctx, kv); err != nil {
			return fmt.Errorf("ensuring KV bucket %s: %w", kv.Bucket, err)
		}
	}

	return nil
}
