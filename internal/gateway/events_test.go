package gateway_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	natsgo "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/gateway"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

func TestEventPublisher_PublishEvidenceIngested(t *testing.T) {
	nc := startTestNATS(t)
	ctx := context.Background()

	eventChan := make(chan *natsgo.Msg, 1)
	sub, err := nc.Subscribe("core.evidence.ingested.test-subject", func(msg *natsgo.Msg) {
		eventChan <- msg
	})
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe() }()

	publisher := gateway.NewEventPublisher(nc)
	err = publisher.PublishEvidenceIngested(ctx, gateway.EvidenceIngestedData{
		ContentDigest: "sha256:abc123",
		ArtifactType:  "EvaluationLog",
		StorageRef:    "locker://test-subject/entry/42",
		SubjectID:     "test-subject",
		Publisher:     gateway.PublisherIdentity{Issuer: "https://issuer", Sub: "user"},
	})
	require.NoError(t, err)

	select {
	case msg := <-eventChan:
		var event map[string]any
		require.NoError(t, json.Unmarshal(msg.Data, &event))
		assert.Equal(t, "dev.complytime.evidence.ingested", event["type"])
		assert.Equal(t, "complytime-gateway", event["source"])

		dataRaw, _ := json.Marshal(event["data"])
		var data gateway.EvidenceIngestedData
		require.NoError(t, json.Unmarshal(dataRaw, &data))
		assert.Equal(t, "sha256:abc123", data.ContentDigest)
		assert.Equal(t, "EvaluationLog", data.ArtifactType)
		assert.Equal(t, "locker://test-subject/entry/42", data.StorageRef)
		assert.Equal(t, "https://issuer", data.Publisher.Issuer)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestEventPublisher_PublishEvidenceSealed(t *testing.T) {
	nc := startTestNATS(t)
	ctx := context.Background()

	eventChan := make(chan *natsgo.Msg, 1)
	sub, err := nc.Subscribe("core.evidence.sealed.test-subject", func(msg *natsgo.Msg) {
		eventChan <- msg
	})
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe() }()

	publisher := gateway.NewEventPublisher(nc)
	err = publisher.PublishEvidenceSealed(ctx, gateway.EvidenceSealedData{
		ContentDigest: "sha256:abc123",
		LogIndex:      42,
		ReceiptDigest: "sha256:def456",
		ReceiptType:   "gemara-receipt/v1",
		StorageRef:    "locker://test-subject/entry/42",
		SubjectID:     "test-subject",
	})
	require.NoError(t, err)

	select {
	case msg := <-eventChan:
		var event map[string]any
		require.NoError(t, json.Unmarshal(msg.Data, &event))
		assert.Equal(t, "dev.complytime.evidence.sealed", event["type"])

		dataRaw, _ := json.Marshal(event["data"])
		var data gateway.EvidenceSealedData
		require.NoError(t, json.Unmarshal(dataRaw, &data))
		assert.Equal(t, int64(42), data.LogIndex)
		assert.Equal(t, "gemara-receipt/v1", data.ReceiptType)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestEventPublisher_PublishSubjectRegistered(t *testing.T) {
	nc := startTestNATS(t)
	ctx := context.Background()

	// Subscribe to subject registration events
	eventChan := make(chan *natsgo.Msg, 1)
	sub, err := nc.Subscribe(natsinfra.SubjectRegistration, func(msg *natsgo.Msg) {
		eventChan <- msg
	})
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe() }()

	// Create publisher and publish event
	publisher := gateway.NewEventPublisher(nc)
	err = publisher.PublishSubjectRegistered(ctx, "new-subject")
	require.NoError(t, err)

	// Verify we received the event
	select {
	case msg := <-eventChan:
		// Parse as CloudEvent
		event := cloudevents.NewEvent()
		err := json.Unmarshal(msg.Data, &event)
		require.NoError(t, err)

		// Verify CloudEvent envelope
		assert.Equal(t, "dev.complytime.subject.registered", event.Type())
		assert.Equal(t, "complytime-gateway", event.Source())
		assert.Equal(t, "new-subject", event.Subject())
		assert.Equal(t, cloudevents.VersionV1, event.SpecVersion())

		// Verify event data
		var data map[string]interface{}
		err = json.Unmarshal(event.Data(), &data)
		require.NoError(t, err)
		assert.Equal(t, "new-subject", data["subjectId"])

	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for subject registered event")
	}
}
