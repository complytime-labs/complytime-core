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

func TestEventPublisher_PublishEvidenceSealed(t *testing.T) {
	nc := startTestNATS(t)
	ctx := context.Background()

	// Subscribe to evidence events
	eventChan := make(chan *natsgo.Msg, 1)
	sub, err := nc.Subscribe(natsinfra.EvidenceSubject("test-subject"), func(msg *natsgo.Msg) {
		eventChan <- msg
	})
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe() }()

	// Create publisher and publish event
	publisher := gateway.NewEventPublisher(nc)
	err = publisher.PublishEvidenceSealed(ctx, "test-subject", 42, "sha256:abc123", "application/vnd.dsse.envelope.v1+json")
	require.NoError(t, err)

	// Verify we received the event
	select {
	case msg := <-eventChan:
		// Parse as CloudEvent
		event := cloudevents.NewEvent()
		err := json.Unmarshal(msg.Data, &event)
		require.NoError(t, err)

		// Verify CloudEvent envelope
		assert.Equal(t, "dev.complytime.evidence.sealed", event.Type())
		assert.Equal(t, "complytime-gateway", event.Source())
		assert.Equal(t, "test-subject", event.Subject())
		assert.Equal(t, cloudevents.VersionV1, event.SpecVersion())

		// Verify event data
		var data map[string]interface{}
		err = json.Unmarshal(event.Data(), &data)
		require.NoError(t, err)
		assert.Equal(t, "test-subject", data["subjectId"])
		assert.Equal(t, float64(42), data["logIndex"]) // JSON numbers are float64
		assert.Equal(t, "sha256:abc123", data["digest"])
		assert.Equal(t, "application/vnd.dsse.envelope.v1+json", data["contentFormat"])

	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for evidence sealed event")
	}
}

func TestEventPublisher_PublishEvidenceSealedWithRef(t *testing.T) {
	nc := startTestNATS(t)
	ctx := context.Background()

	// Subscribe to evidence events
	eventChan := make(chan *natsgo.Msg, 1)
	sub, err := nc.Subscribe(natsinfra.EvidenceSubject("test-subject"), func(msg *natsgo.Msg) {
		eventChan <- msg
	})
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe() }()

	// Create publisher and publish event with reference
	publisher := gateway.NewEventPublisher(nc)
	err = publisher.PublishEvidenceSealedWithRef(ctx, "test-subject", 43, "sha256:def456", "application/vnd.in-toto+json", "sha256:ref999")
	require.NoError(t, err)

	// Verify we received the event
	select {
	case msg := <-eventChan:
		// Parse as CloudEvent
		event := cloudevents.NewEvent()
		err := json.Unmarshal(msg.Data, &event)
		require.NoError(t, err)

		// Verify CloudEvent envelope
		assert.Equal(t, "dev.complytime.evidence.sealed", event.Type())
		assert.Equal(t, "complytime-gateway", event.Source())
		assert.Equal(t, "test-subject", event.Subject())

		// Verify event data includes refDigest
		var data map[string]interface{}
		err = json.Unmarshal(event.Data(), &data)
		require.NoError(t, err)
		assert.Equal(t, "test-subject", data["subjectId"])
		assert.Equal(t, float64(43), data["logIndex"])
		assert.Equal(t, "sha256:def456", data["digest"])
		assert.Equal(t, "application/vnd.in-toto+json", data["contentFormat"])
		assert.Equal(t, "sha256:ref999", data["refDigest"])

	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for evidence sealed event with ref")
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
