// internal/bus/cloudevents.go
package bus

import (
	"encoding/json"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"
)

const (
	DefaultSource = "https://complytime.dev/core"

	EventTypeEvidenceIngested  = "dev.complytime.evidence.ingested"
	EventTypePolicyImported    = "dev.complytime.policy.imported"
	EventTypeTargetRegistered  = "dev.complytime.target.registered"
	EventTypeAuditLogDrafted   = "dev.complytime.auditlog.drafted"
)

// NewCloudEvent builds a CloudEvents v1.0 structured-mode JSON message.
func NewCloudEvent(eventType, source, subject string, data any) ([]byte, error) {
	evt := cloudevents.New()
	evt.SetSpecVersion("1.0")
	evt.SetID(uuid.New().String())
	evt.SetType(eventType)
	evt.SetSource(source)
	evt.SetSubject(subject)
	evt.SetTime(time.Now().UTC())
	if err := evt.SetData("application/json", data); err != nil {
		return nil, fmt.Errorf("set event data: %w", err)
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		return nil, fmt.Errorf("marshal cloud event: %w", err)
	}
	return raw, nil
}

// ParseCloudEventData unmarshals a NATS message as a CloudEvent and extracts
// the typed data payload. Falls back to plain JSON unmarshal for backward
// compatibility with pre-CloudEvents messages.
func ParseCloudEventData[T any](msg []byte) (T, error) {
	var zero T
	var evt cloudevents.Event
	if err := json.Unmarshal(msg, &evt); err == nil && evt.SpecVersion() != "" {
		var data T
		if err := evt.DataAs(&data); err != nil {
			return zero, fmt.Errorf("extract cloud event data: %w", err)
		}
		return data, nil
	}
	var data T
	if err := json.Unmarshal(msg, &data); err != nil {
		return zero, fmt.Errorf("unmarshal plain JSON: %w", err)
	}
	return data, nil
}
