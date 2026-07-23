package graph

import (
	"encoding/json"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/events"
)

func TestParseCloudEvent_Ingested(t *testing.T) {
	event := cloudevents.NewEvent()
	event.SetType(events.TypeEvidenceIngested)
	event.SetSource("complytime-gateway")
	event.SetSubject("my-app-v1")

	data := events.EvidenceIngestedData{
		ContentDigest: "sha256:abc123",
		ArtifactType:  "ControlCatalog",
		StorageRef:    "locker://my-app-v1/1",
		SubjectID:     "my-app-v1",
		Publisher:     events.PublisherIdentity{Issuer: "https://idp", Sub: "ci"},
	}
	require.NoError(t, event.SetData(cloudevents.ApplicationJSON, data))

	eventJSON, err := json.Marshal(event)
	require.NoError(t, err)

	parsed, err := parseCloudEvent(eventJSON)
	require.NoError(t, err)
	assert.Equal(t, events.TypeEvidenceIngested, parsed.Type())
	assert.Equal(t, "my-app-v1", parsed.Subject())

	var parsedData events.EvidenceIngestedData
	require.NoError(t, parsed.DataAs(&parsedData))
	assert.Equal(t, "sha256:abc123", parsedData.ContentDigest)
	assert.Equal(t, "ControlCatalog", parsedData.ArtifactType)
	assert.Equal(t, "my-app-v1", parsedData.SubjectID)
	assert.Equal(t, "https://idp", parsedData.Publisher.Issuer)
	assert.Equal(t, "ci", parsedData.Publisher.Sub)
}

func TestParseCloudEvent_Sealed(t *testing.T) {
	event := cloudevents.NewEvent()
	event.SetType(events.TypeEvidenceSealed)
	event.SetSource("complytime-gateway")
	event.SetSubject("my-app-v1")

	data := events.EvidenceSealedData{
		ContentDigest: "sha256:abc123",
		LogIndex:      42,
		ReceiptDigest: "sha256:def456",
		ReceiptType:   "gemara-receipt/v1",
		StorageRef:    "locker://my-app-v1/42",
		SubjectID:     "my-app-v1",
	}
	require.NoError(t, event.SetData(cloudevents.ApplicationJSON, data))

	eventJSON, err := json.Marshal(event)
	require.NoError(t, err)

	parsed, err := parseCloudEvent(eventJSON)
	require.NoError(t, err)
	assert.Equal(t, events.TypeEvidenceSealed, parsed.Type())
	assert.Equal(t, "my-app-v1", parsed.Subject())

	var parsedData events.EvidenceSealedData
	require.NoError(t, parsed.DataAs(&parsedData))
	assert.Equal(t, "sha256:abc123", parsedData.ContentDigest)
	assert.Equal(t, int64(42), parsedData.LogIndex)
	assert.Equal(t, "sha256:def456", parsedData.ReceiptDigest)
	assert.Equal(t, "locker://my-app-v1/42", parsedData.StorageRef)
}

func TestParseCloudEvent_SubjectRegistered(t *testing.T) {
	event := cloudevents.NewEvent()
	event.SetType(events.TypeSubjectRegistered)
	event.SetSource("complytime-gateway")
	event.SetSubject("my-app-v1")

	data := events.SubjectRegisteredData{
		SubjectID: "my-app-v1",
	}
	require.NoError(t, event.SetData(cloudevents.ApplicationJSON, data))

	eventJSON, err := json.Marshal(event)
	require.NoError(t, err)

	parsed, err := parseCloudEvent(eventJSON)
	require.NoError(t, err)
	assert.Equal(t, events.TypeSubjectRegistered, parsed.Type())

	var parsedData events.SubjectRegisteredData
	require.NoError(t, parsed.DataAs(&parsedData))
	assert.Equal(t, "my-app-v1", parsedData.SubjectID)
}

func TestParseCloudEvent_InvalidJSON(t *testing.T) {
	invalidJSON := []byte(`{"not": "a cloudevent"}`)
	_, err := parseCloudEvent(invalidJSON)
	require.Error(t, err)
}

func TestInferArtifactType(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "ControlCatalog",
			data:     `{"metadata": {"type": "ControlCatalog"}}`,
			expected: "ControlCatalog",
		},
		{
			name:     "ThreatCatalog",
			data:     `{"metadata": {"type": "ThreatCatalog"}}`,
			expected: "ThreatCatalog",
		},
		{
			name:     "InvalidJSON",
			data:     `{invalid}`,
			expected: "unknown",
		},
		{
			name:     "MissingMetadata",
			data:     `{"title": "Test"}`,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferArtifactType([]byte(tt.data))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "UnmarshalTypeError",
			err:      &json.UnmarshalTypeError{},
			expected: true,
		},
		{
			name:     "SyntaxError",
			err:      &json.SyntaxError{},
			expected: true,
		},
		{
			name:     "NetworkError",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPermanentError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
