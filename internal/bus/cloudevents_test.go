// internal/bus/cloudevents_test.go
package bus

import (
	"encoding/json"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCloudEvent_ProducesValidEnvelope(t *testing.T) {
	type testData struct {
		Name string `json:"name"`
	}
	data := testData{Name: "test"}

	raw, err := NewCloudEvent(EventTypeEvidenceIngested, DefaultSource, "pkg:generic/acme/app@v1", data)
	require.NoError(t, err)

	var evt cloudevents.Event
	require.NoError(t, json.Unmarshal(raw, &evt))
	assert.Equal(t, "1.0", evt.SpecVersion())
	assert.Equal(t, EventTypeEvidenceIngested, evt.Type())
	assert.Equal(t, DefaultSource, evt.Source())
	assert.Equal(t, "pkg:generic/acme/app@v1", evt.Subject())
	assert.NotEmpty(t, evt.ID())
	assert.NotNil(t, evt.Time())
	assert.Equal(t, "application/json", evt.DataContentType())

	var out testData
	require.NoError(t, evt.DataAs(&out))
	assert.Equal(t, "test", out.Name)
}

func TestParseCloudEventData_RoundTrip(t *testing.T) {
	type testData struct {
		Value int `json:"value"`
	}
	data := testData{Value: 42}

	raw, err := NewCloudEvent(EventTypeTargetRegistered, DefaultSource, "tgt-1", data)
	require.NoError(t, err)

	out, err := ParseCloudEventData[testData](raw)
	require.NoError(t, err)
	assert.Equal(t, 42, out.Value)
}

func TestParseCloudEventData_FallbackPlainJSON(t *testing.T) {
	type testData struct {
		Value int `json:"value"`
	}
	plainJSON := []byte(`{"value":99}`)

	out, err := ParseCloudEventData[testData](plainJSON)
	require.NoError(t, err)
	assert.Equal(t, 99, out.Value)
}
