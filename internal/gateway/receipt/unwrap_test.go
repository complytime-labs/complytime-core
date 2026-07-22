package receipt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnwrapContent_JSONReceipt(t *testing.T) {
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	originalContent := []byte(`{"event":"test","timestamp":"2026-07-11T10:00:00Z"}`)
	subjectID := "github-com-org-repo"
	artifactType := "github-workflow-run"

	wrapped, err := receipt.Wrap(originalContent, publisher, subjectID, artifactType)
	require.NoError(t, err)

	result, err := receipt.UnwrapContent(wrapped)
	require.NoError(t, err)

	assert.Equal(t, "gemara-receipt/v1", result.Format)

	require.NotNil(t, result.Publisher)
	assert.Equal(t, publisher.Issuer, result.Publisher.Issuer)
	assert.Equal(t, publisher.Sub, result.Publisher.Sub)

	require.NotNil(t, result.Content)
	var unwrapped, original map[string]any
	require.NoError(t, json.Unmarshal(result.Content, &unwrapped))
	require.NoError(t, json.Unmarshal(originalContent, &original))
	assert.Equal(t, original["event"], unwrapped["event"])
	assert.Equal(t, original["timestamp"], unwrapped["timestamp"])
}

func TestUnwrapContent_DSSEReceipt(t *testing.T) {
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	// DSSE envelope as the content
	dsseEnvelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`)),
		"signatures": []map[string]any{
			{
				"keyid": "test-key",
				"sig":   "test-signature",
			},
		},
	}
	dsseJSON, err := json.Marshal(dsseEnvelope)
	require.NoError(t, err)

	subjectID := "github-com-org-repo"
	artifactType := "dsse"

	// Wrap DSSE as receipt
	wrapped, err := receipt.Wrap(dsseJSON, publisher, subjectID, artifactType)
	require.NoError(t, err)

	result, err := receipt.UnwrapContent(wrapped)
	require.NoError(t, err)

	assert.Equal(t, "gemara-receipt/v1", result.Format)

	require.NotNil(t, result.Publisher)
	assert.Equal(t, publisher.Issuer, result.Publisher.Issuer)
	assert.Equal(t, publisher.Sub, result.Publisher.Sub)

	require.NotNil(t, result.Content)
	// Verify unwrapped content is the DSSE envelope
	var unwrapped map[string]any
	require.NoError(t, json.Unmarshal(result.Content, &unwrapped))
	assert.Equal(t, "application/vnd.in-toto+json", unwrapped["payloadType"])
	assert.NotEmpty(t, unwrapped["signatures"])
}
