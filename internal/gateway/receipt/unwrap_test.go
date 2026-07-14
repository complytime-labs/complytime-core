package receipt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnwrapContent_Receipt(t *testing.T) {
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

	assert.False(t, result.IsDSSE)
	assert.False(t, result.IsDSSEChannelReceipt)
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

func TestUnwrapContent_DSSE(t *testing.T) {
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

	result, err := receipt.UnwrapContent(dsseJSON)
	require.NoError(t, err)

	assert.True(t, result.IsDSSE)
	assert.False(t, result.IsDSSEChannelReceipt)
	assert.Equal(t, "dsse", result.Format)
	assert.Equal(t, dsseJSON, result.Content)
	assert.Nil(t, result.Publisher)
}

func TestUnwrapContent_DSSEChannelReceipt(t *testing.T) {
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	dsseDigest := "sha256:abc123def456"
	dsseIndex := int64(42)
	subjectID := "github-com-org-repo"
	payloadType := "https://in-toto.io/attestation/scai/attribute-report/v0.2"

	channelReceipt, err := receipt.BuildDSSEChannelReceipt(dsseDigest, dsseIndex, publisher, subjectID, payloadType)
	require.NoError(t, err)

	result, err := receipt.UnwrapContent(channelReceipt)
	require.NoError(t, err)

	assert.False(t, result.IsDSSE)
	assert.True(t, result.IsDSSEChannelReceipt)
	assert.Equal(t, "gemara-dsse-channel-receipt/v1", result.Format)

	require.NotNil(t, result.Publisher)
	assert.Equal(t, publisher.Issuer, result.Publisher.Issuer)
	assert.Equal(t, publisher.Sub, result.Publisher.Sub)

	assert.Nil(t, result.Content)
}
