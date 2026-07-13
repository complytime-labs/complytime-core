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
	// First create a receipt
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	originalContent := []byte(`{"event":"test","timestamp":"2026-07-11T10:00:00Z"}`)
	subjectID := "github.com/org/repo"
	artifactType := "github-workflow-run"

	wrapped, err := receipt.Wrap(originalContent, publisher, subjectID, artifactType)
	require.NoError(t, err)

	// Now unwrap it
	result, err := receipt.UnwrapContent(wrapped)
	require.NoError(t, err)

	// Verify it was recognized as a receipt
	assert.False(t, result.IsDSSE)
	assert.False(t, result.IsChannelAttestation)
	assert.Equal(t, "gemara-receipt/v1", result.Format)

	// Verify publisher was extracted
	require.NotNil(t, result.Publisher)
	assert.Equal(t, publisher.Issuer, result.Publisher.Issuer)
	assert.Equal(t, publisher.Sub, result.Publisher.Sub)

	// Verify content was decoded
	require.NotNil(t, result.Content)
	// Content should be JCS-canonicalized version
	var unwrapped, original map[string]any
	require.NoError(t, json.Unmarshal(result.Content, &unwrapped))
	require.NoError(t, json.Unmarshal(originalContent, &original))
	assert.Equal(t, original["event"], unwrapped["event"])
	assert.Equal(t, original["timestamp"], unwrapped["timestamp"])
}

func TestUnwrapContent_DSSE(t *testing.T) {
	// Create a mock DSSE envelope
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

	// Unwrap it
	result, err := receipt.UnwrapContent(dsseJSON)
	require.NoError(t, err)

	// Verify it was recognized as DSSE
	assert.True(t, result.IsDSSE)
	assert.False(t, result.IsChannelAttestation)
	assert.Equal(t, "dsse", result.Format)

	// Content should be returned as-is
	assert.Equal(t, dsseJSON, result.Content)

	// No publisher for DSSE (it's in the signature)
	assert.Nil(t, result.Publisher)
}

func TestUnwrapContent_ChannelAttestation(t *testing.T) {
	// Create a channel attestation
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	dsseDigest := "sha256:abc123def456"
	dsseIndex := int64(42)
	subjectID := "github.com/org/repo"
	payloadType := "https://in-toto.io/attestation/scai/attribute-report/v0.2"

	attestation, err := receipt.BuildChannelAttestation(dsseDigest, dsseIndex, publisher, subjectID, payloadType)
	require.NoError(t, err)

	// Unwrap it
	result, err := receipt.UnwrapContent(attestation)
	require.NoError(t, err)

	// Verify it was recognized as a channel attestation
	assert.False(t, result.IsDSSE)
	assert.True(t, result.IsChannelAttestation)
	assert.Equal(t, "gemara-channel-attestation/v1", result.Format)

	// Verify publisher was extracted
	require.NotNil(t, result.Publisher)
	assert.Equal(t, publisher.Issuer, result.Publisher.Issuer)
	assert.Equal(t, publisher.Sub, result.Publisher.Sub)

	// No content extraction for channel attestations (they're references)
	assert.Nil(t, result.Content)
}
