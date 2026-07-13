package receipt_test

import (
	"encoding/json"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildChannelAttestation(t *testing.T) {
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	dsseDigest := "sha256:abc123def456"
	dsseIndex := int64(42)
	subjectID := "github.com/org/repo"
	payloadType := "https://in-toto.io/attestation/scai/attribute-report/v0.2"

	result, err := receipt.BuildChannelAttestation(dsseDigest, dsseIndex, publisher, subjectID, payloadType)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Parse result as JSON
	var wrapper map[string]any
	err = json.Unmarshal(result, &wrapper)
	require.NoError(t, err)

	// Check type field
	assert.Equal(t, "https://in-toto.io/Statement/v1", wrapper["type"])

	// Check predicateType
	assert.Equal(t, "gemara-channel-attestation/v1", wrapper["predicate_type"])

	// Check subject
	subjects, ok := wrapper["subject"].([]any)
	require.True(t, ok)
	require.Len(t, subjects, 1)
	subject := subjects[0].(map[string]any)
	assert.Equal(t, subjectID, subject["name"])

	// Check predicate
	predicate, ok := wrapper["predicate"].(map[string]any)
	require.True(t, ok)

	// Verify evidenceDigest
	assert.Equal(t, dsseDigest, predicate["evidenceDigest"])

	// Verify evidenceIndex
	evidenceIndex, ok := predicate["evidenceIndex"].(float64)
	require.True(t, ok)
	assert.Equal(t, float64(dsseIndex), evidenceIndex)

	// Verify publisher identity
	publisherData, ok := predicate["publisher"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, publisher.Issuer, publisherData["issuer"])
	assert.Equal(t, publisher.Sub, publisherData["sub"])

	// Verify contentEnvelope
	envelope, ok := predicate["contentEnvelope"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, payloadType, envelope["payloadType"])
}
