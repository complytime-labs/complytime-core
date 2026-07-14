package receipt_test

import (
	"encoding/json"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDSSEChannelReceipt(t *testing.T) {
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	dsseDigest := "sha256:abc123def456"
	dsseIndex := int64(42)
	subjectID := "github-com-org-repo"
	payloadType := "https://in-toto.io/attestation/scai/attribute-report/v0.2"

	result, err := receipt.BuildDSSEChannelReceipt(dsseDigest, dsseIndex, publisher, subjectID, payloadType)
	require.NoError(t, err)
	require.NotNil(t, result)

	var wrapper map[string]any
	err = json.Unmarshal(result, &wrapper)
	require.NoError(t, err)

	assert.Equal(t, "https://in-toto.io/Statement/v1", wrapper["type"])
	assert.Equal(t, "gemara-dsse-channel-receipt/v1", wrapper["predicate_type"])

	subjects, ok := wrapper["subject"].([]any)
	require.True(t, ok)
	require.Len(t, subjects, 1)
	subject := subjects[0].(map[string]any)
	assert.Equal(t, subjectID, subject["name"])

	predicate, ok := wrapper["predicate"].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, dsseDigest, predicate["evidenceDigest"])

	evidenceIndex, ok := predicate["evidenceIndex"].(float64)
	require.True(t, ok)
	assert.Equal(t, float64(dsseIndex), evidenceIndex)

	publisherData, ok := predicate["publisher"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, publisher.Issuer, publisherData["issuer"])
	assert.Equal(t, publisher.Sub, publisherData["sub"])

	envelope, ok := predicate["contentEnvelope"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, payloadType, envelope["payloadType"])
}
