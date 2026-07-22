package receipt_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrap(t *testing.T) {
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	content := []byte(`{"event":"test","timestamp":"2026-07-11T10:00:00Z"}`)
	subjectID := "github.com/org/repo"
	artifactType := "github-workflow-run"

	result, err := receipt.Wrap(content, publisher, subjectID, artifactType)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Parse result as JSON
	var wrapper map[string]any
	err = json.Unmarshal(result, &wrapper)
	require.NoError(t, err)

	// Check type field
	assert.Equal(t, "https://in-toto.io/Statement/v1", wrapper["type"])

	// Check predicateType (uses snake_case in protobuf JSON)
	assert.Equal(t, "gemara-receipt/v1", wrapper["predicate_type"])

	// Check subject
	subjects, ok := wrapper["subject"].([]any)
	require.True(t, ok)
	require.Len(t, subjects, 1)
	subject := subjects[0].(map[string]any)
	assert.Equal(t, subjectID, subject["name"])

	// Check predicate
	predicate, ok := wrapper["predicate"].(map[string]any)
	require.True(t, ok)

	// Verify contentDigest is present
	contentDigest, ok := predicate["contentDigest"].(string)
	require.True(t, ok)
	require.NotEmpty(t, contentDigest)

	// Verify content is base64-encoded
	encodedContent, ok := predicate["content"].(string)
	require.True(t, ok)
	decoded, err := base64.StdEncoding.DecodeString(encodedContent)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify publisher identity
	publisherData, ok := predicate["publisher"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, publisher.Issuer, publisherData["issuer"])
	assert.Equal(t, publisher.Sub, publisherData["sub"])

	// Verify artifactType
	assert.Equal(t, artifactType, predicate["artifactType"])

	// Verify receivedAt is present and valid RFC 3339
	receivedAt, ok := predicate["receivedAt"].(string)
	require.True(t, ok)
	require.NotEmpty(t, receivedAt)
	_, err = time.Parse(time.RFC3339, receivedAt)
	require.NoError(t, err, "receivedAt should be valid RFC 3339")
}

func TestWrap_Determinism(t *testing.T) {
	publisher := receipt.Publisher{
		Issuer: "https://auth.example.com",
		Sub:    "service-account-123",
	}

	content := []byte(`{"event":"test","timestamp":"2026-07-11T10:00:00Z"}`)
	subjectID := "github.com/org/repo"
	artifactType := "github-workflow-run"

	// Wrap twice
	result1, err := receipt.Wrap(content, publisher, subjectID, artifactType)
	require.NoError(t, err)

	result2, err := receipt.Wrap(content, publisher, subjectID, artifactType)
	require.NoError(t, err)

	// Parse both results
	var wrapper1, wrapper2 map[string]any
	require.NoError(t, json.Unmarshal(result1, &wrapper1))
	require.NoError(t, json.Unmarshal(result2, &wrapper2))

	// Extract contentDigest from both
	pred1 := wrapper1["predicate"].(map[string]any)
	pred2 := wrapper2["predicate"].(map[string]any)

	digest1 := pred1["contentDigest"].(string)
	digest2 := pred2["contentDigest"].(string)

	// Same content + publisher should produce same contentDigest
	assert.Equal(t, digest1, digest2)

	// Verify the digest is correct
	h := sha256.New()
	h.Write(content)
	expected := "sha256:" + base64.URLEncoding.EncodeToString(h.Sum(nil))
	assert.Equal(t, expected, digest1)
}
