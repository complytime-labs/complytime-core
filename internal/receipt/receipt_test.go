// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapProducesValidStatement(t *testing.T) {
	content := []byte(`{"metadata":{"type":"EvaluationLog"},"target":{"id":"target-123"}}`)
	canonical, digest, err := receipt.Canonicalize(content)
	require.NoError(t, err)

	pub := receipt.Publisher{
		Issuer:  "https://token.actions.githubusercontent.com",
		Subject: "repo:acme/myapp",
		Method:  "jwt-channel",
	}
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	data, err := receipt.Wrap(canonical, digest, pub, "EvaluationLog", "Software", now)
	require.NoError(t, err)

	// Verify it's a valid in-toto v1 Statement
	assert.True(t, receipt.IsReceipt(data))
	assert.Contains(t, string(data), `"_type":"https://in-toto.io/Statement/v1"`)
	assert.Contains(t, string(data), `"predicateType":"https://complytime.dev/gemara-receipt/v1"`)

	// Round-trip through Unwrap
	pred, err := receipt.Unwrap(data)
	require.NoError(t, err)
	assert.Equal(t, digest, pred.ContentDigest["sha256"])
	assert.Equal(t, "repo:acme/myapp", pred.Publisher.Subject)
	assert.Equal(t, "EvaluationLog", pred.ArtifactType)
	assert.Equal(t, "Software", pred.AuthorType)
}

func TestPublisher_JWTChannel(t *testing.T) {
	p := receipt.Publisher{
		Issuer:  "https://example.com",
		Subject: "repo:org/repo",
		Method:  "jwt-channel",
	}
	data, err := json.Marshal(p)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"method":"jwt-channel"`)
}
