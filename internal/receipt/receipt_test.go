// internal/receipt/receipt_test.go
package receipt_test

import (
	"encoding/json"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatement_MarshalJSON(t *testing.T) {
	stmt := receipt.Statement{
		Type: receipt.StatementType,
		Subject: []receipt.Subject{{
			Name:   "EvaluationLog/target-123",
			Digest: map[string]string{"sha256": "abc123"},
		}},
		PredicateType: receipt.PredicateType,
		Predicate: receipt.Predicate{
			Content:       json.RawMessage(`{"metadata":{"type":"EvaluationLog"}}`),
			ContentDigest: map[string]string{"sha256": "abc123"},
			ContentFormat: "application/json",
			Publisher: receipt.Publisher{
				Issuer:  "https://token.actions.githubusercontent.com",
				Subject: "repo:acme/myapp",
				Method:  "jwt-channel",
			},
			ArtifactType: "EvaluationLog",
			AuthorType:   "Software",
		},
	}

	data, err := json.Marshal(stmt)
	require.NoError(t, err)

	var roundTrip receipt.Statement
	require.NoError(t, json.Unmarshal(data, &roundTrip))
	assert.Equal(t, receipt.StatementType, roundTrip.Type)
	assert.Equal(t, receipt.PredicateType, roundTrip.PredicateType)
	assert.Equal(t, "abc123", roundTrip.Predicate.ContentDigest["sha256"])
	assert.Equal(t, "repo:acme/myapp", roundTrip.Predicate.Publisher.Subject)
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
