// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrap_ProducesValidStatement(t *testing.T) {
	content := []byte(`{"metadata":{"type":"EvaluationLog"},"target":{"id":"tgt-1"}}`)
	canonical, digest, err := receipt.Canonicalize(content)
	require.NoError(t, err)

	pub := receipt.Publisher{
		Issuer:  "https://token.actions.githubusercontent.com",
		Subject: "repo:acme/myapp",
		Method:  "jwt-channel",
	}
	now := time.Date(2026, 6, 29, 20, 0, 0, 0, time.UTC)
	data, err := receipt.Wrap(canonical, digest, pub, "EvaluationLog", "Software", now)
	require.NoError(t, err)

	assert.True(t, receipt.IsReceipt(data))
	assert.Contains(t, string(data), `"_type":"https://in-toto.io/Statement/v1"`)
	assert.Contains(t, string(data), `"EvaluationLog/tgt-1"`)

	pred, err := receipt.Unwrap(data)
	require.NoError(t, err)
	assert.Equal(t, digest, pred.ContentDigest["sha256"])
	assert.Equal(t, "application/json", pred.ContentFormat)
	assert.Equal(t, "Software", pred.AuthorType)
	assert.Equal(t, pub.Issuer, pred.Publisher.Issuer)
}

func TestWrap_ContentPreservedAsRawJSON(t *testing.T) {
	content := []byte(`{"alpha":1,"beta":"two"}`)
	canonical, digest, err := receipt.Canonicalize(content)
	require.NoError(t, err)

	pub := receipt.Publisher{Issuer: "iss", Subject: "sub", Method: "jwt-channel"}
	data, err := receipt.Wrap(canonical, digest, pub, "EvaluationLog", "", time.Now())
	require.NoError(t, err)

	pred, err := receipt.Unwrap(data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"alpha":1,"beta":"two"}`, string(pred.Content))
}

func TestUnwrap_VerifiesDigest(t *testing.T) {
	content := []byte(`{"metadata":{"type":"EvaluationLog"}}`)
	canonical, digest, err := receipt.Canonicalize(content)
	require.NoError(t, err)

	pub := receipt.Publisher{Issuer: "iss", Subject: "sub", Method: "jwt-channel"}
	data, err := receipt.Wrap(canonical, digest, pub, "EvaluationLog", "Software", time.Now())
	require.NoError(t, err)

	pred, err := receipt.Unwrap(data)
	require.NoError(t, err)
	assert.Equal(t, "EvaluationLog", pred.ArtifactType)
	assert.Equal(t, "Software", pred.AuthorType)
	assert.Equal(t, "iss", pred.Publisher.Issuer)
	assert.JSONEq(t, string(canonical), string(pred.Content))
}

func TestUnwrap_RejectsCorruptedContent(t *testing.T) {
	content := []byte(`{"metadata":{"type":"EvaluationLog"}}`)
	canonical, digest, err := receipt.Canonicalize(content)
	require.NoError(t, err)

	pub := receipt.Publisher{Issuer: "iss", Subject: "sub", Method: "jwt-channel"}
	data, err := receipt.Wrap(canonical, digest, pub, "EvaluationLog", "", time.Now())
	require.NoError(t, err)

	// Corrupt the content to simulate tampering — change a value in the stored content
	tampered := bytes.ReplaceAll(data, []byte(`EvaluationLog`), []byte(`TamperedValue`))
	_, err = receipt.Unwrap(tampered)
	assert.ErrorContains(t, err, "digest mismatch")
}

func TestIsReceipt(t *testing.T) {
	content := []byte(`{"metadata":{"type":"EvaluationLog"}}`)
	canonical, digest, err := receipt.Canonicalize(content)
	require.NoError(t, err)

	pub := receipt.Publisher{Issuer: "iss", Subject: "sub", Method: "jwt-channel"}
	data, err := receipt.Wrap(canonical, digest, pub, "EvaluationLog", "", time.Now())
	require.NoError(t, err)

	assert.True(t, receipt.IsReceipt(data))
	assert.False(t, receipt.IsReceipt([]byte(`metadata:\n  type: EvaluationLog`)))
	assert.False(t, receipt.IsReceipt([]byte(`{"payload":"abc","payloadType":"application/json"}`)))
}
