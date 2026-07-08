// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeArtifact_YAML(t *testing.T) {
	yamlBody := []byte(`metadata:
  type: EvaluationLog
  version: v1.0.0
target:
  id: target-123
`)
	jsonBytes, err := normalizeArtifact(yamlBody)
	require.NoError(t, err)
	assert.Contains(t, string(jsonBytes), `"type":"EvaluationLog"`)
	assert.Contains(t, string(jsonBytes), `"id":"target-123"`)
}

func TestNormalizeArtifact_JSON(t *testing.T) {
	input := []byte(`{"metadata":{"type":"EvaluationLog","version":"v1.0.0"},"target":{"id":"tgt"}}`)
	jsonBytes, err := normalizeArtifact(input)
	require.NoError(t, err)
	assert.Contains(t, string(jsonBytes), `"type":"EvaluationLog"`)
}

func TestNormalizeArtifact_InvalidYAML(t *testing.T) {
	_, err := normalizeArtifact([]byte(`{{{ invalid`))
	assert.Error(t, err)
}

func TestNormalizeArtifact_MissingType(t *testing.T) {
	_, err := normalizeArtifact([]byte(`target:
  id: tgt-1
`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing metadata.type")
}

func TestNormalizeArtifact_TargetRegistration(t *testing.T) {
	_, err := normalizeArtifact([]byte(`metadata:
  type: TargetRegistration
target:
  id: tgt-1
`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TargetRegistration must use the admin API")
}

func TestDetectAuthorType(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{"present", []byte("metadata:\n  author:\n    type: Software"), "Software"},
		{"missing", []byte("metadata:\n  type: EvaluationLog"), ""},
		{"human", []byte("metadata:\n  author:\n    type: Human"), "Human"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, detectAuthorType(tt.body))
		})
	}
}
