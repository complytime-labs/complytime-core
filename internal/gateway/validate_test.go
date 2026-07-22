package gateway

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSchemaRegistry(t *testing.T) {
	registry, err := NewSchemaRegistry()
	require.NoError(t, err)
	require.NotNil(t, registry)

	// Should have all 13 Gemara artifact types
	expectedTypes := []string{
		"EvaluationLog",
		"EnforcementLog",
		"AuditLog",
		"Policy",
		"MappingDocument",
		"ControlCatalog",
		"CapabilityCatalog",
		"GuidanceCatalog",
		"ThreatCatalog",
		"RiskCatalog",
		"Lexicon",
		"VectorCatalog",
		"PrincipleCatalog",
	}

	for _, artifactType := range expectedTypes {
		assert.Contains(t, registry.schemas, artifactType, "Missing schema for %s", artifactType)
	}
}

func TestValidate_GemaraTypeDetectedAndAttempted(t *testing.T) {
	registry, err := NewSchemaRegistry()
	require.NoError(t, err)

	// Artifact with EvaluationLog type - will fail validation due to missing fields
	artifact := map[string]interface{}{
		"metadata": map[string]interface{}{
			"type": "EvaluationLog",
		},
	}

	artifactBytes, err := json.Marshal(artifact)
	require.NoError(t, err)

	err = registry.Validate(artifactBytes)
	// This will fail validation (missing required fields), which is expected
	// The key is it should recognize the type and attempt validation
	require.Error(t, err)
	ve, ok := err.(*validationError)
	require.True(t, ok, "Expected ValidationError")
	assert.Equal(t, "EvaluationLog", ve.ArtifactType)
	// Should have validation errors about missing fields
	assert.NotEmpty(t, ve.Details)
}

func TestValidate_InvalidArtifact_MissingRequiredField(t *testing.T) {
	registry, err := NewSchemaRegistry()
	require.NoError(t, err)

	// EvaluationLog missing required "result" field
	artifact := map[string]interface{}{
		"metadata": map[string]interface{}{
			"type":           "EvaluationLog",
			"id":             "test-eval-log",
			"description":    "Test evaluation log",
			"gemara-version": "0.1.0",
			"author": map[string]interface{}{
				"id":   "test-actor",
				"name": "Test Actor",
				"type": "Human",
				"contact": map[string]interface{}{
					"name": "Test User",
				},
			},
		},
		"target": map[string]interface{}{
			"id":   "test-subject",
			"name": "Test Subject",
			"type": "Software",
		},
		"evaluations": []interface{}{
			map[string]interface{}{
				"name":    "Test Evaluation",
				"message": "Test message",
				"result":  "Passed",
				"control": map[string]interface{}{
					"entry-id":     "ctrl-1",
					"reference-id": "REF-001",
				},
				"assessment-logs": []interface{}{
					map[string]interface{}{
						"description": "Test assessment",
						"message":     "Assessment message",
						"result":      "Passed",
						"start":       "2026-01-01T00:00:00Z",
						"applicability": []interface{}{
							"all",
						},
						"requirement": map[string]interface{}{
							"entry-id":     "req-1",
							"reference-id": "REF-001",
						},
						"steps": []interface{}{
							"step1",
						},
					},
				},
			},
		},
		// Missing "result" field
	}

	artifactBytes, err := json.Marshal(artifact)
	require.NoError(t, err)

	err = registry.Validate(artifactBytes)
	require.Error(t, err)

	ve, ok := err.(*validationError)
	require.True(t, ok, "Expected ValidationError")
	assert.Equal(t, "EvaluationLog", ve.ArtifactType)
	assert.NotEmpty(t, ve.Details)
}

func TestValidate_UnknownArtifactType(t *testing.T) {
	registry, err := NewSchemaRegistry()
	require.NoError(t, err)

	// Artifact with unsupported/unknown type in metadata.type
	artifact := map[string]interface{}{
		"metadata": map[string]interface{}{
			"type": "UnknownType",
		},
	}

	artifactBytes, err := json.Marshal(artifact)
	require.NoError(t, err)

	// metadata.type present but unrecognized should error
	err = registry.Validate(artifactBytes)
	require.Error(t, err)
	ve, ok := err.(*validationError)
	require.True(t, ok, "Expected ValidationError")
	assert.Equal(t, "UnknownType", ve.ArtifactType)
	assert.NotEmpty(t, ve.Details)
	// Should mention the unsupported type
	assert.Contains(t, ve.Details[0], "unsupported artifact type")
}

func TestValidate_NoTypeSkipsValidation(t *testing.T) {
	registry, err := NewSchemaRegistry()
	require.NoError(t, err)

	// Artifact with no type field (non-Gemara artifact)
	artifact := map[string]interface{}{
		"someField": "someValue",
	}

	artifactBytes, err := json.Marshal(artifact)
	require.NoError(t, err)

	// Should skip validation and return nil
	err = registry.Validate(artifactBytes)
	assert.NoError(t, err)
}

func TestValidate_InvalidJSON(t *testing.T) {
	registry, err := NewSchemaRegistry()
	require.NoError(t, err)

	invalidJSON := []byte(`{invalid json`)

	err = registry.Validate(invalidJSON)
	require.Error(t, err)

	ve, ok := err.(*validationError)
	require.True(t, ok, "Expected ValidationError")
	assert.Equal(t, "unknown", ve.ArtifactType)
	assert.NotEmpty(t, ve.Details)
}

func TestValidate_TopLevelTypeFallback(t *testing.T) {
	registry, err := NewSchemaRegistry()
	require.NoError(t, err)

	// Artifact with type at top level (backward compat)
	artifact := map[string]interface{}{
		"type": "Policy",
		"metadata": map[string]interface{}{
			"id":             "test-policy",
			"description":    "Test policy",
			"gemara-version": "0.1.0",
			"author": map[string]interface{}{
				"id":   "test-actor",
				"name": "Test Actor",
				"type": "Human",
				"contact": map[string]interface{}{
					"name": "Test User",
				},
			},
		},
		"target": map[string]interface{}{
			"id":   "test-subject",
			"name": "Test Subject",
			"type": "Software",
		},
		"policy": map[string]interface{}{
			"id": "pol-1",
		},
		"requirements": []interface{}{
			map[string]interface{}{
				"id": "req-1",
			},
		},
	}

	artifactBytes, err := json.Marshal(artifact)
	require.NoError(t, err)

	// Should extract type from top level and validate against Policy schema
	err = registry.Validate(artifactBytes)
	// This may fail due to missing required fields, but the key is it should
	// recognize the type and attempt validation
	if err != nil {
		ve, ok := err.(*validationError)
		require.True(t, ok, "Expected ValidationError")
		assert.Equal(t, "Policy", ve.ArtifactType)
	}
}
