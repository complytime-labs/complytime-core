package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseControlCatalog(t *testing.T) {
	catalogJSON := `{
		"metadata": {
			"id": "test-controls-v1",
			"type": "ControlCatalog",
			"version": "1.0.0",
			"author": {"id": "test", "name": "Test", "type": "Human"},
			"description": "Test catalog",
			"gemara-version": "1.0.0"
		},
		"title": "Test Controls",
		"controls": [
			{
				"id": "CTRL-001",
				"title": "Access Control",
				"objective": "Ensure proper access",
				"group": "access",
				"assessment-requirements": [
					{
						"id": "REQ-001",
						"text": "Verify access logs",
						"applicability": ["all"]
					}
				],
				"threats": [
					{
						"reference-id": "THREAT-001"
					}
				]
			},
			{
				"id": "CTRL-002",
				"title": "Encryption",
				"objective": "Protect data at rest",
				"group": "crypto",
				"assessment-requirements": [
					{
						"id": "REQ-002",
						"text": "Verify encryption",
						"applicability": ["all"]
					}
				],
				"threats": [
					{
						"reference-id": "threat-catalog-v1",
						"entries": [
							{"reference-id": "THREAT-002"},
							{"reference-id": "THREAT-003"}
						]
					}
				]
			}
		]
	}`

	parsed, err := ParseArtifact("ControlCatalog", []byte(catalogJSON), 42)
	require.NoError(t, err)
	assert.Equal(t, "test-controls-v1", parsed.CatalogID)
	assert.Len(t, parsed.Entities, 2)

	// Check first control
	assert.Equal(t, "CTRL-001", parsed.Entities[0].ID)
	assert.Equal(t, "Control", parsed.Entities[0].Label)
	assert.Equal(t, "Access Control", parsed.Entities[0].Properties["title"])
	assert.Equal(t, "Ensure proper access", parsed.Entities[0].Properties["objective"])
	assert.Equal(t, "access", parsed.Entities[0].Properties["group"])
	assert.Equal(t, "test-controls-v1", parsed.Entities[0].Properties["catalogID"])
	assert.Equal(t, int64(42), parsed.Entities[0].EvidenceLogIndex)

	reqTexts := parsed.Entities[0].Properties["assessmentRequirements"].([]string)
	assert.Equal(t, []string{"Verify access logs"}, reqTexts)

	// Check edges
	assert.Len(t, parsed.Edges, 3) // CTRL-001 -> THREAT-001, CTRL-002 -> THREAT-002, CTRL-002 -> THREAT-003

	// First edge
	assert.Equal(t, "CTRL-001", parsed.Edges[0].FromID)
	assert.Equal(t, "Control", parsed.Edges[0].FromLabel)
	assert.Equal(t, "THREAT-001", parsed.Edges[0].ToID)
	assert.Equal(t, "Threat", parsed.Edges[0].ToLabel)
	assert.Equal(t, "ADDRESSES", parsed.Edges[0].EdgeType)

	// Nested edges
	assert.Equal(t, "CTRL-002", parsed.Edges[1].FromID)
	assert.Equal(t, "THREAT-002", parsed.Edges[1].ToID)
	assert.Equal(t, "ADDRESSES", parsed.Edges[1].EdgeType)
}

func TestParseThreatCatalog(t *testing.T) {
	catalogJSON := `{
		"metadata": {
			"id": "test-threats-v1",
			"type": "ThreatCatalog",
			"version": "1.0.0",
			"author": {"id": "test", "name": "Test", "type": "Human"},
			"description": "Test catalog",
			"gemara-version": "1.0.0"
		},
		"title": "Test Threats",
		"threats": [
			{
				"id": "THREAT-001",
				"title": "Unauthorized Access",
				"description": "Attacker gains unauthorized access",
				"group": "access",
				"capabilities": [
					{
						"reference-id": "CAP-001"
					}
				],
				"vectors": [
					{
						"reference-id": "VEC-001"
					}
				]
			},
			{
				"id": "THREAT-002",
				"title": "Data Theft",
				"description": "Attacker steals sensitive data",
				"group": "confidentiality",
				"capabilities": [
					{
						"reference-id": "capability-catalog-v1",
						"entries": [
							{"reference-id": "CAP-002"},
							{"reference-id": "CAP-003"}
						]
					}
				]
			}
		]
	}`

	parsed, err := ParseArtifact("ThreatCatalog", []byte(catalogJSON), 100)
	require.NoError(t, err)
	assert.Equal(t, "test-threats-v1", parsed.CatalogID)
	assert.Len(t, parsed.Entities, 2)

	// Check first threat
	assert.Equal(t, "THREAT-001", parsed.Entities[0].ID)
	assert.Equal(t, "Threat", parsed.Entities[0].Label)
	assert.Equal(t, "Unauthorized Access", parsed.Entities[0].Properties["title"])
	assert.Equal(t, "Attacker gains unauthorized access", parsed.Entities[0].Properties["description"])
	assert.Equal(t, int64(100), parsed.Entities[0].EvidenceLogIndex)

	// Check edges
	assert.Len(t, parsed.Edges, 4) // THREAT-001 -> CAP-001, THREAT-001 -> VEC-001, THREAT-002 -> CAP-002, THREAT-002 -> CAP-003

	// Check capability edge
	capEdge := parsed.Edges[0]
	assert.Equal(t, "THREAT-001", capEdge.FromID)
	assert.Equal(t, "Threat", capEdge.FromLabel)
	assert.Equal(t, "CAP-001", capEdge.ToID)
	assert.Equal(t, "Capability", capEdge.ToLabel)
	assert.Equal(t, "LEVERAGES", capEdge.EdgeType)

	// Check vector edge
	vecEdge := parsed.Edges[1]
	assert.Equal(t, "THREAT-001", vecEdge.FromID)
	assert.Equal(t, "VEC-001", vecEdge.ToID)
	assert.Equal(t, "Vector", vecEdge.ToLabel)
	assert.Equal(t, "LEVERAGES", vecEdge.EdgeType)
}

func TestParseCapabilityCatalog(t *testing.T) {
	catalogJSON := `{
		"metadata": {
			"id": "test-capabilities-v1",
			"type": "CapabilityCatalog",
			"version": "1.0.0",
			"author": {"id": "test", "name": "Test", "type": "Human"},
			"description": "Test catalog",
			"gemara-version": "1.0.0"
		},
		"title": "Test Capabilities",
		"capabilities": [
			{
				"id": "CAP-001",
				"title": "File Upload",
				"description": "Users can upload files",
				"group": "storage"
			},
			{
				"id": "CAP-002",
				"title": "API Access",
				"description": "External API access",
				"group": "integration"
			}
		]
	}`

	parsed, err := ParseArtifact("CapabilityCatalog", []byte(catalogJSON), 50)
	require.NoError(t, err)
	assert.Equal(t, "test-capabilities-v1", parsed.CatalogID)
	assert.Len(t, parsed.Entities, 2)
	assert.Len(t, parsed.Edges, 0) // Capabilities don't introduce edges by themselves

	// Check first capability
	assert.Equal(t, "CAP-001", parsed.Entities[0].ID)
	assert.Equal(t, "Capability", parsed.Entities[0].Label)
	assert.Equal(t, "File Upload", parsed.Entities[0].Properties["title"])
	assert.Equal(t, "Users can upload files", parsed.Entities[0].Properties["description"])
	assert.Equal(t, int64(50), parsed.Entities[0].EvidenceLogIndex)
}

func TestParseArtifact_UnsupportedType(t *testing.T) {
	parsed, err := ParseArtifact("UnknownType", []byte(`{}`), 1)
	require.NoError(t, err)
	assert.Len(t, parsed.Entities, 0)
	assert.Len(t, parsed.Edges, 0)
}

func TestParseArtifact_InvalidJSON(t *testing.T) {
	_, err := ParseArtifact("ControlCatalog", []byte(`{invalid json}`), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshaling")
}
