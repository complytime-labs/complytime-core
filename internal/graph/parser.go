package graph

import (
	"encoding/json"
	"fmt"

	"github.com/gemaraproj/go-gemara"
)

// ParsedArtifact contains the entities and edges extracted from a Gemara artifact.
type ParsedArtifact struct {
	CatalogID string
	Entities  []EntityRecord
	Edges     []EdgeRecord
}

// ParseArtifact parses a Gemara artifact and extracts entities and edges.
func ParseArtifact(artifactType string, data []byte, evidenceLogIndex int64) (*ParsedArtifact, error) {
	switch artifactType {
	case "ControlCatalog":
		return parseControlCatalog(data, evidenceLogIndex)
	case "ThreatCatalog":
		return parseThreatCatalog(data, evidenceLogIndex)
	case "CapabilityCatalog":
		return parseCapabilityCatalog(data, evidenceLogIndex)
	default:
		return &ParsedArtifact{Entities: []EntityRecord{}, Edges: []EdgeRecord{}}, nil
	}
}

func parseControlCatalog(data []byte, logIndex int64) (*ParsedArtifact, error) {
	var catalog gemara.ControlCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshaling ControlCatalog: %w", err)
	}

	result := &ParsedArtifact{
		CatalogID: catalog.Metadata.Id,
		Entities:  []EntityRecord{},
		Edges:     []EdgeRecord{},
	}

	for _, control := range catalog.Controls {
		props := map[string]any{
			"title":     control.Title,
			"objective": control.Objective,
			"group":     control.Group,
			"catalogID": catalog.Metadata.Id,
		}

		var reqTexts []string
		for _, req := range control.AssessmentRequirements {
			reqTexts = append(reqTexts, req.Text)
		}
		if len(reqTexts) > 0 {
			props["assessmentRequirements"] = reqTexts
		}

		result.Entities = append(result.Entities, EntityRecord{
			ID:               control.Id,
			Label:            "Control",
			Properties:       props,
			EvidenceLogIndex: logIndex,
		})

		for _, threatMapping := range control.Threats {
			for _, entry := range threatMapping.Entries {
				if entry.ReferenceId != "" {
					result.Edges = append(result.Edges, EdgeRecord{
						FromID:    control.Id,
						FromLabel: "Control",
						ToID:      entry.ReferenceId,
						ToLabel:   "Threat",
						EdgeType:  "ADDRESSES",
					})
				}
			}
		}
	}

	return result, nil
}

func parseThreatCatalog(data []byte, logIndex int64) (*ParsedArtifact, error) {
	var catalog gemara.ThreatCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshaling ThreatCatalog: %w", err)
	}

	result := &ParsedArtifact{
		CatalogID: catalog.Metadata.Id,
		Entities:  []EntityRecord{},
		Edges:     []EdgeRecord{},
	}

	for _, threat := range catalog.Threats {
		props := map[string]any{
			"title":       threat.Title,
			"description": threat.Description,
			"group":       threat.Group,
		}

		result.Entities = append(result.Entities, EntityRecord{
			ID:               threat.Id,
			Label:            "Threat",
			Properties:       props,
			EvidenceLogIndex: logIndex,
		})

		for _, capMapping := range threat.Capabilities {
			for _, entry := range capMapping.Entries {
				if entry.ReferenceId != "" {
					result.Edges = append(result.Edges, EdgeRecord{
						FromID:    entry.ReferenceId,
						FromLabel: "Capability",
						ToID:      threat.Id,
						ToLabel:   "Threat",
						EdgeType:  "INTRODUCES",
					})
				}
			}
		}

		for _, vecMapping := range threat.Vectors {
			for _, entry := range vecMapping.Entries {
				if entry.ReferenceId != "" {
					result.Edges = append(result.Edges, EdgeRecord{
						FromID:    threat.Id,
						FromLabel: "Threat",
						ToID:      entry.ReferenceId,
						ToLabel:   "Vector",
						EdgeType:  "LEVERAGES",
					})
				}
			}
		}
	}

	return result, nil
}

func parseCapabilityCatalog(data []byte, logIndex int64) (*ParsedArtifact, error) {
	var catalog gemara.CapabilityCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshaling CapabilityCatalog: %w", err)
	}

	result := &ParsedArtifact{
		CatalogID: catalog.Metadata.Id,
		Entities:  []EntityRecord{},
		Edges:     []EdgeRecord{},
	}

	for _, capability := range catalog.Capabilities {
		props := map[string]any{
			"title":       capability.Title,
			"description": capability.Description,
			"group":       capability.Group,
		}

		result.Entities = append(result.Entities, EntityRecord{
			ID:               capability.Id,
			Label:            "Capability",
			Properties:       props,
			EvidenceLogIndex: logIndex,
		})
	}

	return result, nil
}
