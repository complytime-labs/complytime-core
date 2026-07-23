package graph

import (
	"encoding/json"
	"fmt"
)

// TODO: Replace this with go-gemara SDK when available.
// This is a minimal parser that extracts entities and edges from Gemara JSON artifacts.
// It implements just enough to materialize ControlCatalog and ThreatCatalog relationships.

// GemaraMetadata represents common metadata fields in Gemara artifacts.
type GemaraMetadata struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

// ControlCatalog represents a Gemara control catalog.
type ControlCatalog struct {
	Metadata struct {
		GemaraMetadata
	} `json:"metadata"`
	Title    string    `json:"title"`
	Controls []Control `json:"controls"`
}

// Control represents a control entry.
type Control struct {
	ID           string                  `json:"id"`
	Title        string                  `json:"title"`
	Objective    string                  `json:"objective"`
	Group        string                  `json:"group"`
	Threats      []MultiEntryMapping     `json:"threats,omitempty"`
	Guidelines   []MultiEntryMapping     `json:"guidelines,omitempty"`
	Requirements []AssessmentRequirement `json:"assessment-requirements"`
}

// AssessmentRequirement represents an assessment requirement.
type AssessmentRequirement struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// ThreatCatalog represents a Gemara threat catalog.
type ThreatCatalog struct {
	Metadata struct {
		GemaraMetadata
	} `json:"metadata"`
	Title   string   `json:"title"`
	Threats []Threat `json:"threats"`
}

// Threat represents a threat entry.
type Threat struct {
	ID           string              `json:"id"`
	Title        string              `json:"title"`
	Description  string              `json:"description"`
	Group        string              `json:"group"`
	Capabilities []MultiEntryMapping `json:"capabilities,omitempty"`
	Vectors      []MultiEntryMapping `json:"vectors,omitempty"`
}

// CapabilityCatalog represents a Gemara capability catalog.
type CapabilityCatalog struct {
	Metadata struct {
		GemaraMetadata
	} `json:"metadata"`
	Title        string       `json:"title"`
	Capabilities []Capability `json:"capabilities"`
}

// Capability represents a capability entry.
type Capability struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Group       string `json:"group"`
}

// MultiEntryMapping represents a mapping with potential nested entries.
type MultiEntryMapping struct {
	ReferenceID string            `json:"reference-id"`
	Entries     []ArtifactMapping `json:"entries,omitempty"`
}

// ArtifactMapping represents a cross-catalog reference.
type ArtifactMapping struct {
	ReferenceID string `json:"reference-id"`
}

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
		// For unsupported types, return empty result (no error, just skip)
		return &ParsedArtifact{Entities: []EntityRecord{}, Edges: []EdgeRecord{}}, nil
	}
}

func parseControlCatalog(data []byte, logIndex int64) (*ParsedArtifact, error) {
	var catalog ControlCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshaling ControlCatalog: %w", err)
	}

	result := &ParsedArtifact{
		CatalogID: catalog.Metadata.ID,
		Entities:  []EntityRecord{},
		Edges:     []EdgeRecord{},
	}

	for _, control := range catalog.Controls {
		// Create Control entity
		props := map[string]any{
			"title":     control.Title,
			"objective": control.Objective,
			"group":     control.Group,
			"catalogID": catalog.Metadata.ID,
		}

		// Extract assessment requirement texts
		var reqTexts []string
		for _, req := range control.Requirements {
			reqTexts = append(reqTexts, req.Text)
		}
		if len(reqTexts) > 0 {
			props["assessmentRequirements"] = reqTexts
		}

		result.Entities = append(result.Entities, EntityRecord{
			ID:               control.ID,
			Label:            "Control",
			Properties:       props,
			EvidenceLogIndex: logIndex,
		})

		// Create APPLIES edges to threats
		for _, threatMapping := range control.Threats {
			// If there are nested entries, only use those (reference-id is a catalog pointer)
			if len(threatMapping.Entries) > 0 {
				for _, entry := range threatMapping.Entries {
					if entry.ReferenceID != "" {
						result.Edges = append(result.Edges, EdgeRecord{
							FromID:    control.ID,
							FromLabel: "Control",
							ToID:      entry.ReferenceID,
							ToLabel:   "Threat",
							EdgeType:  "APPLIES",
						})
					}
				}
			} else if threatMapping.ReferenceID != "" {
				// Direct reference (no nested entries)
				result.Edges = append(result.Edges, EdgeRecord{
					FromID:    control.ID,
					FromLabel: "Control",
					ToID:      threatMapping.ReferenceID,
					ToLabel:   "Threat",
					EdgeType:  "APPLIES",
				})
			}
		}
	}

	return result, nil
}

func parseThreatCatalog(data []byte, logIndex int64) (*ParsedArtifact, error) {
	var catalog ThreatCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshaling ThreatCatalog: %w", err)
	}

	result := &ParsedArtifact{
		CatalogID: catalog.Metadata.ID,
		Entities:  []EntityRecord{},
		Edges:     []EdgeRecord{},
	}

	for _, threat := range catalog.Threats {
		// Create Threat entity
		props := map[string]any{
			"title":       threat.Title,
			"description": threat.Description,
			"group":       threat.Group,
		}

		result.Entities = append(result.Entities, EntityRecord{
			ID:               threat.ID,
			Label:            "Threat",
			Properties:       props,
			EvidenceLogIndex: logIndex,
		})

		// Create LEVERAGES edges to capabilities
		for _, capMapping := range threat.Capabilities {
			if len(capMapping.Entries) > 0 {
				for _, entry := range capMapping.Entries {
					if entry.ReferenceID != "" {
						result.Edges = append(result.Edges, EdgeRecord{
							FromID:    threat.ID,
							FromLabel: "Threat",
							ToID:      entry.ReferenceID,
							ToLabel:   "Capability",
							EdgeType:  "LEVERAGES",
						})
					}
				}
			} else if capMapping.ReferenceID != "" {
				result.Edges = append(result.Edges, EdgeRecord{
					FromID:    threat.ID,
					FromLabel: "Threat",
					ToID:      capMapping.ReferenceID,
					ToLabel:   "Capability",
					EdgeType:  "LEVERAGES",
				})
			}
		}

		// Create LEVERAGES edges to vectors
		for _, vecMapping := range threat.Vectors {
			if len(vecMapping.Entries) > 0 {
				for _, entry := range vecMapping.Entries {
					if entry.ReferenceID != "" {
						result.Edges = append(result.Edges, EdgeRecord{
							FromID:    threat.ID,
							FromLabel: "Threat",
							ToID:      entry.ReferenceID,
							ToLabel:   "Vector",
							EdgeType:  "LEVERAGES",
						})
					}
				}
			} else if vecMapping.ReferenceID != "" {
				result.Edges = append(result.Edges, EdgeRecord{
					FromID:    threat.ID,
					FromLabel: "Threat",
					ToID:      vecMapping.ReferenceID,
					ToLabel:   "Vector",
					EdgeType:  "LEVERAGES",
				})
			}
		}
	}

	return result, nil
}

func parseCapabilityCatalog(data []byte, logIndex int64) (*ParsedArtifact, error) {
	var catalog CapabilityCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshaling CapabilityCatalog: %w", err)
	}

	result := &ParsedArtifact{
		CatalogID: catalog.Metadata.ID,
		Entities:  []EntityRecord{},
		Edges:     []EdgeRecord{},
	}

	for _, capability := range catalog.Capabilities {
		// Create Capability entity
		props := map[string]any{
			"title":       capability.Title,
			"description": capability.Description,
			"group":       capability.Group,
		}

		result.Entities = append(result.Entities, EntityRecord{
			ID:               capability.ID,
			Label:            "Capability",
			Properties:       props,
			EvidenceLogIndex: logIndex,
		})
	}

	return result, nil
}
