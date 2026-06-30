// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"fmt"

	"github.com/goccy/go-yaml"

	"github.com/complytime-labs/complytime-core/internal/evidence"
)

// normalizeArtifact unmarshals body (YAML or JSON) through a generic
// structure and marshals to JSON. go-yaml handles both YAML and JSON.
func normalizeArtifact(body []byte) ([]byte, error) {
	typeStr := evidence.DetectArtifactTypeString(body)
	if typeStr == "" {
		return nil, fmt.Errorf("missing metadata.type")
	}
	if typeStr == "TargetRegistration" {
		return nil, fmt.Errorf("TargetRegistration must use the admin API")
	}

	var generic map[string]any
	if err := yaml.Unmarshal(body, &generic); err != nil {
		return nil, fmt.Errorf("unmarshal artifact: %w", err)
	}
	jsonBytes, err := json.Marshal(generic)
	if err != nil {
		return nil, fmt.Errorf("marshal to JSON: %w", err)
	}
	return jsonBytes, nil
}

// detectAuthorType extracts metadata.author.type from raw artifact bytes.
func detectAuthorType(body []byte) string {
	var h struct {
		Metadata struct {
			Author struct {
				Type string `yaml:"type"`
			} `yaml:"author"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(body, &h); err != nil {
		return ""
	}
	return h.Metadata.Author.Type
}
