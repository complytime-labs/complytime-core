// internal/receipt/wrap.go
package receipt

import (
	"encoding/json"
	"fmt"
	"time"
)

// Wrap builds an in-toto v1 Statement with a gemara-receipt/v1 predicate.
// canonical must be RFC 8785 canonical JSON. digest is its SHA-256 hex.
func Wrap(canonical []byte, digest string, pub Publisher, artifactType, authorType string, ingestedAt time.Time) ([]byte, error) {
	targetID := extractTargetID(canonical)
	subjectName := artifactType
	if targetID != "" {
		subjectName = artifactType + "/" + targetID
	}

	stmt := Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name:   subjectName,
			Digest: map[string]string{"sha256": digest},
		}},
		PredicateType: PredicateType,
		Predicate: Predicate{
			Content:       json.RawMessage(canonical),
			ContentDigest: map[string]string{"sha256": digest},
			ContentFormat: "application/json",
			Publisher:     pub,
			AuthorType:    authorType,
			ArtifactType:  artifactType,
			IngestedAt:    ingestedAt,
		},
	}
	data, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}
	return data, nil
}

// extractTargetID reads target.id from canonical JSON without full parsing.
func extractTargetID(canonical []byte) string {
	var t struct {
		Target struct {
			ID string `json:"id"`
		} `json:"target"`
	}
	if err := json.Unmarshal(canonical, &t); err != nil {
		return ""
	}
	return t.Target.ID
}

// Unwrap extracts the predicate from an in-toto Statement and verifies the
// content digest. Returns an error if the digest does not match.
func Unwrap(data []byte) (*Predicate, error) {
	var stmt Statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal statement: %w", err)
	}
	if stmt.Type != StatementType {
		return nil, fmt.Errorf("unexpected statement type: %s", stmt.Type)
	}
	if stmt.PredicateType != PredicateType {
		return nil, fmt.Errorf("unexpected predicate type: %s", stmt.PredicateType)
	}

	expectedDigest, ok := stmt.Predicate.ContentDigest["sha256"]
	if !ok {
		return nil, fmt.Errorf("missing sha256 in contentDigest")
	}

	_, actualDigest, err := Canonicalize(stmt.Predicate.Content)
	if err != nil {
		return nil, fmt.Errorf("re-canonicalize content: %w", err)
	}
	if actualDigest != expectedDigest {
		return nil, fmt.Errorf("content digest mismatch: got %s, want %s", actualDigest, expectedDigest)
	}

	return &stmt.Predicate, nil
}

// IsReceipt returns true if data looks like an in-toto v1 Statement.
func IsReceipt(data []byte) bool {
	var s struct {
		Type string `json:"_type"`
	}
	return json.Unmarshal(data, &s) == nil && s.Type == StatementType
}
