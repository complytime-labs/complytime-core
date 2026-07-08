// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"fmt"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// Wrap builds an in-toto v1 Statement with a gemara-receipt/v1 predicate.
// canonical must be deterministic canonical JSON. digest is its SHA-256 hex.
func Wrap(canonical []byte, digest string, pub Publisher, artifactType, authorType string, ingestedAt time.Time) ([]byte, error) {
	targetID := extractTargetID(canonical)
	subjectName := artifactType
	if targetID != "" {
		subjectName = artifactType + "/" + targetID
	}

	var contentGeneric any
	if err := json.Unmarshal(canonical, &contentGeneric); err != nil {
		return nil, fmt.Errorf("parse canonical content: %w", err)
	}

	predMap := map[string]any{
		"content":       contentGeneric,
		"contentDigest": map[string]any{"sha256": digest},
		"contentFormat": "application/json",
		"publisher": map[string]any{
			"issuer":  pub.Issuer,
			"subject": pub.Subject,
			"method":  pub.Method,
		},
		"authorType":   authorType,
		"artifactType": artifactType,
		"ingestedAt":   ingestedAt.Format(time.RFC3339Nano),
	}

	predStruct, err := structpb.NewStruct(predMap)
	if err != nil {
		return nil, fmt.Errorf("build predicate struct: %w", err)
	}

	stmt := &intoto.Statement{
		Type: StatementType,
		Subject: []*intoto.ResourceDescriptor{{
			Name:   subjectName,
			Digest: map[string]string{"sha256": digest},
		}},
		PredicateType: PredicateType,
		Predicate:     predStruct,
	}

	data, err := protojson.Marshal(stmt)
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

// Unwrap extracts the predicate from an in-toto v1 Statement and verifies
// the content digest. This is an intra-service consistency check, not a
// security boundary — tamper-evidence comes from Tessera's Merkle proofs.
func Unwrap(data []byte) (*Predicate, error) {
	var stmt intoto.Statement
	if err := protojson.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal statement: %w", err)
	}
	if stmt.Type != StatementType {
		return nil, fmt.Errorf("unexpected statement type: %s", stmt.Type)
	}
	if stmt.PredicateType != PredicateType {
		return nil, fmt.Errorf("unexpected predicate type: %s", stmt.PredicateType)
	}

	if stmt.Predicate == nil {
		return nil, fmt.Errorf("missing predicate")
	}

	predJSON, err := protojson.Marshal(stmt.Predicate)
	if err != nil {
		return nil, fmt.Errorf("marshal predicate: %w", err)
	}

	var pred Predicate
	if err := json.Unmarshal(predJSON, &pred); err != nil {
		return nil, fmt.Errorf("unmarshal predicate: %w", err)
	}

	expectedDigest, ok := pred.ContentDigest["sha256"]
	if !ok {
		return nil, fmt.Errorf("missing sha256 in contentDigest")
	}

	_, actualDigest, err := Canonicalize(pred.Content)
	if err != nil {
		return nil, fmt.Errorf("re-canonicalize content: %w", err)
	}
	if actualDigest != expectedDigest {
		return nil, fmt.Errorf("content digest mismatch: got %s, want %s", actualDigest, expectedDigest)
	}

	return &pred, nil
}

// IsReceipt returns true if data looks like an in-toto v1 Statement.
func IsReceipt(data []byte) bool {
	var stmt intoto.Statement
	if err := protojson.Unmarshal(data, &stmt); err != nil {
		return false
	}
	return stmt.Type == StatementType
}
