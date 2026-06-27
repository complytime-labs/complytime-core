// internal/attestation/statement.go
package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	StatementTypeV1      = "https://in-toto.io/Statement/v1"
	PredicateTypeReceipt = "https://complytime.dev/gemara-receipt/v1"
)

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type PublisherMeta struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Method  string `json:"method"`
}

type ReceiptPredicate struct {
	Content      string        `json:"content"`
	Publisher    PublisherMeta `json:"publisher"`
	ArtifactType string        `json:"artifactType"`
	IngestedAt   time.Time     `json:"ingestedAt"`
}

type Statement struct {
	Type          string           `json:"_type"`
	Subject       []Subject        `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     ReceiptPredicate `json:"predicate"`
}

func WrapAsReceipt(content []byte, publisher PublisherMeta, artifactType, targetID string) ([]byte, error) {
	hash := sha256.Sum256(content)
	subjectName := targetID
	if subjectName == "" {
		subjectName = "unknown"
	}

	stmt := Statement{
		Type: StatementTypeV1,
		Subject: []Subject{{
			Name:   subjectName,
			Digest: map[string]string{"sha256": hex.EncodeToString(hash[:])},
		}},
		PredicateType: PredicateTypeReceipt,
		Predicate: ReceiptPredicate{
			Content:      string(content),
			Publisher:    publisher,
			ArtifactType: artifactType,
			IngestedAt:   time.Now().UTC(),
		},
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}
	return data, nil
}

func Unwrap(data []byte) ([]byte, *Statement, error) {
	data = trimLeadingWhitespace(data)
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty entry")
	}

	if data[0] != '{' {
		return data, nil, nil
	}

	var stmt Statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return data, nil, nil
	}
	if stmt.Type != StatementTypeV1 {
		return data, nil, nil
	}

	return []byte(stmt.Predicate.Content), &stmt, nil
}

func trimLeadingWhitespace(data []byte) []byte {
	for len(data) > 0 && (data[0] == ' ' || data[0] == '\t' || data[0] == '\n' || data[0] == '\r') {
		data = data[1:]
	}
	return data
}
