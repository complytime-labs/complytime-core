// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	v1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const PredicateTypeReceipt = "https://complytime.dev/gemara-receipt/v1"

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

func WrapAsReceipt(content []byte, publisher PublisherMeta, artifactType, targetID string) ([]byte, error) {
	hash := sha256.Sum256(content)
	subjectName := targetID
	if subjectName == "" {
		subjectName = "unknown"
	}

	pred := ReceiptPredicate{
		Content:      string(content),
		Publisher:    publisher,
		ArtifactType: artifactType,
		IngestedAt:   time.Now().UTC(),
	}

	predJSON, err := json.Marshal(pred)
	if err != nil {
		return nil, fmt.Errorf("marshal predicate: %w", err)
	}

	predStruct := &structpb.Struct{}
	if err := protojson.Unmarshal(predJSON, predStruct); err != nil {
		return nil, fmt.Errorf("convert predicate to struct: %w", err)
	}

	stmt := &v1.Statement{
		Type: v1.StatementTypeUri,
		Subject: []*v1.ResourceDescriptor{{
			Name:   subjectName,
			Digest: map[string]string{"sha256": hex.EncodeToString(hash[:])},
		}},
		PredicateType: PredicateTypeReceipt,
		Predicate:     predStruct,
	}

	data, err := protojson.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}
	return data, nil
}

// UnwrappedStatement holds the parsed in-toto statement metadata after unwrapping.
type UnwrappedStatement struct {
	Type          string
	SubjectName   string
	SubjectDigest map[string]string
	PredicateType string
	Publisher     PublisherMeta
	ArtifactType  string
}

func Unwrap(data []byte) ([]byte, *UnwrappedStatement, error) {
	trimmed := bytes.TrimLeft(data, " \t\n\r")
	if len(trimmed) == 0 {
		return nil, nil, fmt.Errorf("empty entry")
	}

	if trimmed[0] != '{' {
		return data, nil, nil
	}

	stmt := &v1.Statement{}
	if err := protojson.Unmarshal(trimmed, stmt); err != nil {
		return data, nil, nil
	}
	if stmt.GetType() != v1.StatementTypeUri {
		return data, nil, nil
	}

	predFields := stmt.GetPredicate().GetFields()
	if predFields == nil {
		return data, nil, fmt.Errorf("statement has no predicate")
	}

	contentVal := predFields["content"]
	if contentVal == nil {
		return data, nil, fmt.Errorf("predicate has no content field")
	}
	content := contentVal.GetStringValue()

	unwrapped := &UnwrappedStatement{
		Type:          stmt.GetType(),
		PredicateType: stmt.GetPredicateType(),
	}

	if len(stmt.GetSubject()) > 0 {
		unwrapped.SubjectName = stmt.GetSubject()[0].GetName()
		unwrapped.SubjectDigest = stmt.GetSubject()[0].GetDigest()
	}

	pubVal := predFields["publisher"]
	if pubVal != nil {
		pubFields := pubVal.GetStructValue().GetFields()
		if pubFields != nil {
			unwrapped.Publisher = PublisherMeta{
				Issuer:  pubFields["issuer"].GetStringValue(),
				Subject: pubFields["subject"].GetStringValue(),
				Method:  pubFields["method"].GetStringValue(),
			}
		}
	}

	artVal := predFields["artifactType"]
	if artVal != nil {
		unwrapped.ArtifactType = artVal.GetStringValue()
	}

	return []byte(content), unwrapped, nil
}
