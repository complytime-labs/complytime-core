package receipt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	v1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// Publisher represents the identity of the publisher.
type Publisher struct {
	Issuer string `json:"issuer"`
	Sub    string `json:"sub"`
}

// Wrap wraps unsigned content into a gemara-receipt/v1 in-toto Statement.
// Content is JCS-canonicalized, SHA-256 hashed, and base64-encoded into the predicate.
// The full receipt is JCS-canonicalized after protojson.Marshal for digest stability.
func Wrap(content []byte, publisher Publisher, subjectID, artifactType string) ([]byte, error) {
	// JCS-canonicalize input content
	canonicalContent, err := jsoncanonicalizer.Transform(content)
	if err != nil {
		return nil, fmt.Errorf("canonicalize content: %w", err)
	}

	// SHA-256 hash the canonical content
	h := sha256.New()
	h.Write(canonicalContent)
	contentDigest := "sha256:" + base64.URLEncoding.EncodeToString(h.Sum(nil))

	// Base64-encode the canonical content
	encodedContent := base64.StdEncoding.EncodeToString(canonicalContent)

	// Build predicate
	predicate := map[string]any{
		"content":       encodedContent,
		"contentDigest": contentDigest,
		"publisher":     publisher,
		"artifactType":  artifactType,
		"receivedAt":    time.Now().UTC().Format(time.RFC3339),
	}

	predicateStruct, err := predicateToStruct(predicate)
	if err != nil {
		return nil, fmt.Errorf("convert predicate to struct: %w", err)
	}

	// Build in-toto v1 Statement
	stmt := &v1.Statement{
		Type: v1.StatementTypeUri,
		Subject: []*v1.ResourceDescriptor{
			{
				Name: subjectID,
			},
		},
		PredicateType: "gemara-receipt/v1",
		Predicate:     predicateStruct,
	}

	// Marshal to JSON using protojson
	marshaler := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}
	stmtJSON, err := marshaler.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	// JCS-canonicalize the full receipt
	canonicalReceipt, err := jsoncanonicalizer.Transform(stmtJSON)
	if err != nil {
		return nil, fmt.Errorf("canonicalize receipt: %w", err)
	}

	return canonicalReceipt, nil
}

// predicateToStruct converts a Go value to a structpb.Struct.
func predicateToStruct(v any) (*structpb.Struct, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return structpb.NewStruct(m)
}
