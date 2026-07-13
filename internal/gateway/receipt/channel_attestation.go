package receipt

import (
	"fmt"

	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"google.golang.org/protobuf/encoding/protojson"
)

// BuildChannelAttestation creates a gemara-channel-attestation/v1 in-toto Statement
// that references a DSSE-signed artifact by digest and index.
// This avoids triple-nesting (in-toto wrapping DSSE wrapping in-toto).
func BuildChannelAttestation(dsseDigest string, dsseIndex int64, publisher Publisher, subjectID, payloadType string) ([]byte, error) {
	// Build predicate
	predicate := map[string]any{
		"evidenceDigest": dsseDigest,
		"evidenceIndex":  dsseIndex,
		"publisher":      publisher,
		"contentEnvelope": map[string]any{
			"payloadType": payloadType,
		},
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
		PredicateType: "gemara-channel-attestation/v1",
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

	// JCS-canonicalize the full attestation
	canonicalAttestation, err := jsoncanonicalizer.Transform(stmtJSON)
	if err != nil {
		return nil, fmt.Errorf("canonicalize attestation: %w", err)
	}

	return canonicalAttestation, nil
}
