package receipt

import (
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	v1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// BuildDSSEChannelReceipt creates a gemara-dsse-channel-receipt/v1 in-toto Statement
// that references a DSSE-signed artifact by digest and index.
// This avoids triple-nesting (in-toto wrapping DSSE wrapping in-toto).
func BuildDSSEChannelReceipt(dsseDigest string, dsseIndex int64, publisher Publisher, subjectID, payloadType string) ([]byte, error) {
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

	stmt := &v1.Statement{
		Type: v1.StatementTypeUri,
		Subject: []*v1.ResourceDescriptor{
			{
				Name: subjectID,
			},
		},
		PredicateType: "gemara-dsse-channel-receipt/v1",
		Predicate:     predicateStruct,
	}

	marshaler := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}
	stmtJSON, err := marshaler.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	canonical, err := jsoncanonicalizer.Transform(stmtJSON)
	if err != nil {
		return nil, fmt.Errorf("canonicalize receipt: %w", err)
	}

	return canonical, nil
}
