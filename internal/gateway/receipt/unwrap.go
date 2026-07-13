package receipt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// UnwrapResult contains the unwrapped content and metadata.
type UnwrapResult struct {
	Content               []byte
	Publisher             *Publisher
	Format                string
	IsDSSE                bool
	IsChannelAttestation bool
}

// UnwrapContent detects the entry type and unwraps it appropriately.
// - DSSE envelope: returns as-is with IsDSSE=true
// - gemara-receipt/v1: extracts content + publisher
// - gemara-channel-attestation/v1: extracts publisher, IsChannelAttestation=true
func UnwrapContent(entry []byte) (UnwrapResult, error) {
	var raw map[string]any
	if err := json.Unmarshal(entry, &raw); err != nil {
		return UnwrapResult{}, fmt.Errorf("unmarshal entry: %w", err)
	}

	// Check for DSSE envelope
	if hasDSSEFields(raw) {
		return UnwrapResult{
			Content: entry,
			Format:  "dsse",
			IsDSSE:  true,
		}, nil
	}

	// Check for in-toto Statement (receipt or channel attestation)
	predicateType, ok := raw["predicate_type"].(string)
	if !ok {
		return UnwrapResult{}, fmt.Errorf("unknown entry format: missing predicate_type")
	}

	predicate, ok := raw["predicate"].(map[string]any)
	if !ok {
		return UnwrapResult{}, fmt.Errorf("invalid entry: missing predicate")
	}

	// Extract publisher from predicate
	publisher, err := extractPublisher(predicate)
	if err != nil {
		return UnwrapResult{}, fmt.Errorf("extract publisher: %w", err)
	}

	switch predicateType {
	case "gemara-receipt/v1":
		// Extract and decode content
		encodedContent, ok := predicate["content"].(string)
		if !ok {
			return UnwrapResult{}, fmt.Errorf("receipt missing content field")
		}

		content, err := base64.StdEncoding.DecodeString(encodedContent)
		if err != nil {
			return UnwrapResult{}, fmt.Errorf("decode content: %w", err)
		}

		return UnwrapResult{
			Content:   content,
			Publisher: publisher,
			Format:    predicateType,
		}, nil

	case "gemara-channel-attestation/v1":
		return UnwrapResult{
			Publisher:            publisher,
			Format:               predicateType,
			IsChannelAttestation: true,
		}, nil

	default:
		return UnwrapResult{}, fmt.Errorf("unknown predicate type: %s", predicateType)
	}
}

// hasDSSEFields checks if the JSON has the structure of a DSSE envelope.
func hasDSSEFields(raw map[string]any) bool {
	_, hasPayloadType := raw["payloadType"]
	_, hasSignatures := raw["signatures"]
	return hasPayloadType && hasSignatures
}

// extractPublisher extracts the Publisher from a predicate.
func extractPublisher(predicate map[string]any) (*Publisher, error) {
	publisherData, ok := predicate["publisher"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("predicate missing publisher field")
	}

	issuer, ok := publisherData["issuer"].(string)
	if !ok {
		return nil, fmt.Errorf("publisher missing issuer field")
	}

	sub, ok := publisherData["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("publisher missing sub field")
	}

	return &Publisher{
		Issuer: issuer,
		Sub:    sub,
	}, nil
}
