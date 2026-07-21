package receipt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// UnwrapResult contains the unwrapped content and metadata.
type UnwrapResult struct {
	Content   []byte
	Publisher *Publisher
	Format    string
}

// UnwrapContent unwraps a gemara-receipt/v1 in-toto Statement.
// - gemara-receipt/v1: extracts content + publisher
// The content field may be base64-encoded DSSE or JSON artifact bytes.
func UnwrapContent(entry []byte) (UnwrapResult, error) {
	var raw map[string]any
	if err := json.Unmarshal(entry, &raw); err != nil {
		return UnwrapResult{}, fmt.Errorf("unmarshal entry: %w", err)
	}

	// Check for in-toto Statement
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

	if predicateType != "gemara-receipt/v1" {
		return UnwrapResult{}, fmt.Errorf("unknown predicate type: %s", predicateType)
	}

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
