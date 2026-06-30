// internal/receipt/receipt.go
package receipt

import (
	"encoding/json"
	"time"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"
	PredicateType = "https://complytime.dev/gemara-receipt/v1"
)

// Statement is an in-toto v1 Statement wrapping a Gemara receipt.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject identifies the artifact by name and content digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is the gemara-receipt/v1 predicate binding channel identity to content.
type Predicate struct {
	Content       json.RawMessage   `json:"content"`
	ContentDigest map[string]string `json:"contentDigest"`
	ContentFormat string            `json:"contentFormat"`
	Publisher     Publisher         `json:"publisher"`
	AuthorType    string            `json:"authorType"`
	ArtifactType  string            `json:"artifactType"`
	IngestedAt    time.Time         `json:"ingestedAt"`
	BundleID      string            `json:"bundleId,omitempty"`
	OCIReference  string            `json:"ociReference,omitempty"`
}

// Publisher records the channel identity from the verified JWT.
type Publisher struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Method  string `json:"method"`
}
