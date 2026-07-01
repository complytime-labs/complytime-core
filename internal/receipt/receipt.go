// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"time"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"
	PredicateType = "https://complytime.dev/gemara-receipt/v1"
)

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
