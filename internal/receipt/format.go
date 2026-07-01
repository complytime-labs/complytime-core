// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// Format identifies the submission content format.
type Format int

const (
	FormatYAML Format = iota
	FormatJSON
	FormatDSSE
)

// DetectFormat determines the submission format from the Content-Type header.
// Defaults to YAML for backward compatibility.
func DetectFormat(contentType string) Format {
	ct := strings.ToLower(contentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/json":
		return FormatJSON
	case "application/vnd.dsse+json":
		return FormatDSSE
	case "application/yaml", "application/x-yaml":
		return FormatYAML
	default:
		return FormatYAML
	}
}

// ValidateDSSE checks that data is a structurally valid DSSE envelope.
// Does NOT verify signatures — that is a consumer-edge concern.
func ValidateDSSE(data []byte) error {
	var env dsse.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("invalid DSSE JSON: %w", err)
	}
	if env.Payload == "" {
		return fmt.Errorf("DSSE envelope missing payload")
	}
	if env.PayloadType == "" {
		return fmt.Errorf("DSSE envelope missing payloadType")
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("DSSE envelope has no signatures")
	}
	return nil
}

// DecodeDSSEPayload extracts and base64-decodes the payload from a DSSE envelope.
func DecodeDSSEPayload(data []byte) ([]byte, error) {
	var env dsse.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse DSSE: %w", err)
	}
	payload, err := env.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	return payload, nil
}

// IsDSSE returns true if data looks like a DSSE envelope.
func IsDSSE(data []byte) bool {
	var env dsse.Envelope
	return json.Unmarshal(data, &env) == nil && env.Payload != "" && env.PayloadType != ""
}
