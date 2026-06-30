package receipt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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

// DSSEEnvelope is the Dead Simple Signing Envelope structure.
type DSSEEnvelope struct {
	Payload     string          `json:"payload"`
	PayloadType string          `json:"payloadType"`
	Signatures  []DSSESignature `json:"signatures"`
}

// DSSESignature is a single signature entry in a DSSE envelope.
type DSSESignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// ValidateDSSE checks that data is a structurally valid DSSE envelope.
// Does NOT verify signatures — that is a consumer-edge concern.
func ValidateDSSE(data []byte) error {
	var env DSSEEnvelope
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
	var env DSSEEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse DSSE: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		payload, err = base64.RawURLEncoding.DecodeString(env.Payload)
		if err != nil {
			return nil, fmt.Errorf("decode DSSE payload: %w", err)
		}
	}
	return payload, nil
}

// IsDSSE returns true if data looks like a DSSE envelope.
func IsDSSE(data []byte) bool {
	var d struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}
	return json.Unmarshal(data, &d) == nil && d.Payload != "" && d.PayloadType != ""
}
