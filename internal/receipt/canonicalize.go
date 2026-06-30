// internal/receipt/canonicalize.go
package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Canonicalize applies RFC 8785 (JSON Canonicalization Scheme) to JSON input.
// Returns the canonical form and its SHA-256 hex digest. Uses json.Number
// preservation to avoid float64 round-trip artifacts.
func Canonicalize(jsonData []byte) ([]byte, string, error) {
	var generic any
	dec := json.NewDecoder(bytes.NewReader(jsonData))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, "", fmt.Errorf("decode: %w", err)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return nil, "", fmt.Errorf("marshal: %w", err)
	}
	h := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(h[:]), nil
}
