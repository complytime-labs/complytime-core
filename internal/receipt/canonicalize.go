// internal/receipt/canonicalize.go
package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Canonicalize produces a deterministic JSON form by unmarshaling and
// re-marshaling with sorted keys. Returns the canonical bytes and SHA-256
// hex digest. Not a full RFC 8785 implementation (no ECMAScript number
// normalization or UTF-16 sort order), but sufficient for same-artifact
// digest stability within complytime-core.
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
