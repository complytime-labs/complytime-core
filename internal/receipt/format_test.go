package receipt_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/receipt"
	"github.com/stretchr/testify/assert"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		contentType string
		want        receipt.Format
	}{
		{"application/yaml", receipt.FormatYAML},
		{"application/x-yaml", receipt.FormatYAML},
		{"application/json", receipt.FormatJSON},
		{"application/json; charset=utf-8", receipt.FormatJSON},
		{"application/vnd.dsse+json", receipt.FormatDSSE},
		{"text/plain", receipt.FormatYAML},
		{"", receipt.FormatYAML},
	}
	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			assert.Equal(t, tt.want, receipt.DetectFormat(tt.contentType))
		})
	}
}

func TestValidateDSSE_Valid(t *testing.T) {
	data := []byte(`{
		"payload": "eyJ0eXBlIjoiRXZhbHVhdGlvbkxvZyJ9",
		"payloadType": "application/vnd.gemara+json",
		"signatures": [{"keyid": "key1", "sig": "c2lnbmF0dXJl"}]
	}`)
	assert.NoError(t, receipt.ValidateDSSE(data))
}

func TestValidateDSSE_MissingPayload(t *testing.T) {
	data := []byte(`{"payloadType": "application/json", "signatures": [{"sig": "abc"}]}`)
	assert.ErrorContains(t, receipt.ValidateDSSE(data), "missing payload")
}

func TestValidateDSSE_NoSignatures(t *testing.T) {
	data := []byte(`{"payload": "abc", "payloadType": "application/json", "signatures": []}`)
	assert.ErrorContains(t, receipt.ValidateDSSE(data), "no signatures")
}

func TestIsDSSE(t *testing.T) {
	assert.True(t, receipt.IsDSSE([]byte(`{"payload":"abc","payloadType":"t"}`)))
	assert.False(t, receipt.IsDSSE([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`)))
	assert.False(t, receipt.IsDSSE([]byte(`metadata:
  type: EvaluationLog`)))
}
