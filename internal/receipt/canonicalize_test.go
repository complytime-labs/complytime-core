// internal/receipt/canonicalize_test.go
package receipt_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/receipt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalize_SortsKeys(t *testing.T) {
	input := []byte(`{"zebra":"z","alpha":"a","middle":{"beta":"b","alpha":"a"}}`)
	canonical, digest, err := receipt.Canonicalize(input)
	require.NoError(t, err)
	assert.JSONEq(t, `{"alpha":"a","middle":{"alpha":"a","beta":"b"},"zebra":"z"}`, string(canonical))
	assert.Equal(t, string(canonical), `{"alpha":"a","middle":{"alpha":"a","beta":"b"},"zebra":"z"}`)
	assert.Len(t, digest, 64)
}

func TestCanonicalize_PreservesIntegers(t *testing.T) {
	input := []byte(`{"count":42,"name":"test"}`)
	canonical, _, err := receipt.Canonicalize(input)
	require.NoError(t, err)
	assert.Contains(t, string(canonical), `"count":42`)
}

func TestCanonicalize_Deterministic(t *testing.T) {
	input1 := []byte(`{"b":1,"a":2}`)
	input2 := []byte(`{"a":2,"b":1}`)
	c1, d1, err := receipt.Canonicalize(input1)
	require.NoError(t, err)
	c2, d2, err := receipt.Canonicalize(input2)
	require.NoError(t, err)
	assert.Equal(t, c1, c2)
	assert.Equal(t, d1, d2)
}

func TestCanonicalize_InvalidJSON(t *testing.T) {
	_, _, err := receipt.Canonicalize([]byte(`not json`))
	assert.Error(t, err)
}
