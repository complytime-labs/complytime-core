package drivers_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/drivers"
)

type mockFetcher struct {
	data []byte
}

func (m *mockFetcher) Fetch(_ context.Context, source string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.data)), nil
}

func TestRegistry_Fetch(t *testing.T) {
	reg := drivers.NewRegistry()
	reg.Register("mock", &mockFetcher{data: []byte("hello")})

	rc, err := reg.Fetch(context.Background(), "mock://some/path")
	require.NoError(t, err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))
}

func TestRegistry_UnknownScheme(t *testing.T) {
	reg := drivers.NewRegistry()
	_, err := reg.Fetch(context.Background(), "unknown://path")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestRegistry_InvalidURI(t *testing.T) {
	reg := drivers.NewRegistry()
	_, err := reg.Fetch(context.Background(), "not-a-uri")
	require.Error(t, err)
}
