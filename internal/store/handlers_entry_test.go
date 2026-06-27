// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/store"
)

type fakeReader struct {
	entries map[uint64][]byte
}

func (r *fakeReader) Read(_ context.Context, index uint64) ([]byte, error) {
	data, ok := r.entries[index]
	if !ok {
		return nil, fmt.Errorf("index %d not yet integrated (log size: 0)", index)
	}
	return data, nil
}

func TestEntryHandler_ReturnsEntry(t *testing.T) {
	reader := &fakeReader{entries: map[uint64][]byte{
		0: []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[]}`),
	}}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/0", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/entry/:index")
	c.SetParamNames("index")
	c.SetParamValues("0")

	handler := store.EntryHandler(reader)
	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Contains(t, rec.Body.String(), "in-toto.io/Statement")
}

func TestEntryHandler_NotFound(t *testing.T) {
	reader := &fakeReader{entries: map[uint64][]byte{}}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/99", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/entry/:index")
	c.SetParamNames("index")
	c.SetParamValues("99")

	handler := store.EntryHandler(reader)
	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestEntryHandler_InvalidIndex(t *testing.T) {
	reader := &fakeReader{entries: map[uint64][]byte{}}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/invalid", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/entry/:index")
	c.SetParamNames("index")
	c.SetParamValues("invalid")

	handler := store.EntryHandler(reader)
	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEntryHandler_YAMLContentType(t *testing.T) {
	reader := &fakeReader{entries: map[uint64][]byte{
		0: []byte("---\nkey: value\n"),
	}}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/0", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/entry/:index")
	c.SetParamNames("index")
	c.SetParamValues("0")

	handler := store.EntryHandler(reader)
	err := handler(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/x-yaml", rec.Header().Get("Content-Type"))
}
