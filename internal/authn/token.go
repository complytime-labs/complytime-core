package authn

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type StaticTokenSource struct {
	token string
}

func NewStaticTokenSource(token string) *StaticTokenSource {
	return &StaticTokenSource{token: token}
}

func (s *StaticTokenSource) Token(_ context.Context) (string, error) {
	return s.token, nil
}

type FileTokenSource struct {
	path string
}

func NewFileTokenSource(path string) *FileTokenSource {
	return &FileTokenSource{path: path}
}

func (f *FileTokenSource) Token(_ context.Context) (string, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return "", fmt.Errorf("reading token file %s: %w", f.path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

type tokenTransport struct {
	source TokenSource
	base   http.RoundTripper
}

func NewTokenTransport(source TokenSource, base http.RoundTripper) http.RoundTripper {
	return &tokenTransport{source: source, base: base}
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.source.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("obtaining token: %w", err)
	}
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+tok)
	return t.base.RoundTrip(clone)
}
