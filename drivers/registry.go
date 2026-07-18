package drivers

import (
	"context"
	"fmt"
	"io"
	"strings"
)

type Fetcher interface {
	Fetch(ctx context.Context, source string) (io.ReadCloser, error)
}

type Registry struct {
	drivers map[string]Fetcher
}

func NewRegistry() *Registry {
	return &Registry{drivers: make(map[string]Fetcher)}
}

func (r *Registry) Register(scheme string, f Fetcher) {
	r.drivers[scheme] = f
}

func (r *Registry) Fetch(ctx context.Context, source string) (io.ReadCloser, error) {
	scheme, _, ok := strings.Cut(source, "://")
	if !ok {
		return nil, fmt.Errorf("invalid source URI: %s", source)
	}
	f, exists := r.drivers[scheme]
	if !exists {
		return nil, fmt.Errorf("no driver registered for scheme %q", scheme)
	}
	return f.Fetch(ctx, source)
}
