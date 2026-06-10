// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakePinger struct {
	mu  sync.Mutex
	err error
}

func (f *fakePinger) Ping(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakePinger) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestDegradedMiddleware_Healthy(t *testing.T) {
	mw := DegradedMiddleware(map[string]Pinger{
		"postgres": &fakePinger{},
		"nats":     &fakePinger{},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec, req)

	if got := rec.Header().Get(degradedHeader); got != "" {
		t.Fatalf("expected no degraded header, got %q", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestDegradedMiddleware_OneDegraded(t *testing.T) {
	mw := DegradedMiddleware(map[string]Pinger{
		"postgres": &fakePinger{err: errors.New("connection refused")},
		"nats":     &fakePinger{},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec, req)

	got := rec.Header().Get(degradedHeader)
	if got != "postgres" {
		t.Fatalf("expected degraded header %q, got %q", "postgres", got)
	}
}

func TestDegradedMiddleware_MultipleDegraded(t *testing.T) {
	mw := DegradedMiddleware(map[string]Pinger{
		"postgres": &fakePinger{err: errors.New("down")},
		"nats":     &fakePinger{err: errors.New("down")},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec, req)

	got := rec.Header().Get(degradedHeader)
	if got == "" {
		t.Fatal("expected degraded header to be set")
	}
	if got != "postgres,nats" && got != "nats,postgres" {
		t.Fatalf("expected both subsystems in header, got %q", got)
	}
}

func TestDegradedMiddleware_NilPingerSkipped(t *testing.T) {
	mw := DegradedMiddleware(map[string]Pinger{
		"postgres": nil,
		"nats":     &fakePinger{},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec, req)

	if got := rec.Header().Get(degradedHeader); got != "" {
		t.Fatalf("expected no degraded header with nil pinger, got %q", got)
	}
}

func TestDegradedMiddleware_CachesResults(t *testing.T) {
	pinger := &fakePinger{err: errors.New("down")}
	mw := DegradedMiddleware(map[string]Pinger{
		"postgres": pinger,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec, req)

	if got := rec.Header().Get(degradedHeader); got != "postgres" {
		t.Fatalf("first request: expected degraded, got %q", got)
	}

	// Recover the pinger — but cache should still report degraded within TTL.
	pinger.setErr(nil)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec2, req2)

	if got := rec2.Header().Get(degradedHeader); got != "postgres" {
		t.Fatalf("cached request: expected stale degraded, got %q", got)
	}
}

func TestDegradedMiddleware_CacheExpires(t *testing.T) {
	pinger := &fakePinger{err: errors.New("down")}
	mw := DegradedMiddlewareWithTTL(map[string]Pinger{
		"postgres": pinger,
	}, 50*time.Millisecond)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec, req)

	if got := rec.Header().Get(degradedHeader); got != "postgres" {
		t.Fatalf("first request: expected degraded, got %q", got)
	}

	pinger.setErr(nil)
	time.Sleep(100 * time.Millisecond)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(okHandler()).ServeHTTP(rec2, req2)

	if got := rec2.Header().Get(degradedHeader); got != "" {
		t.Fatalf("after cache expiry: expected no header, got %q", got)
	}
}

func TestDegradedMiddleware_Concurrent(t *testing.T) {
	pinger := &fakePinger{err: errors.New("down")}
	mw := DegradedMiddleware(map[string]Pinger{
		"postgres": pinger,
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			mw(okHandler()).ServeHTTP(rec, req)
		}()
	}
	wg.Wait()
}
