// SPDX-License-Identifier: Apache-2.0

package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimit_AllowsBelowLimit(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	// 10 requests/sec, burst of 10 — all 5 requests should succeed.
	handler := RateLimit(RateLimitOptions{Rate: 10, Burst: 10})(inner)

	for i := range 5 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
		req.RemoteAddr = "192.0.2.1:12345"
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("request %d: status = %d, want 202", i, rec.Code)
		}
	}
}

func TestRateLimit_RejectsAboveBurst(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	// Burst of 2 — the third request should be rejected.
	handler := RateLimit(RateLimitOptions{Rate: 1, Burst: 2})(inner)

	for range 2 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
		req.RemoteAddr = "192.0.2.1:12345"
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("initial burst request should succeed, got %d", rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-burst request: status = %d, want 429", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if _, ok := body["errors"]; !ok {
		t.Fatal("response body should contain 'errors' key")
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func TestRateLimit_SetsRetryAfterHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	handler := RateLimit(RateLimitOptions{Rate: 1, Burst: 1})(inner)

	// Exhaust the burst.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	handler.ServeHTTP(rec, req)

	// Next request should be rate-limited with Retry-After header.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("expected Retry-After header to be set")
	}
}

func TestRateLimit_PerIPIsolation(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	// Burst of 1 per IP.
	handler := RateLimit(RateLimitOptions{Rate: 1, Burst: 1})(inner)

	// First IP exhausts burst.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("first IP initial: status = %d, want 202", rec.Code)
	}

	// Second IP should still be allowed.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "198.51.100.2:54321"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("second IP: status = %d, want 202", rec.Code)
	}

	// First IP is now rate-limited.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("first IP over-limit: status = %d, want 429", rec.Code)
	}
}

func TestRateLimit_XForwardedForIgnored(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	handler := RateLimit(RateLimitOptions{Rate: 1, Burst: 1})(inner)

	// Exhaust burst using RemoteAddr "10.0.0.1".
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}

	// Same RemoteAddr should be rate-limited regardless of XFF.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "10.0.0.1:5678"
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 10.0.0.1")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same RemoteAddr with different XFF: status = %d, want 429", rec.Code)
	}

	// Different RemoteAddr with same XFF client should be allowed
	// (proves XFF is not used for keying).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "10.0.0.2:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.2")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("different RemoteAddr with same XFF client: status = %d, want 202", rec.Code)
	}
}

func TestRateLimit_DefaultOptions(t *testing.T) {
	opts := DefaultRateLimitOptions()
	if opts.Rate <= 0 {
		t.Fatalf("default rate should be positive, got %f", opts.Rate)
	}
	if opts.Burst <= 0 {
		t.Fatalf("default burst should be positive, got %d", opts.Burst)
	}
}

func TestRateLimit_ZeroValueOptions(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	// Zero-value options should fall back to defaults and not panic
	// or fail open.
	handler := RateLimit(RateLimitOptions{})(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("zero-value opts first request: status = %d, want 202", rec.Code)
	}
}
