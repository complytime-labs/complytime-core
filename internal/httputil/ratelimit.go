// SPDX-License-Identifier: Apache-2.0

package httputil

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// defaultCleanupInterval is how often the background goroutine
	// sweeps the client map for idle entries.
	defaultCleanupInterval = 5 * time.Minute

	// defaultIdleTimeout is how long a client entry can remain
	// unused before it is evicted.
	defaultIdleTimeout = 10 * time.Minute
)

// RateLimitOptions configures the per-IP token bucket rate limiter.
type RateLimitOptions struct {
	// Rate is the number of requests per second allowed per IP.
	Rate float64

	// Burst is the maximum number of requests that can be made in a
	// single burst before rate limiting kicks in.
	Burst int

	// CleanupInterval is how often idle client entries are evicted.
	// Defaults to 5 minutes.
	CleanupInterval time.Duration

	// IdleTimeout is how long a client entry can remain unused
	// before it is evicted. Defaults to 10 minutes.
	IdleTimeout time.Duration

	// MaxClients is the maximum number of distinct client IPs tracked
	// concurrently. New IPs are rejected with 429 when the cap is
	// reached, preventing memory exhaustion from IP spray attacks.
	// Defaults to 100000.
	MaxClients int
}

// DefaultRateLimitOptions returns sensible defaults for the ingest endpoint:
// 10 requests/second with a burst of 20.
func DefaultRateLimitOptions() RateLimitOptions {
	return RateLimitOptions{
		Rate:            10,
		Burst:           20,
		CleanupInterval: defaultCleanupInterval,
		IdleTimeout:     defaultIdleTimeout,
		MaxClients:      100000,
	}
}

// clientEntry pairs a limiter with the last time it was accessed.
type clientEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimit returns middleware that enforces per-IP token bucket rate
// limiting using golang.org/x/time/rate. Clients that exceed their
// allowance receive 429 Too Many Requests with a Retry-After header.
//
// The client IP is extracted from the request's RemoteAddr.
func RateLimit(opts RateLimitOptions) func(http.Handler) http.Handler {
	defaults := DefaultRateLimitOptions()
	if opts.Rate <= 0 {
		opts.Rate = defaults.Rate
	}
	if opts.Burst <= 0 {
		opts.Burst = defaults.Burst
	}

	cleanupInterval := opts.CleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = defaultCleanupInterval
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	maxClients := opts.MaxClients
	if maxClients <= 0 {
		maxClients = defaults.MaxClients
	}

	var (
		mu      sync.Mutex
		clients = make(map[string]*clientEntry)
	)

	// limiterFor returns the rate limiter for ip, or nil if the client
	// map is full and ip is not already tracked.
	limiterFor := func(ip string) *rate.Limiter {
		mu.Lock()
		defer mu.Unlock()

		if entry, ok := clients[ip]; ok {
			entry.lastSeen = time.Now()
			return entry.limiter
		}
		if len(clients) >= maxClients {
			return nil
		}
		lim := rate.NewLimiter(rate.Limit(opts.Rate), opts.Burst)
		clients[ip] = &clientEntry{
			limiter:  lim,
			lastSeen: time.Now(),
		}
		return lim
	}

	// Background goroutine to evict idle entries.
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			cutoff := time.Now().Add(-idleTimeout)
			for ip, entry := range clients {
				if entry.lastSeen.Before(cutoff) {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			lim := limiterFor(ip)

			if lim == nil {
				// Client map is full — reject to prevent memory exhaustion.
				slog.Warn("rate_limit_max_clients", "client_ip", ip)
				w.Header().Set("Retry-After", "1")
				WriteJSON(w, http.StatusTooManyRequests, map[string]any{
					"errors": []string{"rate limit exceeded — try again later"},
				})
				return
			}

			reservation := lim.Reserve()
			if !reservation.OK() {
				// Misconfigured limiter — reject rather than fail open.
				slog.Warn("rate_limit_exceeded", "client_ip", ip, "retry_after", 1)
				w.Header().Set("Retry-After", "1")
				WriteJSON(w, http.StatusTooManyRequests, map[string]any{
					"errors": []string{"rate limit exceeded — try again later"},
				})
				return
			}

			delay := reservation.Delay()
			if delay > 0 {
				// Cancel the reservation — we reject rather than queue.
				reservation.Cancel()
				retrySecs := int(math.Ceil(delay.Seconds()))
				slog.Warn("rate_limit_exceeded", "client_ip", ip, "retry_after", retrySecs)
				w.Header().Set("Retry-After", strconv.Itoa(retrySecs))
				WriteJSON(w, http.StatusTooManyRequests, map[string]any{
					"errors": []string{"rate limit exceeded — try again later"},
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP from the request's RemoteAddr.
// X-Forwarded-For is intentionally ignored to prevent spoofing.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
