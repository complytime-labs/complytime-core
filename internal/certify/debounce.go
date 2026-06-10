// SPDX-License-Identifier: Apache-2.0

package certify

import (
	"log/slog"
	"sync"
	"time"

	"github.com/complytime-labs/complytime-core/internal/bus"
)

// Debouncer coalesces rapid evidence events per policy into a single callback
// after a quiet period. It also tracks in-flight callbacks to prevent duplicate
// concurrent processing for the same policy.
type Debouncer struct {
	window   time.Duration
	handler  func(bus.EvidenceEvent)
	mu       sync.Mutex
	timers   map[string]*time.Timer
	inflight map[string]bool
}

// NewDebouncer creates a debouncer that waits for `window` of quiet time before
// firing handler. If handler is already running for a policy, new events are
// coalesced but won't fire a second concurrent handler.
func NewDebouncer(window time.Duration, handler func(bus.EvidenceEvent)) *Debouncer {
	return &Debouncer{
		window:   window,
		handler:  handler,
		timers:   make(map[string]*time.Timer),
		inflight: make(map[string]bool),
	}
}

// Push records a new event for the given policy. Resets the debounce timer.
func (d *Debouncer) Push(evt bus.EvidenceEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if t, ok := d.timers[evt.PolicyID]; ok {
		t.Stop()
	}

	d.timers[evt.PolicyID] = time.AfterFunc(d.window, func() {
		d.fire(evt)
	})
}

func (d *Debouncer) fire(evt bus.EvidenceEvent) {
	d.mu.Lock()
	delete(d.timers, evt.PolicyID)
	if d.inflight[evt.PolicyID] {
		slog.Debug("skipping duplicate posture check — already in-flight", "policy_id", evt.PolicyID)
		d.mu.Unlock()
		return
	}
	d.inflight[evt.PolicyID] = true
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		delete(d.inflight, evt.PolicyID)
		d.mu.Unlock()
	}()

	d.handler(evt)
}
