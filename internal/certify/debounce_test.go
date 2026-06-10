// SPDX-License-Identifier: Apache-2.0

package certify

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/bus"
)

func TestDebouncer_SingleEvent(t *testing.T) {
	t.Parallel()

	const window = 20 * time.Millisecond
	var calls atomic.Int32
	var mu sync.Mutex
	var last bus.EvidenceEvent

	d := NewDebouncer(window, func(evt bus.EvidenceEvent) {
		calls.Add(1)
		mu.Lock()
		last = evt
		mu.Unlock()
	})

	d.Push(bus.EvidenceEvent{PolicyID: "p1", RecordCount: 3})
	time.Sleep(window + 30*time.Millisecond)

	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls: got %d want 1", got)
	}
	mu.Lock()
	gotEvt := last
	mu.Unlock()
	if gotEvt.PolicyID != "p1" || gotEvt.RecordCount != 3 {
		t.Fatalf("unexpected event: %+v", gotEvt)
	}
}

func TestDebouncer_CoalescesRapidEvents(t *testing.T) {
	t.Parallel()

	const window = 25 * time.Millisecond
	var calls atomic.Int32
	var mu sync.Mutex
	var last bus.EvidenceEvent

	d := NewDebouncer(window, func(evt bus.EvidenceEvent) {
		calls.Add(1)
		mu.Lock()
		last = evt
		mu.Unlock()
	})

	for i := range 5 {
		d.Push(bus.EvidenceEvent{PolicyID: "same", RecordCount: i})
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(window + 40*time.Millisecond)

	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls: got %d want 1", got)
	}
	mu.Lock()
	gotEvt := last
	mu.Unlock()
	if gotEvt.PolicyID != "same" || gotEvt.RecordCount != 4 {
		t.Fatalf("want last coalesced event record_count=4, got %+v", gotEvt)
	}
}

func TestDebouncer_SeparatePolicies(t *testing.T) {
	t.Parallel()

	const window = 20 * time.Millisecond
	var mu sync.Mutex
	seen := make(map[string]int)

	d := NewDebouncer(window, func(evt bus.EvidenceEvent) {
		mu.Lock()
		seen[evt.PolicyID]++
		mu.Unlock()
	})

	d.Push(bus.EvidenceEvent{PolicyID: "a", RecordCount: 1})
	d.Push(bus.EvidenceEvent{PolicyID: "b", RecordCount: 2})
	time.Sleep(window + 50*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if seen["a"] != 1 || seen["b"] != 1 {
		t.Fatalf("want one fire per policy, got %#v", seen)
	}
}

func TestDebouncer_InflightSkips(t *testing.T) {
	t.Parallel()

	const window = 15 * time.Millisecond
	var calls atomic.Int32
	handlerStarted := make(chan struct{}, 1)
	unblock := make(chan struct{})

	d := NewDebouncer(window, func(evt bus.EvidenceEvent) {
		calls.Add(1)
		if evt.PolicyID == "slow" {
			select {
			case handlerStarted <- struct{}{}:
			default:
			}
			<-unblock
		}
	})

	d.Push(bus.EvidenceEvent{PolicyID: "slow", RecordCount: 1})
	time.Sleep(window + 40*time.Millisecond)

	select {
	case <-handlerStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handler did not start")
	}

	d.Push(bus.EvidenceEvent{PolicyID: "slow", RecordCount: 2})
	time.Sleep(window + 40*time.Millisecond)

	close(unblock)
	time.Sleep(50 * time.Millisecond)

	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls: got %d want 1 (second fire skipped while in-flight)", got)
	}
}
