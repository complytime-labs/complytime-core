// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcher_DetectsChangesAndReloads(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.cedar")
	if err := os.WriteFile(policyFile, []byte(`permit(principal, action, resource);`), 0644); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	w := NewWatcher(a, tmpDir, 50*time.Millisecond)
	w.Start()
	defer w.Stop()

	oldPS := a.policies.Load()

	// Wait a bit for initial scan
	time.Sleep(100 * time.Millisecond)

	// Modify file
	if err := os.WriteFile(policyFile, []byte(`forbid(principal, action, resource);`), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for watcher to detect and reload
	time.Sleep(200 * time.Millisecond)

	newPS := a.policies.Load()
	if oldPS == newPS {
		t.Error("watcher should have detected change and reloaded policies")
	}
}

func TestWatcher_SkipsReloadOnParseError(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.cedar")
	if err := os.WriteFile(policyFile, []byte(`permit(principal, action, resource);`), 0644); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	w := NewWatcher(a, tmpDir, 50*time.Millisecond)
	w.Start()
	defer w.Stop()

	oldPS := a.policies.Load()

	// Wait a bit for initial scan
	time.Sleep(100 * time.Millisecond)

	// Write invalid Cedar syntax
	if err := os.WriteFile(policyFile, []byte(`this is not valid cedar syntax`), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for watcher to attempt reload
	time.Sleep(200 * time.Millisecond)

	newPS := a.policies.Load()
	if oldPS != newPS {
		t.Error("watcher should have kept old policy set on parse error")
	}
}

func TestWatcher_StopsCleanly(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.cedar")
	if err := os.WriteFile(policyFile, []byte(`permit(principal, action, resource);`), 0644); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	w := NewWatcher(a, tmpDir, 50*time.Millisecond)
	w.Start()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Stop should complete quickly
	done := make(chan struct{})
	go func() {
		w.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(1 * time.Second):
		t.Error("watcher.Stop() did not complete in time")
	}
}
