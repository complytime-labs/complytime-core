// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Watcher provides hot-reload of Cedar policies via polling.
type Watcher struct {
	authorizer *Authorizer
	dir        string
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
	modTimes   map[string]time.Time
}

// NewWatcher creates a watcher that polls policyDir for changes and reloads the authorizer.
func NewWatcher(authorizer *Authorizer, dir string, interval time.Duration) *Watcher {
	return &Watcher{
		authorizer: authorizer,
		dir:        dir,
		interval:   interval,
		stopCh:     make(chan struct{}),
		modTimes:   make(map[string]time.Time),
	}
}

// Start begins polling for policy file changes.
func (w *Watcher) Start() {
	w.wg.Add(1)
	go w.run()
}

// Stop stops the watcher and waits for the goroutine to exit.
func (w *Watcher) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

// run is the polling loop.
func (w *Watcher) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Initial scan
	w.scanModTimes()

	for {
		select {
		case <-ticker.C:
			if w.hasChanges() {
				if err := w.authorizer.Reload(w.dir); err != nil {
					log.Printf("failed to reload policies: %v", err)
				} else {
					w.scanModTimes()
				}
			}
		case <-w.stopCh:
			return
		}
	}
}

// scanModTimes records current modification times of all .cedar files.
func (w *Watcher) scanModTimes() {
	newModTimes := make(map[string]time.Time)

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".cedar" {
			continue
		}
		path := filepath.Join(w.dir, entry.Name())
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		newModTimes[entry.Name()] = info.ModTime()
	}

	w.modTimes = newModTimes
}

// hasChanges checks if any .cedar file has been added, removed, or modified.
func (w *Watcher) hasChanges() bool {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return false
	}

	currentFiles := make(map[string]time.Time)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".cedar" {
			continue
		}
		path := filepath.Join(w.dir, entry.Name())
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		currentFiles[entry.Name()] = info.ModTime()
	}

	// Check for added or modified files
	for name, modTime := range currentFiles {
		oldModTime, exists := w.modTimes[name]
		if !exists || !modTime.Equal(oldModTime) {
			return true
		}
	}

	// Check for removed files
	for name := range w.modTimes {
		if _, exists := currentFiles[name]; !exists {
			return true
		}
	}

	return false
}
