// SPDX-License-Identifier: Apache-2.0

package tessera

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
)

// Reader provides read-only access to a Tessera POSIX log.
// Unlike Client, it creates no appender, signer, or background goroutines.
type Reader struct {
	storagePath string
}

// NewReader creates a read-only Tessera log reader for the given POSIX storage path.
func NewReader(storagePath string) *Reader {
	return &Reader{storagePath: storagePath}
}

// ReadCheckpoint returns the latest signed checkpoint from the log.
// The returned bytes are a signed sumdb note containing origin, tree size,
// and root hash. Returns os.ErrNotExist if no checkpoint has been published.
func (r *Reader) ReadCheckpoint(_ context.Context) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(r.storagePath, layout.CheckpointPath))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	return data, nil
}

// Read returns the raw entry at the given log index.
func (r *Reader) Read(ctx context.Context, index uint64) ([]byte, error) {
	size, err := r.integratedSize(ctx)
	if err != nil {
		return nil, fmt.Errorf("get integrated size: %w", err)
	}

	if index >= size {
		return nil, fmt.Errorf("index %d not yet integrated (log size: %d)", index, size)
	}

	bundleIndex := index / uint64(layout.EntryBundleWidth)
	entryIndex := index % uint64(layout.EntryBundleWidth)
	p := layout.PartialTileSize(0, bundleIndex, size)

	bundleData, err := r.readEntryBundle(bundleIndex, p)
	if err != nil {
		return nil, fmt.Errorf("read entry bundle: %w", err)
	}

	var bundle api.EntryBundle
	if err := bundle.UnmarshalText(bundleData); err != nil {
		return nil, fmt.Errorf("parse entry bundle: %w", err)
	}

	if int(entryIndex) >= len(bundle.Entries) {
		return nil, fmt.Errorf("entry index %d out of range (bundle has %d entries)", entryIndex, len(bundle.Entries))
	}

	return bundle.Entries[entryIndex], nil
}

// Close is a no-op for the file-based reader (no resources to release).
func (r *Reader) Close() error {
	return nil
}

// readEntryBundle reads a bundle, trying partial tile first then full.
func (r *Reader) readEntryBundle(index uint64, p uint8) ([]byte, error) {
	if p > 0 {
		data, err := os.ReadFile(filepath.Join(r.storagePath, layout.EntriesPath(index, p)))
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read partial entry bundle: %w", err)
		}
	}
	data, err := os.ReadFile(filepath.Join(r.storagePath, layout.EntriesPath(index, 0)))
	if err != nil {
		return nil, fmt.Errorf("read entry bundle: %w", err)
	}
	return data, nil
}

// integratedSize parses the latest checkpoint to determine current tree size.
func (r *Reader) integratedSize(ctx context.Context) (uint64, error) {
	cp, err := r.ReadCheckpoint(ctx)
	if err != nil {
		return 0, fmt.Errorf("read checkpoint for tree size: %w", err)
	}
	// Checkpoint note body format: <origin>\n<size>\n<base64-hash>\n
	parts := bytes.SplitN(cp, []byte{'\n'}, 4)
	if len(parts) < 3 {
		return 0, fmt.Errorf("invalid checkpoint format: expected at least 3 lines")
	}
	size, err := strconv.ParseUint(string(parts[1]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse checkpoint size %q: %w", parts[1], err)
	}
	return size, nil
}
