// SPDX-License-Identifier: Apache-2.0

package tessera

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	tesserapkg "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

type Client struct {
	appender   *tesserapkg.Appender
	reader     tesserapkg.LogReader
	shutdown   func(context.Context) error
	appenderCtx context.Context
	cancel     context.CancelFunc
}

// NewClient creates a new Tessera client.
// Note: A new ephemeral signer key is generated for each client instance.
// Checkpoint signatures cannot be verified across process restarts.
// This is acceptable for local-only transparency logs.
func NewClient(ctx context.Context, storagePath string, opts Options) (*Client, error) {
	// Create a cancellable context for the client's background tasks
	clientCtx, cancel := context.WithCancel(context.Background())

	// Initialize POSIX storage driver
	driver, err := posix.New(clientCtx, posix.Config{
		Path: storagePath,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("init POSIX storage: %w", err)
	}

	// Create a signer for checkpoints
	// For local transparency logs, we generate a test key
	signerKey, _, err := note.GenerateKey(rand.Reader, "tessera-log")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("generate signer key: %w", err)
	}

	signer, err := note.NewSigner(signerKey)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create signer: %w", err)
	}

	// Create append options
	appendOpts := tesserapkg.NewAppendOptions().
		WithBatching(uint(opts.CheckpointSize), opts.CheckpointTime).
		WithCheckpointInterval(opts.CheckpointTime).
		WithCheckpointSigner(signer)

	// Get appender and reader from the driver
	appender, shutdown, reader, err := tesserapkg.NewAppender(clientCtx, driver, appendOpts)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("init appender: %w", err)
	}

	return &Client{
		appender:    appender,
		reader:      reader,
		shutdown:    shutdown,
		appenderCtx: clientCtx,
		cancel:      cancel,
	}, nil
}

func (c *Client) Add(ctx context.Context, entry []byte) (uint64, error) {
	// Create entry and submit to appender
	future := c.appender.Add(ctx, tesserapkg.NewEntry(entry))

	// Resolve the future to get the index
	idx, err := future()
	if err != nil {
		return 0, fmt.Errorf("tessera add: %w", err)
	}
	return idx.Index, nil
}

func (c *Client) Read(ctx context.Context, index uint64) ([]byte, error) {
	// Get current integrated size
	size, err := c.reader.IntegratedSize(ctx)
	if err != nil {
		return nil, fmt.Errorf("get integrated size: %w", err)
	}

	if index >= size {
		return nil, fmt.Errorf("index %d not yet integrated (log size: %d)", index, size)
	}

	// Calculate bundle index and position within bundle
	bundleIndex := index / uint64(layout.EntryBundleWidth)
	entryIndex := index % uint64(layout.EntryBundleWidth)

	// Determine partial tile size if needed
	p := layout.PartialTileSize(0, bundleIndex, size)

	// Read entry bundle
	bundleData, err := c.reader.ReadEntryBundle(ctx, bundleIndex, p)
	if err != nil {
		return nil, fmt.Errorf("read entry bundle: %w", err)
	}

	// Parse bundle using library's parser
	var bundle api.EntryBundle
	if err := bundle.UnmarshalText(bundleData); err != nil {
		return nil, fmt.Errorf("parse entry bundle: %w", err)
	}

	// Return the specific entry
	if int(entryIndex) >= len(bundle.Entries) {
		return nil, fmt.Errorf("entry index %d out of range (bundle has %d entries)", entryIndex, len(bundle.Entries))
	}

	return bundle.Entries[entryIndex], nil
}

func (c *Client) Close() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown appender
	if err := c.shutdown(shutdownCtx); err != nil {
		c.cancel() // Still cancel context even if shutdown fails
		return fmt.Errorf("shutdown appender: %w", err)
	}

	c.cancel()
	return nil
}