// internal/tessera/client.go
package tessera

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	tesserapkg "github.com/transparency-dev/tessera"
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
	// Get the integrated size to verify the entry has been sequenced
	integratedSize, err := c.reader.IntegratedSize(ctx)
	if err != nil {
		return nil, fmt.Errorf("tessera get integrated size: %w", err)
	}

	if index >= integratedSize {
		return nil, fmt.Errorf("index %d not yet integrated (log size: %d)", index, integratedSize)
	}

	// Determine which entry bundle contains this index
	// Entry bundles are stored in groups (default 256 entries per bundle)
	bundleIndex := index / 256
	bundleOffset := index % 256

	// Read the entry bundle
	// Try reading with partial flag 0 first, then try higher values if it fails
	var bundleData []byte
	for p := uint8(0); p < 10; p++ {
		data, err := c.reader.ReadEntryBundle(ctx, bundleIndex, p)
		if err == nil && len(data) > 0 {
			bundleData = data
			break
		}
	}

	if bundleData == nil || len(bundleData) == 0 {
		return nil, fmt.Errorf("entry bundle %d not found or empty", bundleIndex)
	}

	// Parse the bundle to extract the entry
	// The bundle format is: each entry is prefixed with uint16 big-endian length, then data
	var offset int
	var entry []byte
	for i := uint64(0); i <= bundleOffset; i++ {
		if offset+2 > len(bundleData) {
			return nil, fmt.Errorf("malformed entry bundle: unexpected EOF at offset %d (need 2 bytes for length)", offset)
		}

		// Read uint16 big-endian length
		length := int(bundleData[offset])<<8 | int(bundleData[offset+1])
		offset += 2

		if offset+length > len(bundleData) {
			return nil, fmt.Errorf("malformed entry bundle: entry data exceeds bundle size (offset=%d, length=%d, total=%d)", offset, length, len(bundleData))
		}

		if i == bundleOffset {
			entry = bundleData[offset : offset+length]
			break
		}
		offset += length
	}

	return entry, nil
}

func (c *Client) Close() error {
	// Call the shutdown function with a reasonable timeout
	// The shutdown function needs to see the background tasks in the appenderCtx
	if c.shutdown != nil {
		shutdownCtx, cancel := context.WithTimeout(c.appenderCtx, 5*time.Second)
		defer cancel()
		if err := c.shutdown(shutdownCtx); err != nil {
			// Shutdown timeout is acceptable - we'll cancel the context next
		}
	}

	// Cancel the appender context to stop any background tasks
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}