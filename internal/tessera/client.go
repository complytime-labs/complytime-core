// SPDX-License-Identifier: Apache-2.0

package tessera

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	tesserapkg "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

type Client struct {
	appender    *tesserapkg.Appender
	reader      tesserapkg.LogReader
	shutdown    func(context.Context) error
	appenderCtx context.Context
	cancel      context.CancelFunc
	verifierKey string
}

// NewClient creates a new Tessera client.
// When opts.SignerKeyPath is set the signer key is loaded from (or generated
// into) that file so the log maintains a stable identity across restarts.
// An empty SignerKeyPath preserves the previous ephemeral-key behaviour.
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

	// Load or generate signer key pair
	signerKey, verifierKey, generated, err := LoadOrGenerateSignerKey(opts.SignerKeyPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("load signer key: %w", err)
	}
	if opts.SignerKeyPath == "" {
		slog.Warn("tessera using ephemeral signer key — checkpoint signatures will not survive restart")
	} else if generated {
		slog.Info("tessera signer key generated", "path", opts.SignerKeyPath)
	} else {
		slog.Info("tessera signer key loaded", "path", opts.SignerKeyPath)
	}

	signer, err := note.NewSigner(signerKey)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create signer: %w", err)
	}

	// Create append options
	appendOpts := tesserapkg.NewAppendOptions().
		WithBatching(uint(opts.CheckpointSize), opts.CheckpointTime). //nolint:gosec // G115: config value
		WithCheckpointInterval(opts.CheckpointTime).
		WithCheckpointSigner(signer)

	// Wire witnesses if a policy file is configured
	if opts.WitnessPolicyPath != "" {
		policyBytes, err := os.ReadFile(opts.WitnessPolicyPath)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("read witness policy: %w", err)
		}
		witnessGroup, err := tesserapkg.NewWitnessGroupFromPolicy(policyBytes)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("parse witness policy: %w", err)
		}
		witnessOpts := &tesserapkg.WitnessOptions{
			Timeout:  opts.WitnessTimeout,
			FailOpen: opts.WitnessFailOpen,
		}
		appendOpts = appendOpts.WithWitnesses(witnessGroup, witnessOpts)
		slog.Info("tessera witnesses configured",
			"policy", opts.WitnessPolicyPath,
			"fail_open", opts.WitnessFailOpen,
			"timeout", opts.WitnessTimeout,
		)
	}

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
		verifierKey: verifierKey,
	}, nil
}

// VerifierKey returns the log's public verification key. Witnesses and
// clients need this to verify checkpoint signatures.
func (c *Client) VerifierKey() string {
	return c.verifierKey
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
