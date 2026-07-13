package locker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tessera "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

// Ledger is a single transparency log for one subject.
// It wraps a Tessera appender and reader with an in-memory digest index.
type Ledger struct {
	subjectID   string
	storagePath string
	appender    *tessera.Appender
	reader      tessera.LogReader
	shutdown    func(context.Context) error
	verifierKey string

	mu          sync.RWMutex
	digestIndex map[string]uint64 // hex SHA-256 → log index
}

// NewLedger creates a new ledger for the given subject. The Tessera log is stored
// under basePath/subjectID/. A new Ed25519 signing key is generated if one does
// not already exist.
func NewLedger(ctx context.Context, subjectID, basePath string) (*Ledger, error) {
	storagePath := filepath.Join(basePath, subjectID)

	origin := ledgerOrigin(subjectID)
	keyPath := filepath.Join(storagePath, "signer.key")
	signerKey, verifierKey, err := loadOrGenerateKey(keyPath, origin)
	if err != nil {
		return nil, fmt.Errorf("signer key for %s: %w", subjectID, err)
	}

	signer, err := note.NewSigner(signerKey)
	if err != nil {
		return nil, fmt.Errorf("creating note signer: %w", err)
	}

	// Tessera's background goroutines (checkpoint publisher, GC, integration)
	// run for the lifetime of the appender and are stopped by the shutdown
	// function, not by context cancellation. Use context.Background() so the
	// caller's context (which may be a short-lived startup timeout) does not
	// kill long-running Tessera goroutines.
	appenderCtx := context.Background()

	driver, err := posix.New(appenderCtx, posix.Config{
		Path: filepath.Join(storagePath, "tessera"),
	})
	if err != nil {
		return nil, fmt.Errorf("creating posix driver for %s: %w", subjectID, err)
	}

	opts := tessera.NewAppendOptions().
		WithBatching(256, 1*time.Second).
		WithCheckpointInterval(10 * time.Second).
		WithCheckpointSigner(signer)

	appender, shutdown, reader, err := tessera.NewAppender(appenderCtx, driver, opts)
	if err != nil {
		return nil, fmt.Errorf("creating appender for %s: %w", subjectID, err)
	}

	l := &Ledger{
		subjectID:   subjectID,
		storagePath: storagePath,
		appender:    appender,
		reader:      reader,
		shutdown:    shutdown,
		verifierKey: verifierKey,
		digestIndex: make(map[string]uint64),
	}

	if err := l.rebuildDigestIndex(ctx); err != nil {
		slog.Warn("failed to rebuild digest index", "subject", subjectID, "error", err)
	}

	return l, nil
}

// Seal appends a receipt to the ledger and returns the assigned log index.
func (l *Ledger) Seal(ctx context.Context, receipt []byte) (uint64, error) {
	future := l.appender.Add(ctx, tessera.NewEntry(receipt))
	idx, err := future()
	if err != nil {
		return 0, fmt.Errorf("sealing receipt: %w", err)
	}

	digest := SHA256Hex(receipt)
	l.mu.Lock()
	l.digestIndex[digest] = idx.Index
	l.mu.Unlock()

	return idx.Index, nil
}

// Fetch retrieves a sealed receipt by log index.
// It waits for the entry to be integrated into the log before reading it.
func (l *Ledger) Fetch(ctx context.Context, index uint64) ([]byte, error) {
	// Wait for the entry to be integrated
	if err := l.waitForIntegration(ctx, index); err != nil {
		return nil, err
	}

	size, err := l.reader.IntegratedSize(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting integrated size: %w", err)
	}
	if index >= size {
		return nil, fmt.Errorf("%w: index %d, size %d", ErrIndexOutOfRange, index, size)
	}

	// Calculate which bundle contains this index
	bundleIndex := index / layout.EntryBundleWidth
	// Calculate partial tile size (0 means full tile)
	p := layout.PartialTileSize(0, bundleIndex, size)

	bundleData, err := l.reader.ReadEntryBundle(ctx, bundleIndex, p)
	if err != nil {
		return nil, fmt.Errorf("reading entry bundle: %w", err)
	}

	var bundle api.EntryBundle
	if err := bundle.UnmarshalText(bundleData); err != nil {
		return nil, fmt.Errorf("parsing entry bundle: %w", err)
	}

	localIndex := index % layout.EntryBundleWidth
	if int(localIndex) >= len(bundle.Entries) {
		return nil, fmt.Errorf("%w: entry %d not in bundle", ErrIndexOutOfRange, index)
	}

	return bundle.Entries[localIndex], nil
}

// VerifyDigest checks if a receipt with the given hex-encoded SHA-256 digest
// exists in this ledger. Returns the log index and true if found.
func (l *Ledger) VerifyDigest(hexDigest string) (uint64, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	idx, ok := l.digestIndex[hexDigest]
	return idx, ok
}

// VerifierKey returns the public verification key string for this ledger's
// checkpoint signatures.
func (l *Ledger) VerifierKey() string {
	return l.verifierKey
}

// SubjectID returns the subject ID this ledger belongs to.
func (l *Ledger) SubjectID() string {
	return l.subjectID
}

// TesseraStoragePath returns the filesystem path to this ledger's Tessera
// storage (tiles, checkpoint, entry bundles).
func (l *Ledger) TesseraStoragePath() string {
	return filepath.Join(l.storagePath, "tessera")
}

// Close gracefully shuts down the ledger's Tessera appender.
func (l *Ledger) Close(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return l.shutdown(shutdownCtx)
}

// SHA256Hex computes the hex-encoded SHA-256 digest of data.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func ledgerOrigin(subjectID string) string {
	return "complytime/" + subjectID
}

func (l *Ledger) integratedSize(ctx context.Context) (uint64, error) {
	return l.reader.IntegratedSize(ctx)
}

// waitForIntegration polls until the given index has been integrated into the log.
func (l *Ledger) waitForIntegration(ctx context.Context, targetIndex uint64) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for index %d to be integrated", targetIndex)
		case <-ticker.C:
			size, err := l.reader.IntegratedSize(ctx)
			if err != nil {
				return fmt.Errorf("checking integrated size: %w", err)
			}
			if size > targetIndex {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (l *Ledger) rebuildDigestIndex(ctx context.Context) error {
	size, err := l.integratedSize(ctx)
	if err != nil {
		return err
	}
	for i := uint64(0); i < size; i++ {
		data, err := l.Fetch(ctx, i)
		if err != nil {
			return fmt.Errorf("fetching index %d: %w", i, err)
		}
		digest := SHA256Hex(data)
		l.digestIndex[digest] = i
	}
	slog.Info("rebuilt digest index", "subject", l.subjectID, "entries", size)
	return nil
}

// Key management helpers

func loadOrGenerateKey(path, origin string) (signerKey, verifierKey string, err error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parseKeyFile(string(data))
	}
	if !os.IsNotExist(err) {
		return "", "", fmt.Errorf("reading key file: %w", err)
	}
	return generateAndPersist(path, origin)
}

func parseKeyFile(content string) (string, string, error) {
	lines := splitLines(content)
	if len(lines) < 2 {
		return "", "", fmt.Errorf("key file must have signer and verifier lines")
	}
	skey, vkey := lines[0], lines[1]
	if _, err := note.NewSigner(skey); err != nil {
		return "", "", fmt.Errorf("invalid signer key: %w", err)
	}
	if _, err := note.NewVerifier(vkey); err != nil {
		return "", "", fmt.Errorf("invalid verifier key: %w", err)
	}
	return skey, vkey, nil
}

func generateAndPersist(path, origin string) (string, string, error) {
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".signer-*.key")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return "", "", err
	}
	if _, err := fmt.Fprintf(tmp, "%s\n%s\n", skey, vkey); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", "", err
	}
	return skey, vkey, nil
}

func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
