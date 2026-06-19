// SPDX-License-Identifier: Apache-2.0

package tessera

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

const signerKeyOrigin = "tessera-log"

// LoadOrGenerateSignerKey loads a note signer key from the given file path.
// If the file does not exist, a new Ed25519 key pair is generated, persisted
// to the path (with 0600 permissions), and returned.
//
// The file stores both the signer (private) and verifier (public) key strings,
// separated by a newline.
//
// When path is empty the key is generated in memory and not persisted -- this
// preserves the previous ephemeral-key behaviour for tests and dev setups.
//
// The returned generated flag is true when a new key pair was created (either
// ephemeral or freshly persisted) and false when an existing key was loaded.
func LoadOrGenerateSignerKey(path string) (skey, vkey string, generated bool, err error) {
	if path == "" {
		skey, vkey, err = generateKey()
		return skey, vkey, err == nil, err
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-controlled key path
	if err != nil {
		if !os.IsNotExist(err) {
			return "", "", false, fmt.Errorf("read signer key: %w", err)
		}
		// Key file does not exist -- generate and persist.
		skey, vkey, err = generateAndPersist(path)
		return skey, vkey, err == nil, err
	}

	// Warn if key file permissions are broader than 0600.
	info, statErr := os.Stat(path)
	if statErr == nil && info.Mode().Perm()&0077 != 0 {
		slog.Warn("tessera signer key file has overly permissive permissions", "path", path, "mode", info.Mode().Perm())
	}

	skey, vkey, err = parseKeyFile(string(data), path)
	if err != nil {
		return "", "", false, err
	}

	return skey, vkey, false, nil
}

// parseKeyFile validates and returns the signer and verifier keys from file contents.
// The file format is two lines: signer key, then verifier key.
func parseKeyFile(content, path string) (skey, vkey string, err error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return "", "", fmt.Errorf("signer key file is empty: %s", path)
	}

	lines := strings.SplitN(content, "\n", 3)
	if len(lines) < 2 {
		return "", "", fmt.Errorf("invalid signer key file %s: expected signer and verifier key lines", path)
	}

	skey = strings.TrimSpace(lines[0])
	vkey = strings.TrimSpace(lines[1])

	// Validate the signer key is usable.
	if _, err := note.NewSigner(skey); err != nil {
		return "", "", fmt.Errorf("invalid signer key in %s: %w", path, err)
	}

	// Validate the verifier key is usable.
	if _, err := note.NewVerifier(vkey); err != nil {
		return "", "", fmt.Errorf("invalid verifier key in %s: %w", path, err)
	}

	return skey, vkey, nil
}

// generateKey creates a fresh Ed25519 key pair in memory.
func generateKey() (skey, vkey string, err error) {
	skey, vkey, err = note.GenerateKey(rand.Reader, signerKeyOrigin)
	if err != nil {
		return "", "", fmt.Errorf("generate signer key: %w", err)
	}
	return skey, vkey, nil
}

// generateAndPersist generates a new key pair, writes both keys to path,
// and returns them.
func generateAndPersist(path string) (skey, vkey string, err error) {
	skey, vkey, err = generateKey()
	if err != nil {
		return "", "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { //nolint:gosec // G301: parent dir for key file
		return "", "", fmt.Errorf("create key directory: %w", err)
	}

	// File format: signer key (line 1), verifier key (line 2).
	fileContent := skey + "\n" + vkey + "\n"

	// Atomic write: create a unique temp file then rename into place.
	f, err := os.CreateTemp(filepath.Dir(path), ".signer-*.tmp")
	if err != nil {
		return "", "", fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()

	if err := f.Chmod(0600); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err := f.Write([]byte(fileContent)); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("write signer key: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("rename signer key: %w", err)
	}

	return skey, vkey, nil
}
