// SPDX-License-Identifier: Apache-2.0

package tessera_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/tessera"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerateSignerKey_GeneratesNewKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signer.key")

	skey, vkey, generated, err := tessera.LoadOrGenerateSignerKey(keyPath)
	require.NoError(t, err)
	assert.True(t, generated, "new key should be flagged as generated")

	// Signer key should have the expected note format
	assert.True(t, strings.HasPrefix(skey, "PRIVATE+KEY+"), "signer key should start with PRIVATE+KEY+")
	assert.NotEmpty(t, vkey, "verifier key should not be empty")
	assert.False(t, strings.HasPrefix(vkey, "PRIVATE+KEY+"), "verifier key must not be a private key")

	// File should have been written with both keys
	data, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2, "key file should contain exactly two lines")
	assert.Equal(t, skey, lines[0])
	assert.Equal(t, vkey, lines[1])
}

func TestLoadOrGenerateSignerKey_LoadsExistingKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signer.key")

	// Generate initial key
	skey1, vkey1, generated1, err := tessera.LoadOrGenerateSignerKey(keyPath)
	require.NoError(t, err)
	assert.True(t, generated1, "first call should generate")

	// Load again -- should return the same key pair
	skey2, vkey2, generated2, err := tessera.LoadOrGenerateSignerKey(keyPath)
	require.NoError(t, err)
	assert.False(t, generated2, "second call should load, not generate")

	assert.Equal(t, skey1, skey2, "signer key should be stable across loads")
	assert.Equal(t, vkey1, vkey2, "verifier key should be stable across loads")
}

func TestLoadOrGenerateSignerKey_CreatesParentDirs(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "nested", "dir", "signer.key")

	skey, _, generated, err := tessera.LoadOrGenerateSignerKey(keyPath)
	require.NoError(t, err)
	assert.True(t, generated)
	assert.True(t, strings.HasPrefix(skey, "PRIVATE+KEY+"))
}

func TestLoadOrGenerateSignerKey_FilePermissions(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signer.key")

	_, _, _, err := tessera.LoadOrGenerateSignerKey(keyPath)
	require.NoError(t, err)

	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "key file should be owner-only read/write")
}

func TestLoadOrGenerateSignerKey_EmptyPathGeneratesEphemeral(t *testing.T) {
	skey1, _, generated1, err := tessera.LoadOrGenerateSignerKey("")
	require.NoError(t, err)
	assert.True(t, generated1, "ephemeral key should be flagged as generated")
	assert.True(t, strings.HasPrefix(skey1, "PRIVATE+KEY+"))

	// Second call with empty path generates a different key (ephemeral)
	skey2, _, generated2, err := tessera.LoadOrGenerateSignerKey("")
	require.NoError(t, err)
	assert.True(t, generated2, "ephemeral key should be flagged as generated")
	assert.NotEqual(t, skey1, skey2, "empty path should generate a new key each time")
}

func TestLoadOrGenerateSignerKey_CorruptedFileReturnsError(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signer.key")

	err := os.WriteFile(keyPath, []byte("not-a-valid-key\nalso-bad"), 0600)
	require.NoError(t, err)

	_, _, _, err = tessera.LoadOrGenerateSignerKey(keyPath)
	assert.Error(t, err, "should reject invalid key data")
	assert.Contains(t, err.Error(), "invalid signer key")
}

func TestLoadOrGenerateSignerKey_SingleLineFileReturnsError(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signer.key")

	err := os.WriteFile(keyPath, []byte("PRIVATE+KEY+tessera-log+abc123+keydata"), 0600)
	require.NoError(t, err)

	_, _, _, err = tessera.LoadOrGenerateSignerKey(keyPath)
	assert.Error(t, err, "should reject file with only one line")
	assert.Contains(t, err.Error(), "expected signer and verifier key lines")
}

func TestLoadOrGenerateSignerKey_EmptyFileReturnsError(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "signer.key")

	err := os.WriteFile(keyPath, []byte(""), 0600)
	require.NoError(t, err)

	_, _, _, err = tessera.LoadOrGenerateSignerKey(keyPath)
	assert.Error(t, err, "should reject empty key file")
	assert.Contains(t, err.Error(), "empty")
}
