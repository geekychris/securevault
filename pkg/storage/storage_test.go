package storage

import (
	"os"
	"testing"

	vaulterrors "securevault/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey is a fixed 32-byte key for testing
var testKey = []byte("01234567890123456789012345678901")

func testKeyProvider() ([]byte, error) {
	return testKey, nil
}

func testBackend(t *testing.T) (Backend, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "securevault-storage-test")
	require.NoError(t, err)

	backend, err := NewFileBackend(tmpDir, testKeyProvider)
	require.NoError(t, err)

	return backend, func() { os.RemoveAll(tmpDir) }
}

func TestWriteAndReadSecret(t *testing.T) {
	backend, cleanup := testBackend(t)
	defer cleanup()

	data := map[string]interface{}{
		"username": "admin",
		"password": "secret",
	}

	err := backend.WriteSecret("app/db", data, WriteOptions{UserID: "test"})
	require.NoError(t, err)

	secret, err := backend.ReadSecret("app/db", ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, "admin", secret.Data["username"])
	assert.Equal(t, "secret", secret.Data["password"])
	assert.Equal(t, 1, secret.Version)
}

func TestReadNonExistentSecret(t *testing.T) {
	backend, cleanup := testBackend(t)
	defer cleanup()

	_, err := backend.ReadSecret("nonexistent", ReadOptions{})
	assert.Error(t, err)
	assert.True(t, vaulterrors.IsNotFound(err))
}

func TestVersioning(t *testing.T) {
	backend, cleanup := testBackend(t)
	defer cleanup()

	// Write v1
	err := backend.WriteSecret("test/versioned", map[string]interface{}{"v": "1"}, WriteOptions{UserID: "test"})
	require.NoError(t, err)

	// Write v2
	err = backend.WriteSecret("test/versioned", map[string]interface{}{"v": "2"}, WriteOptions{UserID: "test"})
	require.NoError(t, err)

	// Read latest
	secret, err := backend.ReadSecret("test/versioned", ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, "2", secret.Data["v"])
	assert.Equal(t, 2, secret.Version)

	// Read v1
	secret, err = backend.ReadSecret("test/versioned", ReadOptions{Version: 1})
	require.NoError(t, err)
	assert.Equal(t, "1", secret.Data["v"])
	assert.Equal(t, 1, secret.Version)

	// Metadata
	meta, err := backend.GetSecretMetadata("test/versioned")
	require.NoError(t, err)
	assert.Equal(t, 2, meta.CurrentVersion)
	assert.Len(t, meta.Versions, 2)
}

func TestDeleteSecret(t *testing.T) {
	backend, cleanup := testBackend(t)
	defer cleanup()

	err := backend.WriteSecret("test/delete", map[string]interface{}{"key": "value"}, WriteOptions{UserID: "test"})
	require.NoError(t, err)

	err = backend.DeleteSecret("test/delete", DeleteOptions{Destroy: true, UserID: "test"})
	require.NoError(t, err)

	_, err = backend.ReadSecret("test/delete", ReadOptions{})
	assert.Error(t, err)
	assert.True(t, vaulterrors.IsNotFound(err))
}

func TestDeleteSpecificVersions(t *testing.T) {
	backend, cleanup := testBackend(t)
	defer cleanup()

	// Write 3 versions
	for i := 0; i < 3; i++ {
		err := backend.WriteSecret("test/multi", map[string]interface{}{"v": i}, WriteOptions{UserID: "test"})
		require.NoError(t, err)
	}

	// Soft delete v1
	err := backend.DeleteSecret("test/multi", DeleteOptions{Versions: []int{1}, UserID: "test"})
	require.NoError(t, err)

	// v1 should be destroyed
	_, err = backend.ReadSecret("test/multi", ReadOptions{Version: 1})
	assert.Error(t, err)
	assert.True(t, vaulterrors.IsVersionDestroyed(err))

	// v2 and v3 should still be accessible
	secret, err := backend.ReadSecret("test/multi", ReadOptions{Version: 2})
	require.NoError(t, err)
	assert.Equal(t, float64(1), secret.Data["v"])

	secret, err = backend.ReadSecret("test/multi", ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, float64(2), secret.Data["v"])
}

func TestListSecrets(t *testing.T) {
	backend, cleanup := testBackend(t)
	defer cleanup()

	for _, path := range []string{"app/a", "app/b", "app/c"} {
		err := backend.WriteSecret(path, map[string]interface{}{"key": "value"}, WriteOptions{UserID: "test"})
		require.NoError(t, err)
	}

	secrets, err := backend.ListSecrets("app")
	require.NoError(t, err)
	assert.Len(t, secrets, 3)
}

func TestEncryptionAtRest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securevault-enc-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	backend, err := NewFileBackend(tmpDir, testKeyProvider)
	require.NoError(t, err)

	err = backend.WriteSecret("secret/test", map[string]interface{}{
		"password": "super-secret-value",
	}, WriteOptions{UserID: "test"})
	require.NoError(t, err)

	// Read the raw file and verify it's encrypted
	fb := backend.(*FileBackend)
	versionPath := fb.getSecretVersionPath("secret/test", 1)
	raw, err := os.ReadFile(versionPath)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "super-secret-value")

	// Metadata should also be encrypted
	metaPath := fb.getSecretMetadataPath("secret/test")
	rawMeta, err := os.ReadFile(metaPath)
	require.NoError(t, err)
	assert.NotContains(t, string(rawMeta), "secret/test")
}

func TestNonExistentVersionReturnsError(t *testing.T) {
	backend, cleanup := testBackend(t)
	defer cleanup()

	err := backend.WriteSecret("test/ver", map[string]interface{}{"k": "v"}, WriteOptions{UserID: "test"})
	require.NoError(t, err)

	_, err = backend.ReadSecret("test/ver", ReadOptions{Version: 99})
	assert.Error(t, err)
	assert.True(t, vaulterrors.IsVersionNotFound(err))
}
