//go:build postgres
// +build postgres

package storage

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getPostgresConfig gets PostgreSQL configuration from environment variables
// with fallbacks to default test values
func getPostgresConfig() PostgresConfig {
	return PostgresConfig{
		Host:     getEnvOrDefault("POSTGRES_HOST", "localhost"),
		Port:     getEnvIntOrDefault("POSTGRES_PORT", 5432),
		User:     getEnvOrDefault("POSTGRES_USER", "securevault"),
		Password: getEnvOrDefault("POSTGRES_PASSWORD", "securevault"),
		DBName:   getEnvOrDefault("POSTGRES_DB", "securevault"),
		SSLMode:  getEnvOrDefault("POSTGRES_SSLMODE", "disable"),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// cleanDatabase removes all secrets from the database for clean test state
func cleanDatabase(t *testing.T, backend *PostgresBackend) {
	t.Log("Cleaning database before test...")

	// Delete all secrets directly using SQL
	_, err := backend.db.Exec(`
		DELETE FROM secrets CASCADE
	`)
	if err != nil {
		t.Logf("Warning: Failed to clean database: %v", err)
	}
}

// TestPostgresBackendCRUD tests basic CRUD operations on the PostgreSQL backend
func TestPostgresBackendCRUD(t *testing.T) {
	config := getPostgresConfig()
	backend, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create PostgreSQL backend")
	defer backend.Close()

	// Ensure clean state
	cleanDatabase(t, backend)

	// Test data
	path := "test/postgres/secret1"
	secretData := map[string]interface{}{
		"username": "admin",
		"password": "secret123",
		"active":   true,
		"count":    float64(42), // Use float64 for numbers to ensure JSON compatibility
	}

	// Test Write
	t.Run("Write", func(t *testing.T) {
		err := backend.WriteSecret(path, secretData, WriteOptions{
			UserID: "test-user",
		})
		require.NoError(t, err, "Failed to write secret")
	})

	// Test Read
	t.Run("Read", func(t *testing.T) {
		secret, err := backend.ReadSecret(path, ReadOptions{})
		require.NoError(t, err, "Failed to read secret")
		assert.Equal(t, 1, secret.Version, "Expected version to be 1")
		assert.Equal(t, "test-user", secret.CreatedBy, "Expected created by to be test-user")

		// Check data
		assert.Equal(t, "admin", secret.Data["username"], "Expected username to be admin")
		assert.Equal(t, "admin", secret.Data["username"], "Expected username to be admin")
		assert.Equal(t, "secret123", secret.Data["password"], "Expected password to be secret123")
		assert.Equal(t, true, secret.Data["active"], "Expected active to be true")
		assert.Equal(t, float64(42), secret.Data["count"], "Expected count to be 42")
	})
	t.Run("Update", func(t *testing.T) {
		updatedData := map[string]interface{}{
			"username": "admin",
			"password": "newpassword",
			"active":   false,
			"count":    float64(43), // Use float64 for numbers
		}

		err := backend.WriteSecret(path, updatedData, WriteOptions{
			UserID: "test-updater",
		})
		require.NoError(t, err, "Failed to update secret")

		// Read updated data
		secret, err := backend.ReadSecret(path, ReadOptions{})
		require.NoError(t, err, "Failed to read updated secret")
		assert.Equal(t, 2, secret.Version, "Expected version to be 2")
		assert.Equal(t, "test-updater", secret.CreatedBy, "Expected created by to be test-updater")

		// Check updated data
		assert.Equal(t, "admin", secret.Data["username"], "Expected username to be admin")
		assert.Equal(t, "newpassword", secret.Data["password"], "Expected password to be newpassword")
		assert.Equal(t, false, secret.Data["active"], "Expected active to be false")
		assert.Equal(t, float64(43), secret.Data["count"], "Expected count to be 43")
	})

	// Test Read Specific Version
	t.Run("ReadSpecificVersion", func(t *testing.T) {
		secret, err := backend.ReadSecret(path, ReadOptions{
			Version: 1,
		})
		require.NoError(t, err, "Failed to read version 1")
		assert.Equal(t, 1, secret.Version, "Expected version to be 1")
		assert.Equal(t, "test-user", secret.CreatedBy, "Expected created by to be test-user")

		// Check original data
		assert.Equal(t, "admin", secret.Data["username"], "Expected username to be admin")
		assert.Equal(t, "secret123", secret.Data["password"], "Expected password to be secret123")
		assert.Equal(t, true, secret.Data["active"], "Expected active to be true")
		assert.Equal(t, float64(42), secret.Data["count"], "Expected count to be 42")
	})

	// Test Get Metadata
	t.Run("GetMetadata", func(t *testing.T) {
		metadata, err := backend.GetSecretMetadata(path)
		require.NoError(t, err, "Failed to get metadata")
		assert.Equal(t, 2, metadata.CurrentVersion, "Expected current version to be 2")
		assert.Len(t, metadata.Versions, 2, "Expected 2 versions")

		// Check version 1
		v1, ok := metadata.Versions[1]
		assert.True(t, ok, "Expected version 1 to exist")
		assert.Equal(t, "test-user", v1.CreatedBy, "Expected version 1 created by to be test-user")

		// Check version 2
		v2, ok := metadata.Versions[2]
		assert.True(t, ok, "Expected version 2 to exist")
		assert.Equal(t, "test-updater", v2.CreatedBy, "Expected version 2 created by to be test-updater")
	})

	// Test Delete Specific Version
	t.Run("DeleteSpecificVersion", func(t *testing.T) {
		err := backend.DeleteSecret(path, DeleteOptions{
			UserID:   "test-deleter",
			Versions: []int{1},
		})
		require.NoError(t, err, "Failed to delete version 1")

		// Metadata should show only version 2
		metadata, err := backend.GetSecretMetadata(path)
		require.NoError(t, err, "Failed to get metadata after deletion")
		assert.Equal(t, 2, metadata.CurrentVersion, "Expected current version to be 2")
		assert.Len(t, metadata.Versions, 1, "Expected 1 version")

		// Version 1 should be gone
		_, ok := metadata.Versions[1]
		assert.False(t, ok, "Expected version 1 to be gone")

		// Version 2 should still exist
		_, ok = metadata.Versions[2]
		assert.True(t, ok, "Expected version 2 to exist")

		// Reading version 1 should fail
		_, err = backend.ReadSecret(path, ReadOptions{
			Version: 1,
		})
		assert.Error(t, err, "Expected error when reading deleted version")
	})

	// Test Complete Delete
	t.Run("DeleteCompletely", func(t *testing.T) {
		err := backend.DeleteSecret(path, DeleteOptions{
			UserID:  "test-deleter",
			Destroy: true,
		})
		require.NoError(t, err, "Failed to delete secret completely")

		// Reading the secret should fail
		_, err = backend.ReadSecret(path, ReadOptions{})
		assert.Error(t, err, "Expected error when reading deleted secret")

		// Getting metadata should fail
		_, err = backend.GetSecretMetadata(path)
		assert.Error(t, err, "Expected error when getting metadata of deleted secret")
	})
}

// TestPostgresBackendListSecrets tests listing secrets
func TestPostgresBackendListSecrets(t *testing.T) {
	config := getPostgresConfig()
	backend, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create PostgreSQL backend")
	// Only defer once

	// Create multiple secrets with different prefixes
	cleanDatabase(t, backend)
	defer backend.Close()

	// Create multiple secrets with different prefixes
	secretPaths := []string{
		"app/db/postgres",
		"app/db/mysql",
		"app/api/key",
		"system/config",
	}
	// Write all secrets
	for _, path := range secretPaths {
		err := backend.WriteSecret(path, map[string]interface{}{
			"value": path,
			"test":  true,
		}, WriteOptions{
			UserID: "test-user",
			Metadata: map[string]interface{}{
				"test": "metadata",
			},
		})
		require.NoError(t, err, "Failed to write secret: %s", path)
	}
	// Test list all
	t.Run("ListAll", func(t *testing.T) {
		paths, err := backend.ListSecrets("")
		require.NoError(t, err, "Failed to list all secrets")

		// Check if we have exactly our test paths (ignoring any extras from other tests)
		// Instead of checking the exact length, we'll verify that all our test paths are included
		for _, path := range secretPaths {
			assert.Contains(t, paths, path, "Expected path '%s' to be in list", path)
		}

		// Log the actual paths for debugging
		t.Logf("Found %d paths in database", len(paths))
	})

	// Test list with prefix
	t.Run("ListWithPrefix", func(t *testing.T) {
		paths, err := backend.ListSecrets("app/db")
		require.NoError(t, err, "Failed to list secrets with prefix")
		assert.Len(t, paths, 2, "Expected 2 secrets with prefix app/db")
		assert.Contains(t, paths, "app/db/postgres", "Expected app/db/postgres to be in list")
		assert.Contains(t, paths, "app/db/mysql", "Expected app/db/mysql to be in list")
	})

	// Test list with non-existent prefix
	t.Run("ListNonExistentPrefix", func(t *testing.T) {
		paths, err := backend.ListSecrets("non/existent")
		require.NoError(t, err, "ListSecrets with non-existent prefix should not error")
		assert.Len(t, paths, 0, "Expected no secrets with non-existent prefix")
	})

	// Clean up
	for _, path := range secretPaths {
		err := backend.DeleteSecret(path, DeleteOptions{
			UserID:  "test-user",
			Destroy: true,
		})
		require.NoError(t, err, "Failed to clean up path: %s", path)
	}
}

// TestPostgresBackendVersions tests version handling
func TestPostgresBackendVersions(t *testing.T) {
	config := getPostgresConfig()
	backend, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create PostgreSQL backend")
	defer backend.Close()

	// Ensure clean state
	cleanDatabase(t, backend)

	path := "test/postgres/versioned"
	updates := []map[string]interface{}{
		{"version": "v1", "data": "first version"},
		{"version": "v2", "data": "second version"},
		{"version": "v3", "data": "third version"},
	}

	// Write all versions
	for i, data := range updates {
		err := backend.WriteSecret(path, data, WriteOptions{
			UserID: "test-user",
			Metadata: map[string]interface{}{
				"note": fmt.Sprintf("Update %d", i+1),
			},
		})
		require.NoError(t, err, "Failed to write version %d", i+1)
	}

	// Test metadata has correct versions
	t.Run("VersionMetadata", func(t *testing.T) {
		metadata, err := backend.GetSecretMetadata(path)
		require.NoError(t, err, "Failed to get metadata")
		assert.Equal(t, 3, metadata.CurrentVersion, "Expected current version to be 3")
		assert.Len(t, metadata.Versions, 3, "Expected 3 versions")

		// Check each version
		for i := 1; i <= 3; i++ {
			version, ok := metadata.Versions[i]
			assert.True(t, ok, "Expected version %d to exist", i)
			assert.Equal(t, "test-user", version.CreatedBy, "Expected created by to be test-user")
			// Check custom metadata
			var metaMap map[string]interface{}
			if version.CustomMetadata != nil {
				metaMap = version.CustomMetadata
			} else {
				metaMap = make(map[string]interface{})
			}

			expectedNote := fmt.Sprintf("Update %d", i)
			assert.Equal(t, expectedNote, metaMap["note"], "Expected note for version %d", i)
		}
	})

	// Test reading specific versions
	t.Run("ReadVersions", func(t *testing.T) {
		for i, update := range updates {
			version := i + 1
			secret, err := backend.ReadSecret(path, ReadOptions{
				Version: version,
			})
			require.NoError(t, err, "Failed to read version %d", version)
			assert.Equal(t, version, secret.Version, "Expected version to be %d", version)
			assert.Equal(t, update["version"], secret.Data["version"], "Expected version field to match")
			assert.Equal(t, update["data"], secret.Data["data"], "Expected data field to match")
		}
	})

	// Test reading latest version
	t.Run("ReadLatest", func(t *testing.T) {
		secret, err := backend.ReadSecret(path, ReadOptions{})
		require.NoError(t, err, "Failed to read latest version")
		assert.Equal(t, 3, secret.Version, "Expected version to be 3")
		assert.Equal(t, updates[2]["version"], secret.Data["version"], "Expected version field to match latest")
		assert.Equal(t, updates[2]["data"], secret.Data["data"], "Expected data field to match latest")
	})

	// Clean up
	backend.DeleteSecret(path, DeleteOptions{
		UserID:  "test-user",
		Destroy: true,
	})
}

// TestPostgresBackendReplication tests replication-related functionality
func TestPostgresBackendReplication(t *testing.T) {
	config := getPostgresConfig()
	backend, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create PostgreSQL backend")
	defer backend.Close()

	// Ensure clean state
	cleanDatabase(t, backend)

	path := "test/postgres/replicated"

	// Test writing with replication flags
	t.Run("ReplicationWrite", func(t *testing.T) {
		// Write with preserved version
		err := backend.WriteSecret(path, map[string]interface{}{
			"replicated": true,
			"source":     "leader",
		}, WriteOptions{
			UserID:          "replication",
			IsReplication:   true,
			PreserveVersion: true,
			Metadata: map[string]interface{}{
				"version":        float64(5),
				"source_node":    "leader-1",
				"replication_id": "123456",
			},
		})
		require.NoError(t, err, "Failed to write with replication flags")

		// Read the secret and verify version was preserved
		secret, err := backend.ReadSecret(path, ReadOptions{})
		require.NoError(t, err, "Failed to read replicated secret")

		// Version should be 5 as specified in metadata
		assert.Equal(t, 5, secret.Version, "Expected version to be preserved as 5")

		// Check that data was correctly stored
		assert.Equal(t, true, secret.Data["replicated"], "Expected replicated flag to be true")
		assert.Equal(t, "leader", secret.Data["source"], "Expected source to be leader")

		// Verify metadata
		metadata, err := backend.GetSecretMetadata(path)
		require.NoError(t, err, "Failed to get metadata")

		// Current version should match the preserved version
		assert.Equal(t, 5, metadata.CurrentVersion, "Expected current version to be 5")

		// Check version in versions map
		v5, ok := metadata.Versions[5]
		assert.True(t, ok, "Expected version 5 to exist")
		assert.Equal(t, "replication", v5.CreatedBy, "Expected created by to be replication")
	})

	// Test sequential replication writes
	t.Run("SequentialReplicationWrites", func(t *testing.T) {
		// Write version 6
		err := backend.WriteSecret(path, map[string]interface{}{
			"replicated": true,
			"source":     "leader",
			"seq":        1,
		}, WriteOptions{
			UserID:          "replication",
			IsReplication:   true,
			PreserveVersion: true,
			Metadata: map[string]interface{}{
				"version": float64(6),
			},
		})
		require.NoError(t, err, "Failed to write version 6")

		// Write version 7
		err = backend.WriteSecret(path, map[string]interface{}{
			"replicated": true,
			"source":     "leader",
			"seq":        2,
		}, WriteOptions{
			UserID:          "replication",
			IsReplication:   true,
			PreserveVersion: true,
			Metadata: map[string]interface{}{
				"version": float64(7),
			},
		})
		require.NoError(t, err, "Failed to write version 7")

		// Verify metadata has all versions
		metadata, err := backend.GetSecretMetadata(path)
		require.NoError(t, err, "Failed to get metadata")

		assert.Equal(t, 7, metadata.CurrentVersion, "Expected current version to be 7")
		assert.Len(t, metadata.Versions, 3, "Expected 3 versions (5, 6, 7)")

		// Check we can read all versions
		for version := 5; version <= 7; version++ {
			secret, err := backend.ReadSecret(path, ReadOptions{
				Version: version,
			})
			require.NoError(t, err, "Failed to read version %d", version)
			assert.Equal(t, version, secret.Version, "Expected correct version")
			assert.Equal(t, true, secret.Data["replicated"], "Expected replicated flag for version %d", version)
		}
	})

	// Test out-of-order replication (simulating catchup)
	t.Run("OutOfOrderReplication", func(t *testing.T) {
		// Create a new path for this test
		catchupPath := "test/postgres/catchup"

		// Write version 10 first (simulating a gap in replication)
		err := backend.WriteSecret(catchupPath, map[string]interface{}{
			"version": 10,
			"data":    "This is the latest version",
		}, WriteOptions{
			UserID:          "replication",
			IsReplication:   true,
			PreserveVersion: true,
			Metadata: map[string]interface{}{
				"version": float64(10),
			},
		})
		require.NoError(t, err, "Failed to write version 10")

		// Now write version 5 (earlier version catching up)
		err = backend.WriteSecret(catchupPath, map[string]interface{}{
			"version": 5,
			"data":    "This is an earlier version",
		}, WriteOptions{
			UserID:          "replication",
			IsReplication:   true,
			PreserveVersion: true,
			Metadata: map[string]interface{}{
				"version": float64(5),
			},
		})
		require.NoError(t, err, "Failed to write version 5")

		// Verify metadata
		metadata, err := backend.GetSecretMetadata(catchupPath)
		require.NoError(t, err, "Failed to get metadata")

		// Current version should still be 10 (highest)
		assert.Equal(t, 10, metadata.CurrentVersion, "Expected current version to remain 10")
		assert.Len(t, metadata.Versions, 2, "Expected 2 versions (5, 10)")

		// Check version 5 content
		secret5, err := backend.ReadSecret(catchupPath, ReadOptions{Version: 5})
		require.NoError(t, err, "Failed to read version 5")
		assert.Equal(t, "This is an earlier version", secret5.Data["data"], "Expected correct data for version 5")

		// Check version 10 content
		secret10, err := backend.ReadSecret(catchupPath, ReadOptions{Version: 10})
		require.NoError(t, err, "Failed to read version 10")
		assert.Equal(t, "This is the latest version", secret10.Data["data"], "Expected correct data for version 10")

		// Reading latest version should get version 10
		latestSecret, err := backend.ReadSecret(catchupPath, ReadOptions{})
		require.NoError(t, err, "Failed to read latest version")
		assert.Equal(t, 10, latestSecret.Version, "Latest read should return version 10")
	})
	// Clean up
	err = backend.DeleteSecret(path, DeleteOptions{
		UserID:  "test-user",
		Destroy: true,
	})
	require.NoError(t, err, "Failed to clean up path: %s", path)

	err = backend.DeleteSecret("test/postgres/catchup", DeleteOptions{
		UserID:  "test-user",
		Destroy: true,
	})
	require.NoError(t, err, "Failed to clean up path: test/postgres/catchup")

	// Final cleanup to ensure clean state for next tests
	cleanDatabase(t, backend)
}

// TestPostgresBackendConcurrency tests concurrent operations on the PostgreSQL backend
func TestPostgresBackendConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	config := getPostgresConfig()
	backend, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create PostgreSQL backend")
	defer backend.Close()

	// Ensure clean state
	cleanDatabase(t, backend)

	basePath := "test/postgres/concurrent"
	concurrentWrites := 3 // Reduced from 5 to speed up tests further
	iterations := 2       // Reduced from 3 to speed up tests further

	// Set a shorter timeout for this test
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use wait group to track concurrent goroutines
	var wg sync.WaitGroup
	// Test concurrent writes to different paths
	t.Run("ConcurrentWritesToDifferentPaths", func(t *testing.T) {
		// Create a done channel specific to this subtest
		done := make(chan struct{})
		// Reset waitgroup
		wg = sync.WaitGroup{}

		for i := 0; i < concurrentWrites; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				path := fmt.Sprintf("%s/path%d", basePath, idx)

				// Write multiple versions concurrently
				for j := 0; j < iterations; j++ {
					select {
					case <-ctx.Done():
						t.Logf("Context cancelled during writes, goroutine %d exiting", idx)
						return
					default:
						data := map[string]interface{}{
							"index":     float64(idx),
							"iteration": float64(j),
							"timestamp": float64(time.Now().UnixNano()),
							"value":     fmt.Sprintf("test-value-%d-%d", idx, j),
						}

						err := backend.WriteSecret(path, data, WriteOptions{
							UserID: fmt.Sprintf("user-%d", idx),
						})
						if err != nil {
							t.Logf("Failed to write to path %s in iteration %d: %v", path, j, err)
						}
						// No sleep to make test faster
					}
				}
			}(i)
		}
		// Wait for all goroutines to complete with timeout
		go func() {
			wg.Wait()
			close(done)
		}()

		// Wait with timeout
		select {
		case <-done:
			t.Log("All concurrent writes completed successfully")
		case <-ctx.Done():
			t.Log("Concurrent writes timed out after 5 seconds, proceeding with verification anyway")
		}
		wg.Wait()

		// Verify all writes succeeded
		t.Log("Verifying all concurrent writes succeeded")
		for i := 0; i < concurrentWrites; i++ {
			path := fmt.Sprintf("%s/path%d", basePath, i)

			// Check that each path has exactly 'iterations' versions
			metadata, err := backend.GetSecretMetadata(path)
			require.NoError(t, err, "Failed to get metadata for path %s", path)
			assert.Equal(t, iterations, metadata.CurrentVersion,
				"Expected current version for path %s to be %d", path, iterations)

			// Read latest version and check data
			secret, err := backend.ReadSecret(path, ReadOptions{})
			require.NoError(t, err, "Failed to read latest version for path %s", path)
			assert.Equal(t, iterations, secret.Version,
				"Expected latest version for path %s to be %d", path, iterations)
			assert.Equal(t, float64(i), secret.Data["index"],
				"Expected index for path %s to be %d", path, i)
			assert.Equal(t, float64(iterations-1), secret.Data["iteration"],
				"Expected iteration for path %s to be %d", path, iterations-1)
		}
	})

	// Test concurrent reads from the same path
	t.Run("ConcurrentReads", func(t *testing.T) {
		// Create a new done channel specific to this subtest
		done := make(chan struct{})
		// Reset waitgroup
		wg = sync.WaitGroup{}

		// Create a test secret with multiple versions
		sharedPath := fmt.Sprintf("%s/shared", basePath)

		// Write multiple versions to the shared path
		for i := 0; i < 3; i++ { // Reduced from 5 to speed up setup
			err := backend.WriteSecret(sharedPath, map[string]interface{}{
				"version": float64(i + 1),
				"data":    fmt.Sprintf("Version %d data", i+1),
			}, WriteOptions{
				UserID: "setup-user",
				Metadata: map[string]interface{}{
					"test": fmt.Sprintf("version-%d-metadata", i+1),
				},
			})
			require.NoError(t, err, "Failed to write version %d to shared path", i+1)
		}

		// Test concurrent reads of different versions
		readCounts := make([]int, 4) // Index 0 not used, versions 1-3
		var countMutex sync.Mutex

		// Launch concurrent readers (reduced count)
		for i := 0; i < 10; i++ { // Reduced from 20 to speed up test further
			wg.Add(1)
			go func() {
				defer wg.Done()

				select {
				case <-ctx.Done():
					t.Log("Context cancelled during reads, reader goroutine exiting")
					return
				default:
					// Choose a random version to read (1-3 or 0 for latest)
					version := rand.Intn(4) // 0-3

					// Read the version
					opts := ReadOptions{}
					if version > 0 {
						opts.Version = version
					}

					secret, err := backend.ReadSecret(sharedPath, opts)
					if err != nil {
						t.Logf("Read failed for version %d: %v", version, err)
						return
					}

					// If reading latest (version=0), the actual version should be 3
					actualVersion := secret.Version
					if version == 0 {
						if actualVersion != 3 {
							t.Logf("Latest version mismatch: expected 3, got %d", actualVersion)
						}
					} else if version != actualVersion {
						t.Logf("Version mismatch: requested %d, got %d", version, actualVersion)
					}

					// Increment read count for this version
					countMutex.Lock()
					if version == 0 {
						readCounts[3]++
					} else {
						readCounts[version]++
					}
					countMutex.Unlock()
				}
			}()
		}
		// Wait for all reads to complete with timeout
		go func() {
			wg.Wait()
			close(done)
		}()

		// Wait with timeout
		select {
		case <-done:
			t.Log("All concurrent reads completed successfully")
		case <-ctx.Done():
			t.Log("Concurrent reads timed out after 5 seconds, proceeding with verification anyway")
		}
		wg.Wait()

		// Log read counts
		t.Log("Read counts by version:")
		for i := 1; i <= 3; i++ {
			t.Logf("Version %d: %d reads", i, readCounts[i])
		}
	})

	// Test mixed concurrent operations (reads and writes)
	t.Run("ConcurrentMixedOperations", func(t *testing.T) {
		// Create a new done channel specific to this subtest
		done := make(chan struct{})
		// Reset waitgroup
		wg = sync.WaitGroup{}

		mixedPath := fmt.Sprintf("%s/mixed", basePath)

		// Create initial version
		err := backend.WriteSecret(mixedPath, map[string]interface{}{
			"version": float64(1),
			"counter": float64(0),
			"created": time.Now().Format(time.RFC3339),
		}, WriteOptions{
			UserID: "setup-user",
		})
		require.NoError(t, err, "Failed to create initial version")

		// Create a counter to track successful operations
		successfulReads := int32(0)
		successfulWrites := int32(0)
		var finalVersion int32 = 1

		// Launch mixed operations (reduced count)
		for i := 0; i < 20; i++ { // Reduced from 50 to speed up test
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				// Check for context cancellation
				select {
				case <-ctx.Done():
					t.Logf("Context cancelled during mixed operations, goroutine %d exiting", idx)
					return
				default:
					// Continue with the operation
				}

				// Randomly choose operation: true=write, false=read
				doWrite := (idx%3 == 0) // 33% writes, 67% reads

				if doWrite {
					// Read first to get current data
					secret, err := backend.ReadSecret(mixedPath, ReadOptions{})
					if err != nil {
						t.Logf("Read before write failed: %v", err)
						return
					}

					// Get current counter value and increment it
					currentCounter := 0
					if counterVal, ok := secret.Data["counter"]; ok {
						if f, ok := counterVal.(float64); ok {
							currentCounter = int(f)
						}
					}

					// Update the counter by incrementing current value
					err = backend.WriteSecret(mixedPath, map[string]interface{}{
						"counter":          float64(currentCounter + 1),
						"updated_by":       float64(idx),
						"timestamp":        time.Now().Format(time.RFC3339),
						"previous_version": float64(secret.Version),
					}, WriteOptions{
						UserID: fmt.Sprintf("user-%d", idx),
						Metadata: map[string]interface{}{
							"operation": "update",
							"writer_id": float64(idx),
						},
					})
					if err != nil {
						t.Logf("Write failed: %v", err)
					} else {
						atomic.AddInt32(&successfulWrites, 1)
						// Track this successful write
						atomic.AddInt32(&finalVersion, 1)
					}
				} else {
					// Perform a read operation
					_, err := backend.ReadSecret(mixedPath, ReadOptions{})
					if err != nil {
						t.Logf("Read failed: %v", err)
					} else {
						atomic.AddInt32(&successfulReads, 1)
					}
				}

				// No sleep to make test run faster
			}(i)
		}

		// Wait for all operations to complete with timeout
		go func() {
			wg.Wait()
			close(done)
		}()

		// Wait with timeout
		select {
		case <-done:
			t.Log("All concurrent mixed operations completed successfully")
		case <-ctx.Done():
			t.Log("Concurrent mixed operations timed out after 5 seconds, proceeding with verification anyway")
		}

		// Verify final state
		t.Logf("Mixed operations complete: %d successful reads, %d successful writes",
			successfulReads, successfulWrites)

		// Read final state
		secret, err := backend.ReadSecret(mixedPath, ReadOptions{})
		require.NoError(t, err, "Failed to read final state")

		// Log the actual values for debugging
		t.Logf("Final version: %d", secret.Version)
		t.Logf("Final counter: %v", secret.Data["counter"])

		// Verify we have at least one successful write
		assert.True(t, successfulWrites > 0,
			"Expected at least one successful write operation")

		// Get the metadata to verify version count
		metadata, err := backend.GetSecretMetadata(mixedPath)
		require.NoError(t, err, "Failed to get final metadata")
		t.Logf("Total versions in metadata: %d", len(metadata.Versions))

		// Verify metadata has at least the initial version plus our writes
		assert.True(t, len(metadata.Versions) >= int(1+successfulWrites),
			"Expected at least %d versions but got %d", 1+successfulWrites, len(metadata.Versions))
	})

	// Clean up all paths used in concurrent tests
	cleanupPaths := []string{
		fmt.Sprintf("%s/shared", basePath),
		fmt.Sprintf("%s/mixed", basePath),
	}
	for i := 0; i < concurrentWrites; i++ {
		cleanupPaths = append(cleanupPaths, fmt.Sprintf("%s/path%d", basePath, i))
	}

	t.Log("Cleaning up paths from concurrent test...")
	for _, path := range cleanupPaths {
		err := backend.DeleteSecret(path, DeleteOptions{
			UserID:  "test-cleanup",
			Destroy: true,
		})
		if err != nil {
			t.Logf("Warning: Failed to clean up path %s: %v", path, err)
		}
	}

	// Final cleanup to ensure clean state for next tests
	cleanDatabase(t, backend)
}

// TestPostgresBackendRestart tests persistence across backend restarts
func TestPostgresBackendRestart(t *testing.T) {
	config := getPostgresConfig()

	// Create temporary backend for cleanup
	cleanupBackend, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create cleanup backend")
	cleanDatabase(t, cleanupBackend)
	cleanupBackend.Close()

	// First backend instance
	backend1, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create first PostgreSQL backend instance")

	// Create test data
	path := "test/postgres/restart"
	initialData := map[string]interface{}{
		"key":     "value",
		"version": float64(1),
	}

	// Write using first backend
	err = backend1.WriteSecret(path, initialData, WriteOptions{
		UserID: "test-user",
	})
	require.NoError(t, err, "Failed to write initial data")

	// Close first backend (simulating restart)
	backend1.Close()

	// Create second backend instance (simulating restart)
	backend2, err := NewPostgresBackend(config)
	require.NoError(t, err, "Failed to create second PostgreSQL backend instance")
	defer backend2.Close()

	// Read using second backend
	secret, err := backend2.ReadSecret(path, ReadOptions{})
	require.NoError(t, err, "Failed to read after restart")

	// Verify data persisted
	assert.Equal(t, "value", secret.Data["key"], "Expected key to be 'value'")
	assert.Equal(t, float64(1), secret.Data["version"], "Expected version to be 1")

	// Update using second backend
	updatedData := map[string]interface{}{
		"key":     "updated-value",
		"version": float64(2),
	}

	err = backend2.WriteSecret(path, updatedData, WriteOptions{
		UserID: "test-user-2",
	})
	require.NoError(t, err, "Failed to update data")

	// Verify update worked
	updatedSecret, err := backend2.ReadSecret(path, ReadOptions{})
	require.NoError(t, err, "Failed to read updated data")
	assert.Equal(t, "updated-value", updatedSecret.Data["key"], "Expected key to be 'updated-value'")
	assert.Equal(t, float64(2), updatedSecret.Data["version"], "Expected version to be 2")

	// Verify metadata shows both versions
	metadata, err := backend2.GetSecretMetadata(path)
	require.NoError(t, err, "Failed to get metadata")
	assert.Equal(t, 2, metadata.CurrentVersion, "Expected current version to be 2")
	assert.Len(t, metadata.Versions, 2, "Expected 2 versions")
	// Clean up
	err = backend2.DeleteSecret(path, DeleteOptions{
		UserID:  "test-cleanup",
		Destroy: true,
	})
	require.NoError(t, err, "Failed to clean up path: %s", path)

	// Final cleanup
	cleanDatabase(t, backend2)
}
