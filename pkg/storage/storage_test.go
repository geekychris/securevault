package storage

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testDir string                 // Temporary directory for tests
	backend Backend                // Backend used across tests
	testMu  sync.Mutex             // Mutex to synchronize test execution
)

// TestMain sets up and tears down test environment
func TestMain(m *testing.M) {
	// Create a temporary directory for tests
	var err error
	testDir, err = os.MkdirTemp("", "securevault-storage-test")
	if err != nil {
		fmt.Printf("Failed to create temp directory: %v\n", err)
		os.Exit(1)
	}

	// Create a backend for tests
	backend, err = NewFileBackend(testDir)
	if err != nil {
		fmt.Printf("Failed to create test backend: %v\n", err)
		os.RemoveAll(testDir)
		os.Exit(1)
	}

	// Run tests
	exitCode := m.Run()

	// Clean up
	os.RemoveAll(testDir)
	os.Exit(exitCode)
}

// TestBasicOperations tests basic CRUD operations
func TestBasicOperations(t *testing.T) {
	testMu.Lock()
	defer testMu.Unlock()

	// Define test data
	secretPath := "test/mysecret"
	secretData := map[string]interface{}{
		"username": "testuser",
		"password": "testpass",
	}
	options := WriteOptions{
		UserID: "test-user",
		Metadata: map[string]interface{}{
			"description": "Test secret",
		},
	}

	// Write a secret
	err := backend.WriteSecret(secretPath, secretData, options)
	require.NoError(t, err, "WriteSecret failed")

	// Read the secret
	readOptions := ReadOptions{Version: 0} // Get latest version
	secret, err := backend.ReadSecret(secretPath, readOptions)
	require.NoError(t, err, "ReadSecret failed")
	assert.Equal(t, secretData["username"], secret.Data["username"], "Username doesn't match")
	assert.Equal(t, secretData["password"], secret.Data["password"], "Password doesn't match")
	assert.Equal(t, options.UserID, secret.CreatedBy, "CreatedBy doesn't match")
	assert.Equal(t, options.Metadata["description"], secret.Metadata["description"], "Metadata doesn't match")
	assert.Equal(t, 1, secret.Version, "Version should be 1")

	// List secrets
	secrets, err := backend.ListSecrets("test")
	require.NoError(t, err, "ListSecrets failed")
	assert.Contains(t, secrets, "test/mysecret", "Secret should be listed")

	// Delete the secret
	deleteOptions := DeleteOptions{
		UserID:  "test-user",
		Destroy: true,
	}
	err = backend.DeleteSecret(secretPath, deleteOptions)
	require.NoError(t, err, "DeleteSecret failed")

	// Verify deletion
	_, err = backend.ReadSecret(secretPath, readOptions)
	assert.Error(t, err, "Secret should be deleted")
	assert.Contains(t, err.Error(), "not found", "Error should indicate secret not found")
}

// TestVersioning tests versioning functionality
func TestVersioning(t *testing.T) {
	testMu.Lock()
	defer testMu.Unlock()

	// Define test data
	secretPath := "test/versioned"
	versions := []map[string]interface{}{
		{"data": "version1", "value": 100},
		{"data": "version2", "value": 200},
		{"data": "version3", "value": 300},
	}

	// Write multiple versions
	for i, data := range versions {
		err := backend.WriteSecret(secretPath, data, WriteOptions{
			UserID: fmt.Sprintf("user-%d", i),
			Metadata: map[string]interface{}{
				"version_info": fmt.Sprintf("Version %d metadata", i+1),
			},
		})
		require.NoError(t, err, "WriteSecret failed for version %d", i+1)
	}

	// Get metadata
	metadata, err := backend.GetSecretMetadata(secretPath)
	require.NoError(t, err, "GetSecretMetadata failed")
	assert.Equal(t, 3, metadata.CurrentVersion, "CurrentVersion should be 3")
	assert.Len(t, metadata.Versions, 3, "Should have 3 versions")

	// Read each version and verify content
	for i, data := range versions {
		version := i + 1
		secret, err := backend.ReadSecret(secretPath, ReadOptions{Version: version})
		require.NoError(t, err, "ReadSecret failed for version %d", version)
		assert.Equal(t, data["data"], secret.Data["data"], "Data doesn't match for version %d", version)
		assert.Equal(t, float64(data["value"].(int)), secret.Data["value"], "Value doesn't match for version %d", version)
		assert.Equal(t, version, secret.Version, "Version number doesn't match")
	}

	// Delete a specific version (middle one)
	err = backend.DeleteSecret(secretPath, DeleteOptions{
		UserID:   "test-user",
		Versions: []int{2},
	})
	require.NoError(t, err, "Failed to delete version 2")

	// Verify version 2 is deleted but others remain
	// Attempt to read the deleted version
	_, versionErr := backend.ReadSecret(secretPath, ReadOptions{Version: 2})
	assert.Error(t, versionErr, "Version 2 should be deleted")
	assert.Contains(t, versionErr.Error(), "destroyed", "Error should indicate version is destroyed")

	// Version 1 and 3 should still be available
	v1, err := backend.ReadSecret(secretPath, ReadOptions{Version: 1})
	require.NoError(t, err, "Version 1 should still exist")
	assert.Equal(t, versions[0]["data"], v1.Data["data"], "Version 1 data mismatch")

	v3, err := backend.ReadSecret(secretPath, ReadOptions{Version: 3})
	require.NoError(t, err, "Version 3 should still exist")
	assert.Equal(t, versions[2]["data"], v3.Data["data"], "Version 3 data mismatch")

	// Latest version should be 3
	latest, err := backend.ReadSecret(secretPath, ReadOptions{Version: 0})
	require.NoError(t, err, "Failed to read latest version")
	assert.Equal(t, 3, latest.Version, "Latest version should be 3")

	// Delete all versions
	err = backend.DeleteSecret(secretPath, DeleteOptions{
		UserID:  "test-user",
		Destroy: true,
	})
	require.NoError(t, err, "Failed to delete all versions")

	// Verify all versions are gone
	_, err = backend.ReadSecret(secretPath, ReadOptions{})
	assert.Error(t, err, "All versions should be deleted")
}

// TestConcurrentAccess tests concurrent access to the backend
func TestConcurrentAccess(t *testing.T) {
	testMu.Lock()
	defer testMu.Unlock()

	const (
		numGoroutines = 10
		numWrites     = 5
	)

	var wg sync.WaitGroup
	results := make(chan error, numGoroutines*numWrites)

	// Launch multiple goroutines to write secrets concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numWrites; j++ {
				path := fmt.Sprintf("concurrent/secret-%d-%d", id, j)
				data := map[string]interface{}{
					"id":    id,
					"value": j,
					"data":  fmt.Sprintf("data-%d-%d", id, j),
				}
				err := backend.WriteSecret(path, data, WriteOptions{
					UserID: fmt.Sprintf("user-%d", id),
				})
				if err != nil {
					results <- fmt.Errorf("write failed for %s: %w", path, err)
					return
				}

				// Immediately read back and verify (adding read concurrency)
				secret, err := backend.ReadSecret(path, ReadOptions{})
				if err != nil {
					results <- fmt.Errorf("read failed for %s: %w", path, err)
					return
				}

				// Compare as float64 since JSON unmarshaling converts numbers to float64
				if secret.Data["id"] != float64(id) || secret.Data["value"] != float64(j) {
					results <- fmt.Errorf("data mismatch for %s: expected id=%d, value=%d, got id=%v, value=%v",
						path, id, j, secret.Data["id"], secret.Data["value"])
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)

	// Check for errors
	var errors []error
	for err := range results {
		errors = append(errors, err)
	}

	assert.Empty(t, errors, "Concurrent operations produced errors: %v", errors)

	// List all secrets to verify they were created
	secrets, err := backend.ListSecrets("concurrent")
	require.NoError(t, err, "Failed to list secrets")
	assert.Len(t, secrets, numGoroutines*numWrites, "Unexpected number of secrets")
}

// TestEncryption tests encryption functionality
func TestEncryption(t *testing.T) {
	testMu.Lock()
	defer testMu.Unlock()

	secretPath := "test/encrypted"
	sensitiveData := map[string]interface{}{
		"api_key":    "very-secret-api-key",
		"password":   "super-secure-password",
		"credit_card": "4111-1111-1111-1111",
	}

	// Write secret
	err := backend.WriteSecret(secretPath, sensitiveData, WriteOptions{})
	require.NoError(t, err, "WriteSecret failed")

	// Get the actual file path
	fileBackend, ok := backend.(*FileBackend)
	require.True(t, ok, "Backend should be FileBackend")
	
	versionPath := fileBackend.getSecretVersionPath(secretPath, 1)
	
	// Read the raw encrypted data
	encryptedData, err := os.ReadFile(versionPath)
	require.NoError(t, err, "Failed to read encrypted file")
	
	// Ensure data is actually encrypted (shouldn't contain plaintext values)
	encryptedStr := string(encryptedData)
	for _, value := range sensitiveData {
		strValue, ok := value.(string)
		if ok {
			assert.NotContains(t, encryptedStr, strValue, 
				"Encrypted data should not contain plaintext value: %s", strValue)
		}
	}
	
	// Try to tamper with the encrypted data
	tamperedData := append(encryptedData, []byte("tampered")...)
	err = os.WriteFile(versionPath, tamperedData, 0600)
	require.NoError(t, err, "Failed to write tampered data")
	
	// Attempt to read the tampered data
	_, err = backend.ReadSecret(secretPath, ReadOptions{})
	assert.Error(t, err, "Reading tampered data should fail")
	assert.Contains(t, err.Error(), "failed to decrypt", "Error should indicate decryption failure")
}

// TestErrorHandling tests various error conditions
func TestErrorHandling(t *testing.T) {
	testMu.Lock()
	defer testMu.Unlock()

	// Test reading non-existent secret
	_, err := backend.ReadSecret("non/existent/path", ReadOptions{})
	assert.Error(t, err, "Reading non-existent secret should fail")
	assert.Contains(t, err.Error(), "not found", "Error should indicate secret not found")

	// Test reading non-existent version
	// First create a secret
	secretPath := "test/error-handling"
	err = backend.WriteSecret(secretPath, map[string]interface{}{"key": "value"}, WriteOptions{})
	require.NoError(t, err, "WriteSecret failed")

	// Try to read non-existent version
	_, err = backend.ReadSecret(secretPath, ReadOptions{Version: 999})
	assert.Error(t, err, "Reading non-existent version should fail")
	assert.Contains(t, err.Error(), "does not exist", "Error should indicate version doesn't exist")

	// Test deleting non-existent secret
	err = backend.DeleteSecret("non/existent/path", DeleteOptions{})
	assert.Error(t, err, "Deleting non-existent secret should fail")
	assert.Contains(t, err.Error(), "not found", "Error should indicate secret not found")
}

// TestMetadataManagement tests metadata operations
func TestMetadataManagement(t *testing.T) {
	testMu.Lock()
	defer testMu.Unlock()

	secretPath := "test/metadata"
	timestamp := time.Now().Truncate(time.Second) // Truncate to avoid microsecond differences
	
	// Create a secret with metadata
	err := backend.WriteSecret(secretPath, map[string]interface{}{"key": "value"}, WriteOptions{
		UserID: "metadata-test-user",
		Metadata: map[string]interface{}{
			"environment": "test",
			"owner":       "test-team",
			"priority":    "high",
		},
	})
	require.NoError(t, err, "WriteSecret failed")
	
	// Get and verify metadata
	metadata, err := backend.GetSecretMetadata(secretPath)
	require.NoError(t, err, "GetSecretMetadata failed")
	
	assert.Equal(t, 1, metadata.CurrentVersion, "CurrentVersion should be 1")
	assert.True(t, metadata.CreatedTime.After(timestamp) || metadata.CreatedTime.Equal(timestamp), 
		"CreatedTime should be >= timestamp")
	assert.True(t, metadata.LastModified.After(timestamp) || metadata.LastModified.Equal(timestamp), 
		"LastModified should be >= timestamp")
	
	// Check version metadata
	versionMetadata, exists := metadata.Versions[1]
	assert.True(t, exists, "Version 1 metadata should exist")
	assert.Equal(t, "metadata-test-user", versionMetadata.CreatedBy, "CreatedBy mismatch")
	
	customMeta := versionMetadata.CustomMetadata
	assert.Equal(t, "test", customMeta["environment"], "Environment metadata mismatch")
	assert.Equal(t, "test-team", customMeta["owner"], "Owner metadata mismatch")
	assert.Equal(t, "high", customMeta["priority"], "Priority metadata mismatch")
}

// TestFileBackendSpecifics tests functionality specific to FileBackend
func TestFileBackendSpecifics(t *testing.T) {
	testMu.Lock()
	defer testMu.Unlock()

	fileBackend, ok := backend.(*FileBackend)
	if !ok {
		t.Fatal("Backend is not a FileBackend")
	}
	
	// Test FileBackend specific functionality
	assert.NotEmpty(t, fileBackend.basePath, "FileBackend basePath should not be empty")
}
