package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Secret represents a stored secret with its metadata
type Secret struct {
	Data         map[string]interface{} `json:"data"`
	CreatedTime  time.Time              `json:"created_time"`
	Version      int                    `json:"version"`
	LastModified time.Time              `json:"last_modified"`
	CreatedBy    string                 `json:"created_by"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SecretMetadata represents metadata about a secret
type SecretMetadata struct {
	Versions       map[int]*VersionMetadata `json:"versions"`
	CurrentVersion int                      `json:"current_version"`
	CreatedTime    time.Time                `json:"created_time"`
	LastModified   time.Time                `json:"last_modified"`
}

// VersionMetadata represents metadata about a specific version of a secret
type VersionMetadata struct {
	CreatedTime  time.Time `json:"created_time"`
	CreatedBy    string    `json:"created_by"`
	DeletedTime  time.Time `json:"deleted_time,omitempty"`
	DeletedBy    string    `json:"deleted_by,omitempty"`
	IsDestroyed  bool      `json:"is_destroyed"`
	CustomMetadata map[string]interface{} `json:"custom_metadata,omitempty"`
}

// WriteOptions contains options for write operations
type WriteOptions struct {
	// UserID is the ID of the user performing the operation
	UserID string
	// Metadata is custom metadata to store with the secret
	Metadata map[string]interface{}
	// IsReplication indicates this write is from replication
	IsReplication bool
	// PreserveVersion indicates whether to preserve the version specified in metadata
	PreserveVersion bool
}

// ReadOptions contains options for read operations
type ReadOptions struct {
	// Version is the version of the secret to read
	// If 0, the latest version is read
	Version int
}

// DeleteOptions contains options for delete operations
type DeleteOptions struct {
	// UserID is the ID of the user performing the operation
	UserID string
	// Versions is a list of versions to delete
	// If empty, all versions are deleted
	Versions []int
	// Destroy indicates whether to permanently delete the secret
	Destroy bool
}

// Backend is the interface that all storage backends must implement
type Backend interface {
	// WriteSecret writes a secret to the backend
	WriteSecret(path string, data map[string]interface{}, options WriteOptions) error
	
	// ReadSecret reads a secret from the backend
	ReadSecret(path string, options ReadOptions) (*Secret, error)
	
	// DeleteSecret deletes a secret from the backend
	DeleteSecret(path string, options DeleteOptions) error
	
	// ListSecrets lists secrets at a specific path
	ListSecrets(path string) ([]string, error)
	
	// GetSecretMetadata gets metadata about a secret
	GetSecretMetadata(path string) (*SecretMetadata, error)
}

// FileBackend implements the Backend interface using the filesystem
type FileBackend struct {
	basePath string
	mutex    *sync.Map
	// encryptionKey is used to encrypt secrets
	encryptionKey []byte
}

// NewFileBackend creates a new file-based backend
func NewFileBackend(basePath string) (Backend, error) {
	// Ensure base path exists
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	// Generate or load encryption key
	keyPath := filepath.Join(basePath, ".key")
	encryptionKey, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to set up encryption key: %w", err)
	}

	return &FileBackend{
		basePath:      basePath,
		mutex:         &sync.Map{},
		encryptionKey: encryptionKey,
	}, nil
}

// loadOrGenerateKey loads an existing encryption key or generates a new one
func loadOrGenerateKey(keyPath string) ([]byte, error) {
	// Try to load existing key
	key, err := os.ReadFile(keyPath)
	if err == nil && len(key) == 32 {
		return key, nil
	}

	// Generate new key if no valid key exists
	key = make([]byte, 32) // AES-256 key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Save key to file with secure permissions
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to save encryption key: %w", err)
	}

	return key, nil
}

// encrypt encrypts data using AES-256-GCM
func (b *FileBackend) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-256-GCM
func (b *FileBackend) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:aesGCM.NonceSize()], ciphertext[aesGCM.NonceSize():]
	
	// Decrypt data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	
	return plaintext, nil
}

// getSecretPath returns the filesystem path for a secret
func (b *FileBackend) getSecretPath(path string) string {
	return filepath.Join(b.basePath, "secrets", path)
}

// getSecretVersionPath returns the filesystem path for a specific version of a secret
func (b *FileBackend) getSecretVersionPath(path string, version int) string {
	return filepath.Join(b.getSecretPath(path), fmt.Sprintf("v%d.data", version))
}

// getSecretMetadataPath returns the filesystem path for a secret's metadata
func (b *FileBackend) getSecretMetadataPath(path string) string {
	return filepath.Join(b.getSecretPath(path), "metadata.json")
}

// WriteSecret writes a secret to the backend
func (b *FileBackend) WriteSecret(path string, data map[string]interface{}, options WriteOptions) error {
	// Get mutex for this path
	pathMutex, _ := b.mutex.LoadOrStore(path, &sync.Mutex{})
	mutex := pathMutex.(*sync.Mutex)
	mutex.Lock()
	defer mutex.Unlock()

	// Ensure secret directory exists
	secretPath := b.getSecretPath(path)
	if err := os.MkdirAll(secretPath, 0700); err != nil {
		return fmt.Errorf("failed to create secret directory: %w", err)
	}

	// Get current metadata or create new
	metadata, err := b.getOrCreateMetadata(path)
	if err != nil {
		return err
	}

	// Determine new version number
	newVersion := metadata.CurrentVersion + 1

	// Create secret object
	now := time.Now()
	secret := Secret{
		Data:         data,
		CreatedTime:  now,
		Version:      newVersion,
		LastModified: now,
		CreatedBy:    options.UserID,
		Metadata:     options.Metadata,
	}

	// Serialize and encrypt secret
	secretData, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	encryptedData, err := b.encrypt(secretData)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Write to temporary file first for atomicity
	versionPath := b.getSecretVersionPath(path, newVersion)
	tempPath := versionPath + ".tmp"
	
	if err := os.WriteFile(tempPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write secret data: %w", err)
	}

	// Update metadata
	if metadata.Versions == nil {
		metadata.Versions = make(map[int]*VersionMetadata)
	}
	
	metadata.Versions[newVersion] = &VersionMetadata{
		CreatedTime:    now,
		CreatedBy:      options.UserID,
		CustomMetadata: options.Metadata,
	}
	
	metadata.CurrentVersion = newVersion
	metadata.LastModified = now
	
	if metadata.CreatedTime.IsZero() {
		metadata.CreatedTime = now
	}

	// Serialize and write metadata
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		os.Remove(tempPath) // Clean up temporary file
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metadataPath := b.getSecretMetadataPath(path)
	tempMetadataPath := metadataPath + ".tmp"
	
	if err := os.WriteFile(tempMetadataPath, metadataBytes, 0600); err != nil {
		os.Remove(tempPath) // Clean up temporary file
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Atomically rename files to their final names
	if err := os.Rename(tempPath, versionPath); err != nil {
		os.Remove(tempPath)
		os.Remove(tempMetadataPath)
		return fmt.Errorf("failed to save secret data: %w", err)
	}

	if err := os.Rename(tempMetadataPath, metadataPath); err != nil {
		// If metadata update fails, we're in an inconsistent state
		// Log error and continue, not much we can do at this point
		// In a real system, we'd want better error recovery
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	return nil
}

// ReadSecret reads a secret from the backend
func (b *FileBackend) ReadSecret(path string, options ReadOptions) (*Secret, error) {
	// Get mutex for this path or create a temporary one if it doesn't exist
	pathMutexObj, ok := b.mutex.Load(path)
	if !ok {
		// If no mutex exists yet, create one but don't store it
		// since we're only reading
		pathMutexObj = &sync.Mutex{}
	}
	mutex := pathMutexObj.(*sync.Mutex)
	mutex.Lock()
	defer mutex.Unlock()

	// Get metadata to find current version or check requested version
	metadata, err := b.GetSecretMetadata(path)
	if err != nil {
		return nil, err
	}

	version := options.Version
	if version == 0 {
		// Use latest version
		version = metadata.CurrentVersion
	}

	// Check if version exists
	versionMeta, exists := metadata.Versions[version]
	if !exists {
		return nil, fmt.Errorf("version %d does not exist", version)
	}

	// Check if version is destroyed
	if versionMeta.IsDestroyed {
		return nil, fmt.Errorf("version %d has been destroyed", version)
	}

	// Read and decrypt secret data
	versionPath := b.getSecretVersionPath(path, version)
	encryptedData, err := os.ReadFile(versionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret data: %w", err)
	}

	decryptedData, err := b.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	var secret Secret
	if err := json.Unmarshal(decryptedData, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return &secret, nil
}

// DeleteSecret deletes a secret from the backend
func (b *FileBackend) DeleteSecret(path string, options DeleteOptions) error {
	// Get mutex for this path
	pathMutexObj, ok := b.mutex.Load(path)
	if !ok {
		return fmt.Errorf("secret not found: %s", path)
	}
	mutex := pathMutexObj.(*sync.Mutex)
	mutex.Lock()
	defer mutex.Unlock()

	// Get metadata
	metadata, err := b.GetSecretMetadata(path)
	if err != nil {
		return err
	}

	// Determine which versions to delete
	versionsToDelete := options.Versions
	if len(versionsToDelete) == 0 && options.Destroy {
		// Delete all versions if none specified and destroy is true
		versionsToDelete = make([]int, 0, len(metadata.Versions))
		for version := range metadata.Versions {
			versionsToDelete = append(versionsToDelete, version)
		}
	}

	// Update metadata or delete files
	now := time.Now()
	secretPath := b.getSecretPath(path)

	if options.Destroy {
		// Permanently delete versions
		for _, version := range versionsToDelete {
			versionMeta, exists := metadata.Versions[version]
			if !exists {
				continue
			}

			// Mark as destroyed in metadata
			versionMeta.IsDestroyed = true
			versionMeta.DeletedTime = now
			versionMeta.DeletedBy = options.UserID
			// Delete the file
			versionPath := b.getSecretVersionPath(path, version)
			if err := os.Remove(versionPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete secret version %d: %w", version, err)
			}
		}

		// If all versions are destroyed, check if we should delete the entire secret
		allDestroyed := true
		for _, meta := range metadata.Versions {
			if !meta.IsDestroyed {
				allDestroyed = false
				break
			}
		}

		if allDestroyed {
			// Delete the entire secret directory
			if err := os.RemoveAll(secretPath); err != nil {
				return fmt.Errorf("failed to delete secret directory: %w", err)
			}
			
			// Remove from mutex map to free memory
			b.mutex.Delete(path)
			return nil
		}
	} else if len(options.Versions) > 0 {
		// Soft delete specific versions
		for _, version := range options.Versions {
			versionMeta, exists := metadata.Versions[version]
			if !exists {
				continue
			}
			
			// Mark version as deleted but not destroyed
			versionMeta.DeletedTime = now
			versionMeta.DeletedBy = options.UserID
			versionMeta.IsDestroyed = true  // This makes the version inaccessible but keeps the file
		}
	}
	// Update metadata file
	metadataPath := b.getSecretMetadataPath(path)
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Write to temporary file first for atomicity
	tempMetadataPath := metadataPath + ".tmp"
	if err := os.WriteFile(tempMetadataPath, metadataBytes, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Atomically rename to final path
	if err := os.Rename(tempMetadataPath, metadataPath); err != nil {
		os.Remove(tempMetadataPath) // Clean up temp file
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

// ListSecrets lists secrets at a specific path
func (b *FileBackend) ListSecrets(path string) ([]string, error) {
	// Normalize path
	dirPath := filepath.Join(b.basePath, "secrets", path)
	
	// Check if path exists
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to access path: %w", err)
	}
	
	// If path is a file, return empty list
	if !info.IsDir() {
		return []string{}, nil
	}
	
	// Read directory entries
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	
	// Find subdirectories which represent secrets or secret folders
	results := make([]string, 0)
	for _, entry := range entries {
		// Skip temporary files
		if strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		
		entryPath := filepath.Join(dirPath, entry.Name())
		entryInfo, err := os.Stat(entryPath)
		if err != nil {
			continue // Skip entries with errors
		}
		
		// If it's a directory, it might be a secret folder or a path prefix
		if entryInfo.IsDir() {
			// Check if it contains a metadata file (which would make it a secret)
			metadataPath := filepath.Join(entryPath, "metadata.json")
			if _, err := os.Stat(metadataPath); err == nil {
				// This is a secret folder
				relativePath := strings.TrimPrefix(entryPath, filepath.Join(b.basePath, "secrets")+string(filepath.Separator))
				results = append(results, relativePath)
			} else if os.IsNotExist(err) {
				// This is a path prefix, add with trailing slash
				relativePath := strings.TrimPrefix(entryPath, filepath.Join(b.basePath, "secrets")+string(filepath.Separator))
				results = append(results, relativePath+"/")
			}
		}
	}
	
	// Sort the results for consistency
	sort.Strings(results)
	
	return results, nil
}

// GetSecretMetadata gets metadata about a secret
func (b *FileBackend) GetSecretMetadata(path string) (*SecretMetadata, error) {
	metadataPath := b.getSecretMetadataPath(path)
	
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("secret not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}
	
	var metadata SecretMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}
	
	return &metadata, nil
}

// getOrCreateMetadata gets existing metadata or creates new metadata
func (b *FileBackend) getOrCreateMetadata(path string) (*SecretMetadata, error) {
	metadata, err := b.GetSecretMetadata(path)
	if err == nil {
		return metadata, nil
	}
	
	// If the error is "secret not found", create new metadata
	if strings.Contains(err.Error(), "secret not found") {
		return &SecretMetadata{
			Versions:       make(map[int]*VersionMetadata),
			CurrentVersion: 0,
			CreatedTime:    time.Time{}, // Will be set during write
			LastModified:   time.Time{}, // Will be set during write
		}, nil
	}
	
	// Other errors are returned
	return nil, err
}
