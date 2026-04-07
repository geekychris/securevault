package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	vaulterrors "securevault/pkg/errors"
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
	CreatedTime    time.Time              `json:"created_time"`
	CreatedBy      string                 `json:"created_by"`
	DeletedTime    time.Time              `json:"deleted_time,omitempty"`
	DeletedBy      string                 `json:"deleted_by,omitempty"`
	IsDestroyed    bool                   `json:"is_destroyed"`
	CustomMetadata map[string]interface{} `json:"custom_metadata,omitempty"`
}

// WriteOptions contains options for write operations
type WriteOptions struct {
	UserID          string
	Metadata        map[string]interface{}
	IsReplication   bool
	PreserveVersion bool
}

// ReadOptions contains options for read operations
type ReadOptions struct {
	Version int
}

// DeleteOptions contains options for delete operations
type DeleteOptions struct {
	UserID   string
	Versions []int
	Destroy  bool
}

// Backend is the interface that all storage backends must implement
type Backend interface {
	WriteSecret(path string, data map[string]interface{}, options WriteOptions) error
	ReadSecret(path string, options ReadOptions) (*Secret, error)
	DeleteSecret(path string, options DeleteOptions) error
	ListSecrets(path string) ([]string, error)
	GetSecretMetadata(path string) (*SecretMetadata, error)
}

// EncryptionKeyProvider provides the encryption key (from seal manager)
type EncryptionKeyProvider func() ([]byte, error)

// FileBackend implements the Backend interface using the filesystem
type FileBackend struct {
	basePath     string
	mutexMap     sync.Map
	globalMu     sync.RWMutex // protects structural operations
	getEncKey    EncryptionKeyProvider
}

// NewFileBackend creates a new file-based backend
func NewFileBackend(basePath string, keyProvider EncryptionKeyProvider) (Backend, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &FileBackend{
		basePath:  basePath,
		getEncKey: keyProvider,
	}, nil
}

// getMutex gets or creates a mutex for a given path
func (b *FileBackend) getMutex(path string) *sync.Mutex {
	actual, _ := b.mutexMap.LoadOrStore(path, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// encrypt encrypts data using AES-256-GCM
func (b *FileBackend) encrypt(data []byte) ([]byte, error) {
	key, err := b.getEncKey()
	if err != nil {
		return nil, fmt.Errorf("encryption unavailable: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-256-GCM
func (b *FileBackend) decrypt(ciphertext []byte) ([]byte, error) {
	key, err := b.getEncKey()
	if err != nil {
		return nil, fmt.Errorf("decryption unavailable: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aesGCM.NonceSize()], ciphertext[aesGCM.NonceSize():]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func (b *FileBackend) getSecretPath(path string) string {
	return filepath.Join(b.basePath, "secrets", path)
}

func (b *FileBackend) getSecretVersionPath(path string, version int) string {
	return filepath.Join(b.getSecretPath(path), fmt.Sprintf("v%d.data", version))
}

func (b *FileBackend) getSecretMetadataPath(path string) string {
	return filepath.Join(b.getSecretPath(path), "metadata.enc")
}

// WriteSecret writes a secret to the backend
func (b *FileBackend) WriteSecret(path string, data map[string]interface{}, options WriteOptions) error {
	mu := b.getMutex(path)
	mu.Lock()
	defer mu.Unlock()

	secretPath := b.getSecretPath(path)
	if err := os.MkdirAll(secretPath, 0700); err != nil {
		return fmt.Errorf("failed to create secret directory: %w", err)
	}

	metadata, err := b.getOrCreateMetadata(path)
	if err != nil {
		return err
	}

	newVersion := metadata.CurrentVersion + 1

	now := time.Now()
	secret := Secret{
		Data:         data,
		CreatedTime:  now,
		Version:      newVersion,
		LastModified: now,
		CreatedBy:    options.UserID,
		Metadata:     options.Metadata,
	}

	// Encrypt secret data
	secretData, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	encryptedData, err := b.encrypt(secretData)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
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

	// Encrypt metadata
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	encryptedMetadata, err := b.encrypt(metadataBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Write both to temp files first
	versionPath := b.getSecretVersionPath(path, newVersion)
	tempVersionPath := versionPath + ".tmp"
	metadataPath := b.getSecretMetadataPath(path)
	tempMetadataPath := metadataPath + ".tmp"

	if err := os.WriteFile(tempVersionPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write secret data: %w", err)
	}

	if err := os.WriteFile(tempMetadataPath, encryptedMetadata, 0600); err != nil {
		os.Remove(tempVersionPath)
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Atomic renames
	if err := os.Rename(tempVersionPath, versionPath); err != nil {
		os.Remove(tempVersionPath)
		os.Remove(tempMetadataPath)
		return fmt.Errorf("failed to save secret data: %w", err)
	}

	if err := os.Rename(tempMetadataPath, metadataPath); err != nil {
		// Rollback: remove the version file since metadata is inconsistent
		os.Remove(versionPath)
		os.Remove(tempMetadataPath)
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	return nil
}

// ReadSecret reads a secret from the backend
func (b *FileBackend) ReadSecret(path string, options ReadOptions) (*Secret, error) {
	mu := b.getMutex(path)
	mu.Lock()
	defer mu.Unlock()

	metadata, err := b.getSecretMetadataLocked(path)
	if err != nil {
		return nil, err
	}

	version := options.Version
	if version == 0 {
		version = metadata.CurrentVersion
	}

	versionMeta, exists := metadata.Versions[version]
	if !exists {
		return nil, &vaulterrors.VersionNotFoundError{Path: path, Version: version}
	}

	if versionMeta.IsDestroyed {
		return nil, &vaulterrors.VersionDestroyedError{Path: path, Version: version}
	}

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
	mu := b.getMutex(path)
	mu.Lock()
	defer mu.Unlock()

	metadata, err := b.getSecretMetadataLocked(path)
	if err != nil {
		return err
	}

	versionsToDelete := options.Versions
	if len(versionsToDelete) == 0 && options.Destroy {
		versionsToDelete = make([]int, 0, len(metadata.Versions))
		for version := range metadata.Versions {
			versionsToDelete = append(versionsToDelete, version)
		}
	}

	now := time.Now()
	secretPath := b.getSecretPath(path)

	if options.Destroy {
		for _, version := range versionsToDelete {
			versionMeta, exists := metadata.Versions[version]
			if !exists {
				continue
			}

			versionMeta.IsDestroyed = true
			versionMeta.DeletedTime = now
			versionMeta.DeletedBy = options.UserID

			versionPath := b.getSecretVersionPath(path, version)
			if err := os.Remove(versionPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete secret version %d: %w", version, err)
			}
		}

		allDestroyed := true
		for _, meta := range metadata.Versions {
			if !meta.IsDestroyed {
				allDestroyed = false
				break
			}
		}

		if allDestroyed {
			if err := os.RemoveAll(secretPath); err != nil {
				return fmt.Errorf("failed to delete secret directory: %w", err)
			}
			b.mutexMap.Delete(path)
			return nil
		}
	} else if len(options.Versions) > 0 {
		for _, version := range options.Versions {
			versionMeta, exists := metadata.Versions[version]
			if !exists {
				continue
			}
			versionMeta.DeletedTime = now
			versionMeta.DeletedBy = options.UserID
			versionMeta.IsDestroyed = true
		}
	}

	// Encrypt and save updated metadata
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	encryptedMetadata, err := b.encrypt(metadataBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	metadataPath := b.getSecretMetadataPath(path)
	tempMetadataPath := metadataPath + ".tmp"
	if err := os.WriteFile(tempMetadataPath, encryptedMetadata, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	if err := os.Rename(tempMetadataPath, metadataPath); err != nil {
		os.Remove(tempMetadataPath)
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

// ListSecrets lists secrets at a specific path
func (b *FileBackend) ListSecrets(path string) ([]string, error) {
	dirPath := filepath.Join(b.basePath, "secrets", path)

	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to access path: %w", err)
	}

	if !info.IsDir() {
		return []string{}, nil
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	results := make([]string, 0)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}

		entryPath := filepath.Join(dirPath, entry.Name())
		entryInfo, err := os.Stat(entryPath)
		if err != nil {
			continue
		}

		if entryInfo.IsDir() {
			metadataPath := filepath.Join(entryPath, "metadata.enc")
			if _, err := os.Stat(metadataPath); err == nil {
				relativePath := strings.TrimPrefix(entryPath, filepath.Join(b.basePath, "secrets")+string(filepath.Separator))
				results = append(results, relativePath)
			} else if os.IsNotExist(err) {
				// Also check for legacy unencrypted metadata
				legacyPath := filepath.Join(entryPath, "metadata.json")
				if _, err := os.Stat(legacyPath); err == nil {
					relativePath := strings.TrimPrefix(entryPath, filepath.Join(b.basePath, "secrets")+string(filepath.Separator))
					results = append(results, relativePath)
				} else {
					relativePath := strings.TrimPrefix(entryPath, filepath.Join(b.basePath, "secrets")+string(filepath.Separator))
					results = append(results, relativePath+"/")
				}
			}
		}
	}

	sort.Strings(results)
	return results, nil
}

// GetSecretMetadata gets metadata about a secret (public - acquires its own lock)
func (b *FileBackend) GetSecretMetadata(path string) (*SecretMetadata, error) {
	mu := b.getMutex(path)
	mu.Lock()
	defer mu.Unlock()
	return b.getSecretMetadataLocked(path)
}

// getSecretMetadataLocked reads metadata without acquiring the lock (caller must hold it)
func (b *FileBackend) getSecretMetadataLocked(path string) (*SecretMetadata, error) {
	metadataPath := b.getSecretMetadataPath(path)

	encryptedData, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &vaulterrors.SecretNotFoundError{Path: path}
		}
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	decryptedData, err := b.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	var metadata SecretMetadata
	if err := json.Unmarshal(decryptedData, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, nil
}

// getOrCreateMetadata gets existing metadata or creates new (caller must hold the lock)
func (b *FileBackend) getOrCreateMetadata(path string) (*SecretMetadata, error) {
	metadata, err := b.getSecretMetadataLocked(path)
	if err == nil {
		return metadata, nil
	}

	if vaulterrors.IsNotFound(err) {
		return &SecretMetadata{
			Versions:       make(map[int]*VersionMetadata),
			CurrentVersion: 0,
		}, nil
	}

	return nil, err
}
