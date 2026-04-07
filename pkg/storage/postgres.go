package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	vaulterrors "securevault/pkg/errors"

	_ "github.com/lib/pq"
)

// PostgresBackend implements the Backend interface using PostgreSQL
type PostgresBackend struct {
	db        *sql.DB
	getEncKey EncryptionKeyProvider
}

// PostgresConfig holds configuration for PostgreSQL backend
type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// NewPostgresBackend creates a new PostgreSQL backend
func NewPostgresBackend(config PostgresConfig, keyProvider EncryptionKeyProvider) (*PostgresBackend, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	backend := &PostgresBackend{
		db:        db,
		getEncKey: keyProvider,
	}

	if err := backend.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize PostgreSQL schema: %w", err)
	}

	return backend, nil
}

func (p *PostgresBackend) initSchema() error {
	_, err := p.db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			path TEXT PRIMARY KEY,
			version INTEGER NOT NULL,
			current_version INTEGER NOT NULL,
			created_time TIMESTAMP NOT NULL,
			last_modified TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create secrets table: %w", err)
	}

	// Store data as encrypted hex string instead of plaintext JSONB
	_, err = p.db.Exec(`
		CREATE TABLE IF NOT EXISTS secret_versions (
			path TEXT NOT NULL,
			version INTEGER NOT NULL,
			encrypted_data TEXT NOT NULL,
			encrypted_metadata TEXT,
			created_time TIMESTAMP NOT NULL,
			created_by TEXT NOT NULL,
			PRIMARY KEY (path, version),
			FOREIGN KEY (path) REFERENCES secrets(path) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create secret_versions table: %w", err)
	}

	return nil
}

// Close closes the database connection
func (p *PostgresBackend) Close() error {
	return p.db.Close()
}

// encrypt encrypts data and returns hex-encoded ciphertext
func (p *PostgresBackend) encrypt(data []byte) (string, error) {
	key, err := p.getEncKey()
	if err != nil {
		return "", fmt.Errorf("encryption unavailable: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts hex-encoded ciphertext
func (p *PostgresBackend) decrypt(hexCiphertext string) ([]byte, error) {
	key, err := p.getEncKey()
	if err != nil {
		return nil, fmt.Errorf("decryption unavailable: %w", err)
	}

	ciphertext, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid hex data: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:aesGCM.NonceSize()], ciphertext[aesGCM.NonceSize():]
	return aesGCM.Open(nil, nonce, ct, nil)
}

// ReadSecret reads a secret from the database
func (p *PostgresBackend) ReadSecret(path string, options ReadOptions) (*Secret, error) {
	var version int
	if options.Version > 0 {
		version = options.Version
	} else {
		var currentVersion int
		err := p.db.QueryRow(`
			SELECT current_version FROM secrets WHERE path = $1
		`, path).Scan(&currentVersion)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, &vaulterrors.SecretNotFoundError{Path: path}
			}
			return nil, fmt.Errorf("failed to get current version: %w", err)
		}
		version = currentVersion
	}

	var encryptedData, encryptedMetadata string
	var createdTime time.Time
	var createdBy string

	err := p.db.QueryRow(`
		SELECT encrypted_data, encrypted_metadata, created_time, created_by
		FROM secret_versions
		WHERE path = $1 AND version = $2
	`, path, version).Scan(&encryptedData, &encryptedMetadata, &createdTime, &createdBy)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, &vaulterrors.VersionNotFoundError{Path: path, Version: version}
		}
		return nil, fmt.Errorf("failed to read secret version: %w", err)
	}

	// Decrypt the data
	decryptedData, err := p.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret data: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(decryptedData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse data JSON: %w", err)
	}

	secret := &Secret{
		Data:        data,
		Version:     version,
		CreatedTime: createdTime,
		CreatedBy:   createdBy,
	}

	return secret, nil
}

// WriteSecret writes a secret to the database
func (p *PostgresBackend) WriteSecret(path string, data map[string]interface{}, options WriteOptions) error {
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	if data == nil {
		data = make(map[string]interface{})
	}

	// Encrypt the data
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to encode data as JSON: %w", err)
	}

	encryptedData, err := p.encrypt(dataJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Encrypt metadata
	var encryptedMetadata string
	if options.Metadata != nil {
		metadataJSON, err := json.Marshal(options.Metadata)
		if err != nil {
			return fmt.Errorf("failed to encode metadata as JSON: %w", err)
		}
		encryptedMetadata, err = p.encrypt(metadataJSON)
		if err != nil {
			return fmt.Errorf("failed to encrypt metadata: %w", err)
		}
	} else {
		emptyMeta, _ := json.Marshal(map[string]interface{}{})
		encryptedMetadata, err = p.encrypt(emptyMeta)
		if err != nil {
			return fmt.Errorf("failed to encrypt empty metadata: %w", err)
		}
	}

	// Check if secret exists
	var exists bool
	var currentVersion int
	err = tx.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM secrets WHERE path = $1), COALESCE((SELECT current_version FROM secrets WHERE path = $1), 0)
	`, path).Scan(&exists, &currentVersion)
	if err != nil {
		return fmt.Errorf("failed to check if secret exists: %w", err)
	}

	version := currentVersion + 1
	if options.IsReplication && options.PreserveVersion {
		if options.Metadata != nil {
			if versionFloat, ok := options.Metadata["version"].(float64); ok {
				version = int(versionFloat)
			}
		}
	}

	now := time.Now()

	if exists {
		updateVersion := version
		if options.IsReplication && options.PreserveVersion && version <= currentVersion {
			// Don't downgrade current version for historical replication
			_, err = tx.Exec(`
				UPDATE secrets SET last_modified = $1 WHERE path = $2
			`, now, path)
		} else {
			_, err = tx.Exec(`
				UPDATE secrets SET current_version = $1, last_modified = $2 WHERE path = $3
			`, updateVersion, now, path)
		}
		if err != nil {
			return fmt.Errorf("failed to update secret metadata: %w", err)
		}
	} else {
		_, err = tx.Exec(`
			INSERT INTO secrets (path, version, current_version, created_time, last_modified)
			VALUES ($1, $2, $3, $4, $5)
		`, path, version, version, now, now)
		if err != nil {
			return fmt.Errorf("failed to insert secret metadata: %w", err)
		}
	}

	_, err = tx.Exec(`
		INSERT INTO secret_versions (path, version, encrypted_data, encrypted_metadata, created_time, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, path, version, encryptedData, encryptedMetadata, now, options.UserID)
	if err != nil {
		return fmt.Errorf("failed to insert secret version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteSecret deletes a secret or specific versions from the database
func (p *PostgresBackend) DeleteSecret(path string, options DeleteOptions) error {
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	var exists bool
	err = tx.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM secrets WHERE path = $1)
	`, path).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if secret exists: %w", err)
	}

	if !exists {
		return &vaulterrors.SecretNotFoundError{Path: path}
	}

	if options.Destroy {
		_, err = tx.Exec(`DELETE FROM secrets WHERE path = $1`, path)
		if err != nil {
			return fmt.Errorf("failed to delete secret: %w", err)
		}
	} else if len(options.Versions) > 0 {
		for _, version := range options.Versions {
			_, err = tx.Exec(`
				DELETE FROM secret_versions WHERE path = $1 AND version = $2
			`, path, version)
			if err != nil {
				return fmt.Errorf("failed to delete secret version: %w", err)
			}
		}

		var count int
		err = tx.QueryRow(`SELECT COUNT(*) FROM secret_versions WHERE path = $1`, path).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to count remaining versions: %w", err)
		}

		if count == 0 {
			_, err = tx.Exec(`DELETE FROM secrets WHERE path = $1`, path)
		} else {
			_, err = tx.Exec(`
				UPDATE secrets SET current_version = (SELECT MAX(version) FROM secret_versions WHERE path = $1), last_modified = $2 WHERE path = $1
			`, path, time.Now())
		}
		if err != nil {
			return fmt.Errorf("failed to update after version delete: %w", err)
		}
	} else {
		var currentVersion int
		err = tx.QueryRow(`SELECT current_version FROM secrets WHERE path = $1`, path).Scan(&currentVersion)
		if err != nil {
			return fmt.Errorf("failed to get current version: %w", err)
		}

		_, err = tx.Exec(`DELETE FROM secret_versions WHERE path = $1 AND version = $2`, path, currentVersion)
		if err != nil {
			return fmt.Errorf("failed to delete current version: %w", err)
		}

		var count int
		err = tx.QueryRow(`SELECT COUNT(*) FROM secret_versions WHERE path = $1`, path).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to count remaining versions: %w", err)
		}

		if count == 0 {
			_, err = tx.Exec(`DELETE FROM secrets WHERE path = $1`, path)
		} else {
			_, err = tx.Exec(`
				UPDATE secrets SET current_version = (SELECT MAX(version) FROM secret_versions WHERE path = $1), last_modified = $2 WHERE path = $1
			`, path, time.Now())
		}
		if err != nil {
			return fmt.Errorf("failed to update after version delete: %w", err)
		}
	}

	return tx.Commit()
}

// ListSecrets lists all secrets under a given path prefix
func (p *PostgresBackend) ListSecrets(prefix string) ([]string, error) {
	if prefix != "" && prefix[len(prefix)-1] != '/' {
		prefix = prefix + "/"
	}

	rows, err := p.db.Query(`
		SELECT path FROM secrets WHERE path LIKE $1 || '%'
	`, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, fmt.Errorf("failed to scan path: %w", err)
		}
		paths = append(paths, path)
	}

	return paths, rows.Err()
}

// GetSecretMetadata gets metadata for a secret
func (p *PostgresBackend) GetSecretMetadata(path string) (*SecretMetadata, error) {
	tx, err := p.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	var currentVersion int
	var createdTime, lastModified time.Time
	err = tx.QueryRow(`
		SELECT current_version, created_time, last_modified FROM secrets WHERE path = $1
	`, path).Scan(&currentVersion, &createdTime, &lastModified)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, &vaulterrors.SecretNotFoundError{Path: path}
		}
		return nil, fmt.Errorf("failed to get secret metadata: %w", err)
	}

	rows, err := tx.Query(`
		SELECT version, created_time, created_by, encrypted_metadata
		FROM secret_versions WHERE path = $1 ORDER BY version
	`, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}
	defer rows.Close()

	versions := make(map[int]*VersionMetadata)
	for rows.Next() {
		var version int
		var versionCreatedTime time.Time
		var createdBy string
		var encryptedMetadata sql.NullString

		if err := rows.Scan(&version, &versionCreatedTime, &createdBy, &encryptedMetadata); err != nil {
			return nil, fmt.Errorf("failed to scan version metadata: %w", err)
		}

		versionMetadata := &VersionMetadata{
			CreatedTime: versionCreatedTime,
			CreatedBy:   createdBy,
		}

		if encryptedMetadata.Valid && encryptedMetadata.String != "" {
			decrypted, err := p.decrypt(encryptedMetadata.String)
			if err == nil {
				var metadataMap map[string]interface{}
				if err := json.Unmarshal(decrypted, &metadataMap); err == nil {
					versionMetadata.CustomMetadata = metadataMap
				}
			}
		}

		versions[version] = versionMetadata
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating version rows: %w", err)
	}

	return &SecretMetadata{
		CurrentVersion: currentVersion,
		Versions:       versions,
		CreatedTime:    createdTime,
		LastModified:   lastModified,
	}, tx.Commit()
}
