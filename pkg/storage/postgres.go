package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// PostgresBackend implements the Backend interface using PostgreSQL
type PostgresBackend struct {
	db *sql.DB
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
func NewPostgresBackend(config PostgresConfig) (*PostgresBackend, error) {
	// Create connection string
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode,
	)

	// Connect to database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	// Create backend instance
	backend := &PostgresBackend{
		db: db,
	}

	// Initialize database schema
	if err := backend.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize PostgreSQL schema: %w", err)
	}

	return backend, nil
}

// initSchema creates necessary tables if they don't exist
func (p *PostgresBackend) initSchema() error {
	// Create secrets table
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

	// Create secret_versions table
	_, err = p.db.Exec(`
		CREATE TABLE IF NOT EXISTS secret_versions (
			path TEXT NOT NULL,
			version INTEGER NOT NULL,
			data JSONB NOT NULL,
			metadata JSONB,
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

// ReadSecret reads a secret from the database
func (p *PostgresBackend) ReadSecret(path string, options ReadOptions) (*Secret, error) {
	var version int
	if options.Version > 0 {
		version = options.Version
	} else {
		// Get the current version
		var currentVersion int
		err := p.db.QueryRow(`
			SELECT current_version FROM secrets WHERE path = $1
		`, path).Scan(&currentVersion)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("secret not found: %s", path)
			}
			return nil, fmt.Errorf("failed to get current version: %w", err)
		}
		version = currentVersion
	}

	// Read the specified version
	var dataJSON, metadataJSON []byte
	var createdTime time.Time
	var createdBy string

	err := p.db.QueryRow(`
		SELECT data, metadata, created_time, created_by
		FROM secret_versions
		WHERE path = $1 AND version = $2
	`, path, version).Scan(&dataJSON, &metadataJSON, &createdTime, &createdBy)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("secret version not found: %s (version %d)", path, version)
		}
		return nil, fmt.Errorf("failed to read secret version: %w", err)
	}

	// Parse data JSON
	var data map[string]interface{}
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return nil, fmt.Errorf("failed to parse data JSON: %w", err)
	}

	// Create and return secret
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
	// Start a transaction
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Ensure data is a valid map to prevent JSON encoding issues
	if data == nil {
		data = make(map[string]interface{})
	}

	// Convert data to JSON - ensure it's properly formatted for PostgreSQL JSONB
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to encode data as JSON: %w", err)
	}

	// Validate that the JSON is well-formed
	var dataCheck interface{}
	if err := json.Unmarshal(dataJSON, &dataCheck); err != nil {
		return fmt.Errorf("generated invalid JSON for data: %w", err)
	}

	// Convert metadata to JSON
	var metadataJSON []byte
	if options.Metadata != nil {
		// Ensure metadata is properly formatted
		metadataJSON, err = json.Marshal(options.Metadata)
		if err != nil {
			return fmt.Errorf("failed to encode metadata as JSON: %w", err)
		}

		// Validate metadata JSON
		var metaCheck interface{}
		if err := json.Unmarshal(metadataJSON, &metaCheck); err != nil {
			return fmt.Errorf("generated invalid JSON for metadata: %w", err)
		}
	} else {
		// Use empty JSON object if no metadata provided
		metadataJSON = []byte("{}")
	}

	// Check if secret exists
	var exists bool
	var currentVersion int
	err = tx.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM secrets WHERE path = $1), COALESCE(current_version, 0)
		FROM secrets
		WHERE path = $1
	`, path).Scan(&exists, &currentVersion)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check if secret exists: %w", err)
	}

	// Determine the version
	var version int
	if options.IsReplication && options.PreserveVersion {
		// In replication mode, use the version from metadata if specified
		if options.Metadata != nil {
			versionFloat, ok := options.Metadata["version"].(float64)
			if ok {
				version = int(versionFloat)
			} else {
				version = currentVersion + 1
			}
		} else {
			version = currentVersion + 1
		}
	} else if exists {
		// Increment version for existing secret
		version = currentVersion + 1
	} else {
		// First version for new secret
		version = 1
	}

	now := time.Now()

	// Store the secret metadata
	if exists {
		// For replication with PreserveVersion, we need special handling:
		// 1. If we're writing a historical version (older than current), don't update current_version
		// 2. If we're writing a newer version, update current_version as usual
		if options.IsReplication && options.PreserveVersion {
			// Only update current_version if this version is newer than the current one
			if version > currentVersion {
				_, err = tx.Exec(`
					UPDATE secrets
					SET current_version = $1, last_modified = $2
					WHERE path = $3
				`, version, now, path)
				if err != nil {
					return fmt.Errorf("failed to update secret metadata: %w", err)
				}
			} else {
				// Just update last_modified timestamp
				_, err = tx.Exec(`
					UPDATE secrets
					SET last_modified = $1
					WHERE path = $2
				`, now, path)
				if err != nil {
					return fmt.Errorf("failed to update secret last_modified: %w", err)
				}
			}
		} else {
			// Standard update - always set current_version to the new version
			_, err = tx.Exec(`
				UPDATE secrets
				SET current_version = $1, last_modified = $2
				WHERE path = $3
			`, version, now, path)
			if err != nil {
				return fmt.Errorf("failed to update secret metadata: %w", err)
			}
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

	// Store the secret version - ensure JSON is properly passed to PostgreSQL
	_, err = tx.Exec(`
		INSERT INTO secret_versions (path, version, data, metadata, created_time, created_by)
		VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6)
	`, path, version, string(dataJSON), string(metadataJSON), now, options.UserID)
	if err != nil {
		return fmt.Errorf("failed to insert secret version: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteSecret deletes a secret or specific versions from the database
func (p *PostgresBackend) DeleteSecret(path string, options DeleteOptions) error {
	// Start a transaction
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if secret exists
	var exists bool
	err = tx.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM secrets WHERE path = $1)
	`, path).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if secret exists: %w", err)
	}

	if !exists {
		return fmt.Errorf("secret not found: %s", path)
	}

	if options.Destroy {
		// Delete the entire secret with all versions
		_, err = tx.Exec(`
			DELETE FROM secrets WHERE path = $1
		`, path)
		if err != nil {
			return fmt.Errorf("failed to delete secret: %w", err)
		}
	} else if len(options.Versions) > 0 {
		// Delete specific versions
		for _, version := range options.Versions {
			_, err = tx.Exec(`
				DELETE FROM secret_versions WHERE path = $1 AND version = $2
			`, path, version)
			if err != nil {
				return fmt.Errorf("failed to delete secret version: %w", err)
			}
		}

		// Check if there are any versions left
		var count int
		err = tx.QueryRow(`
			SELECT COUNT(*) FROM secret_versions WHERE path = $1
		`, path).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to count remaining versions: %w", err)
		}

		if count == 0 {
			// If no versions left, delete the secret metadata
			_, err = tx.Exec(`
				DELETE FROM secrets WHERE path = $1
			`, path)
			if err != nil {
				return fmt.Errorf("failed to delete secret metadata: %w", err)
			}
		} else {
			// Update current version to the latest remaining version
			_, err = tx.Exec(`
				UPDATE secrets
				SET current_version = (
					SELECT MAX(version) FROM secret_versions WHERE path = $1
				),
				last_modified = $2
				WHERE path = $1
			`, path, time.Now())
			if err != nil {
				return fmt.Errorf("failed to update current version: %w", err)
			}
		}
	} else {
		// Get the current version
		var currentVersion int
		err = tx.QueryRow(`
			SELECT current_version FROM secrets WHERE path = $1
		`, path).Scan(&currentVersion)
		if err != nil {
			return fmt.Errorf("failed to get current version: %w", err)
		}

		// Delete the current version
		_, err = tx.Exec(`
			DELETE FROM secret_versions WHERE path = $1 AND version = $2
		`, path, currentVersion)
		if err != nil {
			return fmt.Errorf("failed to delete current version: %w", err)
		}

		// Check if there are any versions left
		var count int
		err = tx.QueryRow(`
			SELECT COUNT(*) FROM secret_versions WHERE path = $1
		`, path).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to count remaining versions: %w", err)
		}

		if count == 0 {
			// If no versions left, delete the secret metadata
			_, err = tx.Exec(`
				DELETE FROM secrets WHERE path = $1
			`, path)
			if err != nil {
				return fmt.Errorf("failed to delete secret metadata: %w", err)
			}
		} else {
			// Update current version to the latest remaining version
			_, err = tx.Exec(`
				UPDATE secrets
				SET current_version = (
					SELECT MAX(version) FROM secret_versions WHERE path = $1
				),
				last_modified = $2
				WHERE path = $1
			`, path, time.Now())
			if err != nil {
				return fmt.Errorf("failed to update current version: %w", err)
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListSecrets lists all secrets under a given path prefix
func (p *PostgresBackend) ListSecrets(prefix string) ([]string, error) {
	// Normalize prefix to ensure consistent matching
	if prefix != "" && prefix[len(prefix)-1] != '/' {
		prefix = prefix + "/"
	}

	// Get all paths that start with the prefix
	rows, err := p.db.Query(`
		SELECT path FROM secrets
		WHERE path LIKE $1 || '%'
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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secret paths: %w", err)
	}

	return paths, nil
}

// GetSecretMetadata gets metadata for a secret
func (p *PostgresBackend) GetSecretMetadata(path string) (*SecretMetadata, error) {
	// Start a transaction for consistent reads
	tx, err := p.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Get secret metadata
	var currentVersion int
	var createdTime, lastModified time.Time
	err = tx.QueryRow(`
		SELECT current_version, created_time, last_modified
		FROM secrets
		WHERE path = $1
	`, path).Scan(&currentVersion, &createdTime, &lastModified)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("secret not found: %s", path)
		}
		return nil, fmt.Errorf("failed to get secret metadata: %w", err)
	}

	// Get all versions
	rows, err := tx.Query(`
		SELECT version, created_time, created_by, metadata
		FROM secret_versions
		WHERE path = $1
		ORDER BY version
	`, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}
	defer rows.Close()

	// Build version map
	versions := make(map[int]*VersionMetadata)
	for rows.Next() {
		var version int
		var versionCreatedTime time.Time
		var createdBy string
		var metadataJSON []byte

		if err := rows.Scan(&version, &versionCreatedTime, &createdBy, &metadataJSON); err != nil {
			return nil, fmt.Errorf("failed to scan version metadata: %w", err)
		}

		// Create version metadata
		versionMetadata := &VersionMetadata{
			CreatedTime: versionCreatedTime,
			CreatedBy:   createdBy,
		}

		// Parse metadata JSON if present
		if metadataJSON != nil {
			var metadataMap map[string]interface{}
			if err := json.Unmarshal(metadataJSON, &metadataMap); err != nil {
				return nil, fmt.Errorf("failed to parse version metadata JSON: %w", err)
			}
			// Store custom metadata in the Metadata map
			versionMetadata.CustomMetadata = metadataMap
		}

		// Add to versions map
		versions[version] = versionMetadata
	}

	// Check for errors in iteration
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating version rows: %w", err)
	}

	// Create and return secret metadata
	secretMetadata := &SecretMetadata{
		CurrentVersion: currentVersion,
		Versions:       versions,
		CreatedTime:    createdTime,
		LastModified:   lastModified,
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return secretMetadata, nil
}
