-- Initialize database for SecureVault PostgreSQL backend tests

-- Enable UUID extension (if needed in the future)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create schema
CREATE SCHEMA IF NOT EXISTS securevault;

-- Set search path
SET search_path TO securevault, public;

-- Create secrets table
CREATE TABLE IF NOT EXISTS secrets (
    path TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    current_version INTEGER NOT NULL,
    created_time TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL
);

-- Create secret_versions table
CREATE TABLE IF NOT EXISTS secret_versions (
    path TEXT NOT NULL,
    version INTEGER NOT NULL,
    data JSONB NOT NULL,
    metadata JSONB,
    created_time TIMESTAMP NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY (path, version),
    FOREIGN KEY (path) REFERENCES secrets(path) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_secrets_path ON secrets(path);
CREATE INDEX IF NOT EXISTS idx_secret_versions_path ON secret_versions(path);
CREATE INDEX IF NOT EXISTS idx_secret_versions_path_version ON secret_versions(path, version);

-- Grant privileges
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA securevault TO securevault;

-- Create a helper function for version tracking
CREATE OR REPLACE FUNCTION securevault.update_last_modified()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_modified = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create a trigger to automatically update last_modified timestamp
CREATE TRIGGER secrets_last_modified
BEFORE UPDATE ON secrets
FOR EACH ROW
EXECUTE FUNCTION securevault.update_last_modified();

-- Create initial schema version tracking
CREATE TABLE IF NOT EXISTS schema_versions (
    version INT PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT NOW(),
    description TEXT
);

-- Insert current schema version
INSERT INTO schema_versions (version, description) 
VALUES (1, 'Initial schema with secrets and versioning support')
ON CONFLICT (version) DO NOTHING;

