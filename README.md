# SecureVault - Secure Secrets Management System

SecureVault is a secure secrets management system similar to HashiCorp Vault, designed to safely store, access, and distribute sensitive information like API keys, passwords, certificates, and other secrets.

## Table of Contents

- [Features](#features)
- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Running the Server](#running-the-server)
- [Using the Go Client](#using-the-go-client)
- [Using the Java Client](#using-the-java-client)
- [Permission Scenarios Examples](#permission-scenarios-examples)
- [Secret Versioning](#secret-versioning)
- [Replication Setup](#replication-setup)
- [Security Considerations](#security-considerations)
- [Backup and Recovery](#backup-and-recovery)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Secure Secret Storage**: AES-256-GCM encrypted storage of sensitive information
- **Fine-grained Access Control**: Policy-based access control for secret paths
- **Versioning**: Full support for versioning of secrets with metadata
- **Multi-node Support**: Distributed architecture with leader-follower replication
- **Client Libraries**: Native clients for Go and Java with consistent APIs
- **RESTful API**: HTTP API for interacting with the vault from any language
- **Role-Based Access Control**: Define policies to restrict access based on roles
- **Audit Logging**: Detailed logs of all access and changes to secrets
- **High Availability**: Support for active/passive failover

## System Requirements

### Minimum Requirements

- **CPU**: 2 cores
- **Memory**: 2GB RAM
- **Disk**: 1GB free space (plus space for secrets)
- **Operating System**: Linux, macOS, or Windows

### Software Requirements

For building and running:
- Go 1.20 or later
- Git

For Java client:
- JDK 17 or later
- Maven 3.6 or later

For production use:
- TLS certificates
- Load balancer (for multi-node setup)

## Quick Start

### Building and Running

```bash
# Clone the repository
git clone https://github.com/yourusername/securevault.git
cd securevault

# Install dependencies
go mod download

# Build server and clients
make build  # Or use the commands below

# Build just the server
go build -o bin/securevault cmd/server/main.go

# Build the Go client
go build -o bin/securevault-client clients/go/cmd/client/main.go

# Start server with development config
./bin/securevault server --config configs/dev-config.yaml
```

### Development Configuration Example

Create a `dev-config.yaml` file:

```yaml
server:
  address: "127.0.0.1"
  port: 8200
  tls:
    enabled: false  # Disable TLS for development

storage:
  type: "file"
  path: "./data"    # Local storage path

auth:
  token_ttl: "24h"  # Default token lifetime

replication:
  mode: "standalone"
```

### Create Your First Secret

```bash
# Get a token (in development mode, a root token is available)
ROOT_TOKEN="root"  # Use an actual token in production

# Create a secret
curl -X POST \
     -H "X-Vault-Token: $ROOT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "secret123"}' \
     http://127.0.0.1:8200/v1/secret/my-first-secret

# Read the secret
curl -H "X-Vault-Token: $ROOT_TOKEN" \
     http://127.0.0.1:8200/v1/secret/my-first-secret

# Create a policy
curl -X POST \
     -H "X-Vault-Token: $ROOT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"policy": {"name": "app-readonly", "description": "Read-only access", "rules": [{"path": "secret/app/*", "capabilities": ["read", "list"]}]}}' \
     http://127.0.0.1:8200/v1/policies
```
## Running the Server

### Configuration

Before running the server, you'll need a configuration file. A sample file is provided at `config.yaml`. 
Review this file and adjust settings as needed:

```yaml
server:
  address: "0.0.0.0"  # Listen on all interfaces
  port: 8200         # Default port
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"

storage:
  type: "file"        # Storage backend type
  path: "/var/lib/securevault/data"

auth:
  token_ttl: "24h"    # Default token lifetime

replication:
  mode: "standalone"  # Replication mode
```

### Starting in Development Mode

For development and testing, you can use a simplified configuration:

```yaml
# dev-config.yaml
server:
  address: "127.0.0.1"
  port: 8200
  tls:
    enabled: false

storage:
  type: "file"
  path: "./data"

auth:
  token_ttl: "24h"
  enable_unauthenticated_token_creation: true  # For easy testing only

replication:
  mode: "standalone"
```

Then start the server:

```bash
./bin/securevault server --config dev-config.yaml
```

### Starting in Production Mode

For production use, enable TLS and disable unauthenticated token creation:

```bash
./bin/securevault server --config prod-config.yaml
```

### Server Commands

The server binary supports various commands:

```bash
# Start the server
./bin/securevault server --config config.yaml

# Create a token
./bin/securevault token create --policy admin

# Create a policy from file
./bin/securevault policy create --file admin-policy.yaml

# List policies
./bin/securevault policy list

# Show server status
./bin/securevault status

# Create backup
./bin/securevault backup create --output backup.zip

# Restore from backup
./bin/securevault backup restore --input backup.zip
```

## Using the Go Client

### Installation

If you're using Go modules, add the client to your project:

```bash
go get github.com/yourusername/securevault/clients/go
```

### Basic Usage

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/securevault/clients/go"
)

func main() {
	// Create a client with configuration options
	client, err := securevault.NewClient(
		"https://vault.example.com:8200",
		"s.your-auth-token",
		securevault.WithTimeout(10*time.Second),
		securevault.WithMaxRetries(3),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Write a secret
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "dbpass123",
		"host":     "db.example.com",
		"port":     5432,
	}

	err = client.WriteSecret(ctx, "database/credentials", secretData)
	if err != nil {
		log.Fatalf("Failed to write secret: %v", err)
	}

	// Read a secret
	secret, err := client.ReadSecret(ctx, "database/credentials")
	if err != nil {
		log.Fatalf("Failed to read secret: %v", err)
	}

	fmt.Printf("Username: %s\n", secret.Data["username"])
	fmt.Printf("Password: %s\n", secret.Data["password"])

	// List secrets at a path
	secrets, err := client.ListSecrets(ctx, "database")
	if err != nil {
		log.Fatalf("Failed to list secrets: %v", err)
	}

	fmt.Println("Available secrets:")
	for _, s := range secrets {
		fmt.Printf("- %s\n", s)
	}

	// Delete a secret
	err = client.DeleteSecret(ctx, "database/credentials")
	if err != nil {
		log.Fatalf("Failed to delete secret: %v", err)
	}
}
```

### Error Handling

The Go client provides helper functions to check specific error types:

```go
secret, err := client.ReadSecret(ctx, "database/credentials")
if err != nil {
    if securevault.IsNotFound(err) {
        // Handle secret not found
        log.Printf("Secret not found: %v", err)
    } else if securevault.IsUnauthorized(err) {
        // Handle authentication error
        log.Printf("Not authorized: %v", err)
    } else if securevault.IsForbidden(err) {
        // Handle permission error
        log.Printf("Permission denied: %v", err)
    } else {
        // Handle other errors
        log.Fatalf("Error reading secret: %v", err)
    }
}
}
}
```

### Managing Policies with Go Client

```go
// Create a policy
policy := &securevault.Policy{
    Name:        "app-policy",
    Description: "Policy for application access",
    Rules: []securevault.PolicyRule{
        {
            Path:         "secret/app/*",
            Capabilities: []string{"read", "list"},
        },
    },
}

err = client.CreatePolicy(ctx, policy)
if err != nil {
    log.Fatalf("Failed to create policy: %v", err)
}

// List policies
policies, err := client.ListPolicies(ctx)
if err != nil {
    log.Fatalf("Failed to list policies: %v", err)
}
for _, p := range policies {
    fmt.Println(p)
}

// Get a specific policy
retrievedPolicy, err := client.GetPolicy(ctx, "app-policy")
if err != nil {
    log.Fatalf("Failed to get policy: %v", err)
}
fmt.Printf("Policy name: %s\n", retrievedPolicy.Name)
fmt.Printf("Description: %s\n", retrievedPolicy.Description)

// Update a policy
retrievedPolicy.Rules = append(retrievedPolicy.Rules, securevault.PolicyRule{
    Path:         "secret/app/logs/*",
    Capabilities: []string{"read", "list"},
})

err = client.UpdatePolicy(ctx, retrievedPolicy)
if err != nil {
    log.Fatalf("Failed to update policy: %v", err)
}

// Delete a policy
err = client.DeletePolicy(ctx, "app-policy")
if err != nil {
    log.Fatalf("Failed to delete policy: %v", err)
}
```

## Permission Scenarios Examples

SecureVault uses a path-based permission system with capabilities that determine what actions users can perform on specific paths. Here are some common scenarios:

### Read-Only Access to Specific Path

This policy gives read-only access to database credentials:

```yaml
name: "db-readonly"
description: "Read-only access to database credentials"
rules:
  - path: "secret/database/*"
    capabilities: ["read", "list"]
```

Usage example:

```bash
# Create a policy
curl -X POST -H "X-Vault-Token: $ROOT_TOKEN" -d '{
  "policy": {
    "name": "db-readonly",
    "description": "Read-only access to database credentials",
    "rules": [
      {
        "path": "secret/database/*",
        "capabilities": ["read", "list"]
      }
    ]
  }
}' http://127.0.0.1:8200/v1/policies

# Create a token with this policy
RESTRICTED_TOKEN=$(curl -X POST -H "X-Vault-Token: $ROOT_TOKEN" -d '{
  "policy_ids": ["db-readonly"],
  "ttl": "1h"
}' http://127.0.0.1:8200/v1/auth/token/create | jq -r '.auth.client_token')

# This will succeed (read is allowed)
curl -H "X-Vault-Token: $RESTRICTED_TOKEN" http://127.0.0.1:8200/v1/secret/database/postgres

# This will fail (write is not allowed)
curl -X POST -H "X-Vault-Token: $RESTRICTED_TOKEN" -d '{
  "data": {"password": "newpassword"}
}' http://127.0.0.1:8200/v1/secret/database/postgres
```

### Application with Multiple Access Patterns

For an application that needs different access levels to different paths:

```yaml
name: "app-xyz-policy"
description: "Access policy for App XYZ"
rules:
  - path: "secret/app/xyz/config/*"
    capabilities: ["read", "list"]
  - path: "secret/app/xyz/data/*"
    capabilities: ["create", "read", "update", "delete", "list"]
  - path: "secret/shared/*"
    capabilities: ["read"]
```

### Admin Access to Specific Team Resources

For team administrators:

```yaml
name: "team-a-admin"
description: "Admin access to Team A resources"
rules:
  - path: "secret/teams/team-a/*"
    capabilities: ["create", "read", "update", "delete", "list"]
  - path: "policies/team-a-*"
    capabilities: ["create", "read", "update", "delete", "list"]
```

## Secret Versioning

SecureVault supports versioning of secrets, allowing you to track changes over time and roll back to previous versions if needed.

### Working with Versions in the Go Client

```go
// Write multiple versions of a secret
// Version 1
client.WriteSecret(ctx, "api/keys", map[string]interface{}{
    "api_key": "version1-key",
})

// Version 2
client.WriteSecret(ctx, "api/keys", map[string]interface{}{
    "api_key": "version2-key",
})

// Get the latest version (2)
latest, err := client.ReadSecret(ctx, "api/keys")
fmt.Println("Latest key:", latest.Data["api_key"])

// Get a specific version (1)
v1, err := client.ReadSecret(ctx, "api/keys", securevault.ReadOptions{
    Version: 1,
})
fmt.Println("Version 1 key:", v1.Data["api_key"])

// Get metadata with version history
meta, err := client.GetSecretMetadata(ctx, "api/keys")
fmt.Printf("Total versions: %d\n", len(meta.Versions))
fmt.Printf("Current version: %d\n", meta.CurrentVersion)
```

### Working with Versions in the Java Client

```java
// Write multiple versions of a secret
// Version 1
Map<String, Object> v1Data = new HashMap<>();
v1Data.put("api_key", "version1-key");
client.writeSecret("api/keys", v1Data);

// Version 2
Map<String, Object> v2Data = new HashMap<>();
v2Data.put("api_key", "version2-key");
client.writeSecret("api/keys", v2Data);

// Get the latest version (2)
Secret latest = client.readSecret("api/keys");
System.out.println("Latest key: " + latest.getData().get("api_key"));

// Get a specific version (1)
Secret v1 = client.readSecret("api/keys", ReadOptions.builder()
        .version(1)
        .build());
System.out.println("Version 1 key: " + v1.getData().get("api_key"));

// Get metadata with version history
SecretMetadata meta = client.getSecretMetadata("api/keys");
System.out.println("Total versions: " + meta.getVersions().size());
System.out.println("Current version: " + meta.getCurrentVersion());
```

### Version Deletion

You can delete specific versions of a secret:

```go
// Go: Delete version 1
client.DeleteSecret(ctx, "api/keys", securevault.DeleteOptions{
    Versions: []int{1},
})
```

```java
// Java: Delete version 1
client.deleteSecret("api/keys", DeleteOptions.builder()
        .versions(Collections.singletonList(1))
        .build());
```

For permanent deletion, set the `Destroy` flag:

```go
// Go: Permanently delete all versions
client.DeleteSecret(ctx, "api/keys", securevault.DeleteOptions{
    Destroy: true,
})
```

```java
// Java: Permanently delete all versions
client.deleteSecret("api/keys", DeleteOptions.builder()
        .destroy(true)
        .build());
```

## Replication Setup

SecureVault supports a leader-follower replication model for high availability and improved read performance. In this model:

- The **leader** node accepts write operations and replicates changes to followers
- **Follower** nodes serve read operations and receive updates from the leader
- All nodes participate in the cluster for high availability

### Replication Architecture

```
    Write Requests                 Read Requests
         ↓                          ↓   ↓   ↓
    +---------+     Replication    +---------+
    |         |-------------------→|         |
    |  Leader |-------------------→| Follower|
    |         |-------------------→|         |
    +---------+                    +---------+
         ↑                              ↑
    +---------+                    +---------+
    |Storage  |                    |Storage  |
    +---------+                    +---------+
```

### Configuring a Leader Node

Create a leader configuration file:

```yaml
# leader-config.yaml
server:
  address: "0.0.0.0"
  port: 8200
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"

storage:
  type: "file"
  path: "/var/lib/securevault/data"

auth:
  token_ttl: "24h"

replication:
  mode: "leader"
  cluster_addr: "10.0.1.10:8201"  # Replication endpoint
  consistency: "strong"           # or "eventual"
  peers:                          # List of follower nodes
    - "10.0.1.11:8201"
    - "10.0.1.12:8201"
```

Start the leader node:

```bash
./bin/securevault server --config leader-config.yaml
```

### Configuring a Follower Node

Create a follower configuration file:

```yaml
# follower-config.yaml
server:
  address: "0.0.0.0"
  port: 8200
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"

storage:
  type: "file"
  path: "/var/lib/securevault/data"

auth:
  token_ttl: "24h"

replication:
  mode: "follower"
  cluster_addr: "10.0.1.11:8201"  # Replication endpoint
  peers:                          # Leader node address
    - "10.0.1.10:8201"
```

Start the follower node:

```bash
./bin/securevault server --config follower-config.yaml
```

### Replication Verification

To verify replication is working correctly:

1. Create a secret on the leader node
2. Verify the secret is available on follower nodes (after replication)
3. Check replication status via the API or CLI

```bash
# Check replication status
curl -H "X-Vault-Token: $TOKEN" http://leader-ip:8200/v1/sys/replication/status

# From CLI
./bin/securevault status replication
```

### Replication Consistency

SecureVault provides two consistency modes:

1. **Strong consistency**: Ensures changes are replicated to all followers before confirming writes
2. **Eventual consistency**: Faster performance, but followers may temporarily serve stale data

Configure this in the `replication.consistency` setting.

## Security Considerations

### TLS Configuration

Always use TLS in production environments:

```yaml
server:
  # ...
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
```

Use strong cipher suites and TLS 1.2+ for secure communication.

### Token Security

- Use short-lived tokens with appropriate TTLs
- Never store tokens in source code or unencrypted configuration files
- Use environment variables or secure credential managers to provide tokens to applications
- Implement token rotation policies

### Network Security

- Place SecureVault servers in a private network segment
- Use firewalls to restrict access to the API endpoints
- Configure a load balancer with WAF protection for public-facing endpoints
- Consider using a VPN for administrative access

### Secure Storage

For production environments:

- Use encrypted filesystems for file-based storage
- For database storage, enable TLS/SSL connections and encryption-at-rest
- Limit database access to the vault server only

### Least Privilege Access

- Create specific policies for different applications and users
- Grant minimal permissions required for each user/application
- Regularly audit and review access policies

Example of a minimal policy for an application:

```yaml
name: "app-xyz-db-access"
description: "Policy for App XYZ database access"
rules:
  - path: "secret/database/xyz/*"
    capabilities: ["read"]
  - path: "secret/app/xyz/*"
    capabilities: ["read", "list"]
```

### Security Hardening Checklist

- [ ] Enable TLS with strong ciphers
- [ ] Use short-lived tokens with minimal permissions
- [ ] Place servers in a secure network segment
- [ ] Enable audit logging
- [ ] Implement infrastructure firewall rules
- [ ] Use encrypted storage for secrets
- [ ] Regular security patches for OS and dependencies
- [ ] Implement IP-based access controls
- [ ] Set up monitoring and alerting

## Backup and Recovery

### Backup Types

SecureVault supports two types of backups:

1. **Snapshot backups**: Complete point-in-time backup of all secrets and configuration
2. **Incremental backups**: Backup of changes since the last snapshot

### Creating a Snapshot Backup

```bash
# CLI command
./bin/securevault backup create --output /path/to/backup/vault-backup.snap

# API request
curl -X POST -H "X-Vault-Token: $TOKEN" \
     http://127.0.0.1:8200/v1/sys/backup/snapshot \
     -o vault-backup.snap
```

### Restoring from a Backup

**Important**: Restoring will overwrite existing data. Ensure the service is stopped before restoring.

```bash
# Stop the service
systemctl stop securevault

# CLI command
./bin/securevault backup restore --input /path/to/backup/vault-backup.snap

# Restart the service
systemctl start securevault
```

### Backup Best Practices

1. **Regular Schedule**: Implement automated backup schedules
2. **Secure Storage**: Store backups in an encrypted, off-site location
3. **Rotation**: Maintain multiple backup generations
4. **Testing**: Regularly test restore procedures
5. **Auditing**: Keep records of backup/restore operations

### Storage Backend Backups

In addition to the snapshot functionality, you should also back up the underlying storage:

- **File backend**: Copy the data directory
- **Database backends**: Use database backup tools (e.g., pg_dump for PostgreSQL)

## Troubleshooting

### Common Issues

#### Connection Refused

**Symptoms**: Client cannot connect to the server, receiving "connection refused" errors.

**Solutions**:

1. Verify the server is running:
   ```bash
   ps aux | grep securevault
   ```

2. Check listening address and port:
   ```bash
   netstat -tlnp | grep 8200
   ```

3. Check firewall rules:
   ```bash
   sudo iptables -L | grep 8200
   ```

#### Authentication Failures

**Symptoms**: Receiving "permission denied" or "invalid token" errors.

**Solutions**:

1. Verify token is correct:
   ```bash
   curl -H "X-Vault-Token: $TOKEN" http://127.0.0.1:8200/v1/auth/token/lookup-self
   ```

2. Check if token has expired or is revoked
3. Ensure token has appropriate policies attached

#### Replication Issues

**Symptoms**: Changes on leader not appearing on followers, replication lag.

**Solutions**:

1. Check replication status:
   ```bash
   ./bin/securevault status replication
   ```

2. Verify network connectivity between nodes
3. Check replication logs for errors
4. Try restarting the follower node
## Architecture

SecureVault's architecture consists of several core components working together to provide secure secret management:

### System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                     SecureVault System                          │
│                                                                 │
│  ┌───────────┐     ┌──────────────────────────────────────┐    │
│  │           │     │            Server (Go)               │    │
│  │           │     │  ┌────────────┐    ┌──────────────┐  │    │
│  │  Clients  │━━━━━┿━▶│API Gateway │━━━▶│Authentication│  │    │
│  │           │     │  └─────┬──────┘    └──────┬───────┘  │    │
│  │           │     │        │                  │          │    │
│  └───────────┘     │        ▼                  ▼          │    │
│                    │  ┌────────────┐    ┌──────────────┐  │    │
│                    │  │   Policy   │◀━━━┿━▶    Secret   │  │    │
│                    │  │Enforcement │    │  Management  │  │    │
│                    │  └─────┬──────┘    └──────┬───────┘  │    │
│                    │        │                  │          │    │
│                    │        ├──────────────────┘          │    │
│                    │        ▼                             │    │
│                    │  ┌────────────┐      ┌────────────┐  │    │
│                    │  │ Replication│━━━━━▶│   Storage   │  │    │
│                    │  │   Engine   │      │   Backend   │  │    │
│                    │  └────────────┘      └────────────┘  │    │
│                    │                                      │    │
│                    └──────────────────────────────────────┘    │
│                                                                │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

1. **API Gateway**: Handles HTTP requests, enforces TLS, and routes to appropriate services
2. **Authentication Service**: Verifies tokens and credentials
3. **Policy Enforcement**: Applies access control rules based on paths and capabilities
4. **Secret Management**: Handles CRUD operations for secrets and versioning
5. **Replication Engine**: Synchronizes data across nodes in a cluster
6. **Storage Backend**: Persists encrypted secrets using one of several options:
   - File Storage: Local encrypted file storage
   - Database Storage: MySQL, PostgreSQL storage options
   - Encryption Layer: AES-256-GCM encryption for all secrets
7. **Clients**: Native implementations for different languages
   - Go Client
   - Java Client

### Data Flow

1. Clients authenticate with the server using tokens
2. API Gateway validates requests and forwards to appropriate internal service
3. Authentication Service validates tokens and permissions
4. Policy Enforcement checks access permissions for the requested operation
5. Secret Management handles the actual secret operations
6. Storage Backend securely persists the data
7. Replication Engine ensures changes are propagated to follower nodes

### Security Design

* **Encryption in Transit**: TLS for all communications
* **Encryption at Rest**: AES-256-GCM for all stored secrets
* **Token-based Authentication**: Short-lived access tokens bound to policies
* **Policy-based Authorization**: Fine-grained access control rules
* **Audit Logging**: Detailed logging of all operations for compliance
## Contributing

Contributions to SecureVault are welcome! This section outlines the process for contributing to the project and guidelines to follow.

### Development Prerequisites

* Go 1.20+
* JDK 17+ (for Java client)
* Git
* Docker (recommended for integration testing)

### Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/securevault.git
   cd securevault
   ```
3. Add the original repository as upstream:
   ```bash
   git remote add upstream https://github.com/original-owner/securevault.git
   ```
4. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Code Style Guidelines

#### Go Code

* Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
* Use `gofmt` to format your code before committing
* Run `golint` and `go vet` to catch common issues
* Add tests for new functionality
* Aim for at least 80% test coverage for new code

```bash
# Format code
gofmt -s -w .

# Run linter
golint ./...

# Run static analysis
go vet ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

#### Java Code

* Follow the [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)
* Use Maven's formatter plugin for consistent formatting
* Add JavaDoc comments for all public methods and classes
* Write JUnit tests for new functionality

```bash
# Format code
cd clients/java
mvn formatter:format

# Run tests
mvn test
```

### Pull Request Process

1. Update the documentation (README.md, etc.) with details of your changes
2. Run all tests and ensure they pass
3. Update any examples to reflect your changes if needed
4. Submit a pull request against the `main` branch of the original repository
5. The PR should clearly describe the problem and solution
6. Ensure all CI checks pass on your PR

### Code Review

* All submissions require review by at least one project maintainer
* Maintainers may request changes before merging
* Be responsive to feedback and be prepared to make requested changes

### Commit Messages

Follow these guidelines for commit messages:

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests after the first line

Example:
```
Add Java client support for secret versioning

- Implement version-aware read operations
- Add metadata retrieval for versions
- Update documentation with examples

Fixes #123
```

### Testing Guidelines

* Write unit tests for all new code
* Write integration tests for API endpoints
* Set up local test environment using Docker for integration tests
* Mock external dependencies in unit tests

### Licensing

By contributing to SecureVault, you agree that your contributions will be licensed under the project's MIT License.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
