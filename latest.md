# Vaultrix Server and Client Guide

This guide provides instructions for building and running the Vaultrix server in test mode and using the Go client to interact with it.

## Overview

Vaultrix is a secure storage system for sensitive data like secrets, credentials, and keys. It provides:

- Secure storage with encryption at rest
- Fine-grained access control
- Secret versioning
- API for programmatic access

## Building and Running the Server

### Prerequisites

- Go 1.20 or later
- Storage directory with write permissions

### Server Setup

1. **Build the server**:
   ```bash
   # Navigate to the project directory
   cd /path/to/securevault2
   
   # Build the server binary
   go build -o bin/securevault ./cmd/server
   ```

2. **Create a test configuration file** (or use the existing one):
   ```yaml
   # test-config.yaml
   server:
     address: "127.0.0.1"
     port: 8200
     tls:
       enabled: false
   
   storage:
     type: "file"
     path: "./vault-data"
   
   auth:
     token_ttl: "24h"
   
   replication:
     mode: "standalone"
   
   logging:
     level: "debug"
     format: "text"
     output: "stdout"
   ```

3. **Create the storage directory**:
   ```bash
   mkdir -p vault-data
   ```

4. **Run the server in test mode**:
   ```bash
   TEST_MODE=true ./bin/securevault -config test-config.yaml
   ```
   
   Alternatively, you can use:
   ```bash
   TESTING=true ./bin/securevault -config test-config.yaml
   ```

### Understanding Test Mode

When running with `TEST_MODE=true` or `TESTING=true`, the server automatically:

- Creates a root token `s.root` that has full administrative access
- Initializes with basic policies (including the "root" policy)
- Accepts various token formats for easier testing
- Skips certain security checks and permission validations

In test mode, the following token formats are automatically accepted:
- `s.root` - The default root token
- `root` - Simple root token
- `test` or `test-token` - Alternative test tokens
- `s.test-token-*` - Any token starting with this prefix
- `s.restricted-token-*` - Tokens with restricted permissions (for testing policies)

**Important**: Test mode should **only** be used for development and testing, never in production.

## Authentication

### Authentication in Test Mode

In test mode, the server provides several authentication options:

#### Root Token

The server is initialized with a root token: `s.root`

This token can be used for all operations and has full administrative access. You must include this token in API requests using the `X-Vault-Token` header.

#### Alternative Test Tokens

In test mode, the server also accepts these tokens with root access:
- `root`
- `test`
- `test-token`
- Any token with the prefix `s.test-token-`

Example:
```bash
# These all work in test mode
curl -H "X-Vault-Token: s.root" http://localhost:8200/v1/secret/my-secret
curl -H "X-Vault-Token: root" http://localhost:8200/v1/secret/my-secret
curl -H "X-Vault-Token: s.test-token-123" http://localhost:8200/v1/secret/my-secret
```

### Creating New Tokens

You can create new tokens with more limited permissions using the API:

```bash
curl -X POST http://localhost:8200/v1/auth/token/create \
  -H "X-Vault-Token: s.root" \
  -d '{"policy_ids": ["read-only"], "ttl": "1h"}'
```

## Available Client Libraries

Vaultrix provides client libraries for multiple programming languages:

- **Go**: Full-featured client with all operations supported
- **Java**: Complete client with object-oriented API
- **Python**: Simple client for Python applications

### Using the Go Client

#### Test Client

The project includes a test client that verifies server functionality.

1. **Run the test client**:
   ```bash
   # Using the root token
   VAULT_TOKEN=s.root VAULT_ADDR=http://127.0.0.1:8200 go run main.go
   ```

2. **Expected output**:
   The test client will:
   - Connect to the server
   - Write a test secret
   - Read the secret back
   - List secrets
   - Get metadata about the secret
   - Perform diagnostic HTTP requests

   If all operations succeed, you'll see a summary with checkmarks for each operation.

### Writing Your Own Client

You can use the Vaultrix Go client in your applications:

```go
import (
    securevault "securevault/clients/go"
)

func main() {
    client, err := securevault.NewClient(
        "http://localhost:8200",
        "s.root",
        securevault.WithTimeout(15*time.Second),
    )
    
    // Write a secret
    err = client.WriteSecret(ctx, "path/to/secret", map[string]interface{}{
        "username": "user",
        "password": "pass",
    })
    
    // Read a secret
    secret, err := client.ReadSecret(ctx, "path/to/secret")
}
```

### Using the Java Client

The Java client provides an object-oriented interface to the Vaultrix server:

```java
import com.example.securevault.SecureVaultClient;
import com.example.securevault.model.Secret;

public class Example {
    public static void main(String[] args) {
        // Create a client
        SecureVaultClient client = SecureVaultClient.builder()
            .address("http://localhost:8200")
            .token("s.root")
            .build();
            
        try {
            // Write a secret
            Map<String, Object> secretData = new HashMap<>();
            secretData.put("username", "user");
            secretData.put("password", "pass");
            client.writeSecret("app/database/credentials", secretData);
            
            // Read a secret
            Secret secret = client.readSecret("app/database/credentials");
            System.out.println("Username: " + secret.getData().get("username"));
        } finally {
            client.close();
        }
    }
}
```

### Using the Python Client

The Python client provides a simple interface for Python applications:

```python
from securevault import SecureVaultClient

# Create a client
client = SecureVaultClient(
    address="http://localhost:8200",
    token="s.root"
)

# Write a secret
client.write_secret("app/database/credentials", {
    "username": "user",
    "password": "pass"
})

# Read a secret
secret = client.read_secret("app/database/credentials")
print(f"Username: {secret['data']['username']}")
```

## API Path Formats

The path formats are consistent across all client libraries. Based on our testing, here are the correct path formats for different operations:

| Operation | Client Method | Path Format | Example |
|-----------|--------------|-------------|---------|
| Write Secret | `WriteSecret()` | `"path/to/secret"` | `"app/db/credentials"` |
| Read Secret | `ReadSecret()` | `"path/to/secret"` | `"app/db/credentials"` |
| List Secrets | `ListSecrets()` | `"list/path"` | `"list/app"` |
| Get Metadata | `GetSecretMetadata()` | `"metadata/path/to/secret"` | `"metadata/app/db/credentials"` |

## Troubleshooting

### Common Issues

1. **Authentication failures**:
   - Ensure you're using the correct token (`s.root` in test mode)
   - Check that the token hasn't expired
   
2. **Path format issues**:
   - For list operations, use the `"list/path"` format
   - For metadata operations, use the `"metadata/path/to/secret"` format or direct HTTP requests
   
3. **Permission denied**:
   - The token may not have the required permissions
   - Use the root token or create a token with appropriate policies

4. **Server not starting**:
   - Check the storage directory permissions
   - Ensure the port (8200 by default) is not already in use

## Advanced Configuration

For more advanced configuration options, see the comments in `config.yaml`. Options include:

- TLS configuration for secure communication
- Different storage backends
- Replication setup for high availability
- Custom token TTL and authentication settings

## Production Deployment Guide

When moving to production, never use test mode. Instead, follow these steps to securely deploy and manage your Vaultrix server.

### Production Server Configuration

1. **Create a production configuration file**:
   ```yaml
   # production-config.yaml
   server:
     address: "0.0.0.0"  # Or your internal network address
     port: 8200
     tls:
       enabled: true
       cert_file: "/path/to/tls/cert.pem"
       key_file: "/path/to/tls/key.pem"
   
   storage:
     type: "file"
     path: "/secure/vault/data"
   
   auth:
     token_ttl: "720h"  # 30 days default TTL
   
   replication:
     mode: "standalone"  # Or "leader" for HA setup
   
   logging:
     level: "info"
     format: "json"
     output: "/var/log/securevault/server.log"
   ```

2. **Secure the storage location**:
   ```bash
   # Create storage with restricted permissions
   sudo mkdir -p /secure/vault/data
   sudo chown vault:vault /secure/vault/data
   sudo chmod 0700 /secure/vault/data
   ```

3. **Run the server without test mode**:
   ```bash
   ./bin/securevault -config production-config.yaml
   ```

### Initial Server Initialization

On first startup, you need to initialize the Vaultrix server:

1. **Generate the root token and unseal keys**:
   ```bash
   curl -X POST https://vault.example.com:8200/v1/sys/init \
     -H "Content-Type: application/json" \
     -d '{
       "secret_shares": 5,
       "secret_threshold": 3
     }'
   ```

   This will return a JSON response containing:
   - The generated root token
   - Unseal keys (if using the sealed storage feature)

   Example response:
   ```json
   {
     "root_token": "s.FMHqKsTTkmQNOXIRr5m9PgXf",
     "unseal_keys_b64": [
       "HZs...Rms=",
       "IGf...Mwe=",
       "ULL...JCw=",
       "NPT...UNs=",
       "HHL...Vg0="
     ]
   }
   ```

2. **Store the root token and unseal keys securely**:
   - Split the root token and unseal keys among trusted administrators
   - Use separate secure storage mechanisms (hardware security modules, etc.)
   - Document the emergency access procedure

3. **Perform initial unsealing** (if using sealed storage):
   ```bash
   # Repeat this with different keys up to the threshold
   curl -X POST https://vault.example.com:8200/v1/sys/unseal \
     -H "Content-Type: application/json" \
     -d '{"key": "HZs...Rms="}'
   ```

### Managing Root and Infrastructure Tokens

#### Root Token Management

The root token has unrestricted access and should be used sparingly:

1. **Use the root token only for initial setup**:
   ```bash
   # Set the root token in your environment
   export VAULT_TOKEN=s.FMHqKsTTkmQNOXIRr5m9PgXf
   
   # Create admin policies and tokens
   curl -X POST https://vault.example.com:8200/v1/policies \
     -H "X-Vault-Token: $VAULT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "policy": {
         "name": "admin",
         "description": "Admin policy with managed permissions",
         "rules": [
           {
             "path": "secret/*",
             "capabilities": ["create", "read", "update", "delete", "list"]
           }
         ]
       }
     }'
   ```

2. **Create admin tokens**:
   ```bash
   curl -X POST https://vault.example.com:8200/v1/auth/token/create \
     -H "X-Vault-Token: $VAULT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "policy_ids": ["admin"],
       "ttl": "168h",
       "display_name": "admin-token"
     }'
   ```

3. **Revoke the root token when initial setup is complete**:
   ```bash
   curl -X POST https://vault.example.com:8200/v1/auth/token/revoke-self \
     -H "X-Vault-Token: $VAULT_TOKEN"
   ```

#### Infrastructure Token Strategy

For infrastructure components (CI/CD pipelines, services, etc.):

1. **Create specific policies for each infrastructure component**:
   ```bash
   # Example: Database credentials manager policy
   curl -X POST https://vault.example.com:8200/v1/policies \
     -H "X-Vault-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "policy": {
         "name": "db-credentials-manager",
         "description": "Policy for database credential rotation service",
         "rules": [
           {
             "path": "secret/databases/*",
             "capabilities": ["create", "read", "update", "delete"]
           }
         ]
       }
     }'
   ```

2. **Create service tokens with appropriate TTLs**:
   ```bash
   curl -X POST https://vault.example.com:8200/v1/auth/token/create \
     -H "X-Vault-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "policy_ids": ["db-credentials-manager"],
       "ttl": "720h",
       "renewable": true,
       "metadata": {
         "service": "db-credential-rotation",
         "environment": "production"
       }
     }'
   ```

3. **Set up periodic token renewal**:
   Tokens should be renewed before they expire. Create a service or scheduled task to handle token renewal:

   ```go
   func renewToken(client *securevault.Client) {
       // Schedule to run at 1/2 of the token's TTL
       for {
           tokenInfo, _ := client.RenewSelfToken("168h")
           // Schedule next renewal
           nextRenewal := tokenInfo.TTL / 2
           time.Sleep(nextRenewal)
       }
   }
   ```

### Client Token Distribution Best Practices

For application clients that need to access secrets:

1. **Prefer short-lived tokens**:
   - Issue tokens with short TTLs (1-24 hours)
   - Require regular renewal
   - Implement automatic revocation when not in use

2. **Use secure distribution channels**:
   - **Infrastructure-as-Code**: Use encrypted variables in your CI/CD system
   - **Container environments**: Use Kubernetes secrets or similar mechanisms
   - **Secure bootstrap**: Initial token acquisition via instance identity verification

3. **Implement the principle of least privilege**:
   ```bash
   # Create a policy that only allows read access to specific secrets
   curl -X POST https://vault.example.com:8200/v1/policies \
     -H "X-Vault-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "policy": {
         "name": "app-webserver",
         "description": "Read-only access to web server secrets",
         "rules": [
           {
             "path": "secret/web/config",
             "capabilities": ["read"]
           }
         ]
       }
     }'
   ```

4. **Token delivery patterns**:

   a. **Bootstrap pattern**:
      - Application starts with an initial bootstrap token
      - Uses it to authenticate and receive its service token
      - Discards the bootstrap token

   b. **Identity-based authentication**:
      - Application authenticates using platform identity (AWS IAM, Azure Managed Identity)
      - Receives a dynamically generated token based on identity

5. **Token rotation schedule**:
   - Critical infrastructure: Every 30 days
   - Services: Every 30-90 days
   - Automation scripts: Every run or daily
   - CI/CD pipelines: Every build

### Audit and Monitoring

For production deployments, enable audit logging and monitoring:

1. **Enable audit logging**:
   ```bash
   curl -X POST https://vault.example.com:8200/v1/sys/audit/file \
     -H "X-Vault-Token: $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "type": "file",
       "options": {
         "file_path": "/var/log/securevault/audit.log"
       }
     }'
   ```

2. **Monitor for unusual activity**:
   - High volume of token creation
   - Access from unusual IP addresses
   - Failed authentication attempts
   - Access outside business hours

3. **Set up alerts for security events**:
   - Root token usage
   - Policy changes
   - Token revocations
   - Server restarts

### Token Lifecycle Automation

Automate the token lifecycle to reduce manual operations:

1. **Creation**: Integrated with service deployment
2. **Distribution**: Via secure channels or identity-based retrieval
3. **Renewal**: Automated by services before expiration
4. **Revocation**: Upon service decommissioning or security events

## Security Considerations

Remember that running in test mode disables several security features:

1. Using a predictable root token
2. Accepting multiple token formats without proper validation
3. Disabling TLS by default
4. Not requiring proper initialization
5. Bypassing certain permission checks
6. Allowing unauthenticated access to some endpoints

### Production Deployment

For production deployments, always:
- DO NOT use `TEST_MODE` or `TESTING` environment variables
- Use TLS with valid certificates
- Use proper initialization with secure tokens
- Apply the principle of least privilege for access control
- Implement proper authentication and authorization checks
- Regularly rotate tokens and credentials

### Testing Restricted Policies

For testing policy restrictions, you can use tokens with the prefix `s.restricted-token-` which will have limited permissions based on the "restricted" policy. This is useful for testing access control without having to create separate tokens.

Example:
```bash
# This token will have restricted permissions
curl -H "X-Vault-Token: s.restricted-token-456" http://localhost:8200/v1/secret/app/allowed
```

