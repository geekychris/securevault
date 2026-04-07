# Vaultrix: Token Management and Server Setup Guide

This document provides comprehensive guidance on setting up a Vaultrix server, managing tokens, and implementing user authentication best practices.

## 1. Initial Server Setup and Requirements

### Prerequisites

- **Operating System**: Linux, macOS, or Windows Server
- **Runtime**: Java 21+ (OpenJDK or Corretto 23 recommended)
- **Storage**: Encrypted file-based storage
- **Network**: Dedicated port (default: 8200) with appropriate firewall rules
- **Hardware**: Minimum 2 CPU cores, 4GB RAM for production deployments

### Configuration File Structure

Vaultrix uses a YAML configuration file (`config.yaml`) for server settings:

```yaml
server:
  address: "0.0.0.0"  # Listen on all interfaces
  port: 8200
  dev_mode: false     # Set to true only for development
  test_mode: false    # Controls automatic root token creation

storage:
  type: "file"
  path: "/var/lib/securevault/data"
    username: "vault_user"
    password: "vault_password"
    ssl_mode: "require"
  # For File storage:
  file:
    path: "/opt/securevault/data"

tls:
  enabled: true
  cert_file: "/opt/securevault/tls/server.crt"
  key_file: "/opt/securevault/tls/server.key"

tokens:
  default_ttl: "24h"       # Default token time-to-live
  max_ttl: "72h"           # Maximum allowed TTL
  enable_root: true        # Whether root token creation is allowed

logging:
  level: "info"            # Options: debug, info, warn, error
  format: "json"           # Options: json, text
  file: "/var/log/securevault/server.log"
```

### Directory Structure

Recommended production directory layout:

```
/opt/securevault/
├── bin/              # Executable files
├── config/           # Configuration files
│   └── config.yaml
├── data/             # Data storage (if using file backend)
├── logs/             # Log files
└── tls/              # TLS certificates and keys
    ├── server.crt
    ├── server.key
    └── ca.crt        # If using a custom CA
```

## 2. Certificate and Key Generation

Vaultrix requires TLS for secure communication. Here's how to generate the necessary certificates:

### Self-Signed Certificates (Development Only)

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate self-signed certificate (valid for 1 year)
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=securevault.local"
```

### Production Certificates

For production, use certificates signed by a trusted Certificate Authority (CA) or your organization's internal CA:

1. **Generate a Certificate Signing Request (CSR)**:
   ```bash
   openssl genrsa -out server.key 2048
   openssl req -new -key server.key -out server.csr -subj "/CN=vault.yourdomain.com"
   ```

2. **Submit the CSR to your CA for signing**

3. **Install the signed certificate**:
   Place the signed certificate file (`server.crt`) and any required CA certificates in the TLS directory.

### Certificate Requirements

- Certificates must be in PEM format
- Private keys must be unencrypted (no passphrase)
- If using custom CAs, include the full certificate chain
- Configure clients to trust the CA certificates

## 3. Root Token Creation Process

The root token is a privileged credential with full administrative access to the Vaultrix server.

### Automatic Root Token Creation (TEST_MODE)

When Vaultrix is started with `test_mode: true` in the configuration:

- A root token with ID `s.root` is automatically generated
- This token is assigned the "root" policy with all capabilities
- The token is set to expire after the default TTL (typically 24 hours)
- The root token is written to the server logs

```log
INFO  [2025-05-02 08:18:51] Vaultrix server initialized in TEST_MODE
INFO  [2025-05-02 08:18:51] Root token created: s.root
INFO  [2025-05-02 08:18:51] Root token expiration: 2025-05-03 08:18:51 UTC
```

### Manual Root Token Creation (Production)

For production environments, root tokens must be created manually:

1. **Initialize the Server**:
   ```bash
   securevault server init --config=/path/to/config.yaml
   ```

2. **Create a Root Token** (requires physical access to the server):
   ```bash
   securevault token create-root
   ```

3. **Save the Token Securely**:
   The token will be displayed once and cannot be retrieved later.

### Root Token Policies

The root token is automatically assigned the "root" policy, which grants all capabilities (`create`, `read`, `update`, `delete`, `list`) on all paths (`*`).

```json
{
  "name": "root",
  "rules": {
    "path": {
      "*": {
        "capabilities": ["create", "read", "update", "delete", "list"]
      }
    }
  }
}
```

### Root Token Management

- Store the root token securely (e.g., in a hardware security module or secure password manager)
- Use the root token only for initial setup and emergency access
- Create administrator tokens with more limited scopes for day-to-day administration
- Rotate root tokens regularly (recommended: every 30-90 days)

## 4. User Management and Authentication

Vaultrix uses a token-based authentication system with policy-based access control.

### Token Types

1. **Root Token**: Complete access to all vault functionality
2. **Service Tokens**: Long-lived tokens for applications and services
3. **Client Tokens**: Short-lived tokens for user operations

### Creating User Tokens

Tokens can be created through the API or using the client libraries:

```java
// Example using the Java client library
SecureVaultClient client = SecureVaultClient.builder()
    .withAddress("https://vault.example.com:8200")
    .withToken("s.root")  // Or another token with token creation permission
    .build();

// Create a token with specific policies and TTL
TokenCreateOptions options = TokenCreateOptions.builder()
    .withPolicies(Arrays.asList("app-read", "app-write"))
    .withTtl(Duration.ofHours(8))
    .build();
TokenResponse token = client.createToken(options);
String newTokenId = token.getTokenId();

// Looking up token information
TokenLookupResponse tokenInfo = client.lookupToken(newTokenId);
System.out.println("Token expires at: " + tokenInfo.getExpireTime());

// Renewing a token
TokenRenewOptions renewOptions = TokenRenewOptions.builder()
    .withToken(newTokenId)
    .withIncrement(Duration.ofHours(12))
    .build();
TokenResponse renewedToken = client.renewToken(renewOptions);

// Revoking a token when done with it
TokenRevokeOptions revokeOptions = TokenRevokeOptions.builder()
    .withToken(newTokenId)
    .withRevokeChild(true)
    .build();
client.revokeToken(revokeOptions);
```

### API Example
### API Example

```
POST /auth/token/create
Authorization: X-Vault-Token: [token]

{
  "policies": ["app-read", "app-write"],
  "ttl": "8h",
  "metadata": {
    "user": "alice",
    "application": "inventory-system"
  }
}
```

### Token Authentication

Clients authenticate requests by including the token in the `X-Vault-Token` HTTP header:

```
GET /secret/data/my-secret
X-Vault-Token: s.7f3b0a9b2c8d7e6f5a4b3c2d1e0f9a8b
```

The server validates:
1. Token existence in the token store
2. Token expiry status
3. Policy permissions for the requested operation

### Creating and Managing Policies

Policies define permissions on specific paths:

```json
{
  "name": "app-read",
  "rules": {
    "path": {
      "secret/data/app/*": {
        "capabilities": ["read", "list"]
      }
    }
  }
}
```

To create a policy via API:

```
POST /sys/policies/create
X-Vault-Token: [admin-token]

{
  "name": "app-read",
  "policy": "{\"path\":{\"secret/data/app/*\":{\"capabilities\":[\"read\",\"list\"]}}}"
}
```

### Managing Credentials

Vaultrix stores credentials (usernames, passwords, API keys, etc.) as encrypted secrets:

```java
// Storing credentials
Map<String, Object> credentials = new HashMap<>();
credentials.put("username", "service_account");
credentials.put("password", "complex-password-123");
credentials.put("api_key", "ak_12345abcdef");

client.writeSecret("secret/app/database", credentials);

// Retrieving credentials
Secret secret = client.readSecret("secret/app/database");
String username = (String) secret.getData().get("username");
String password = (String) secret.getData().get("password");
```

### Token Lifecycle Management

1. **Creation**: Tokens are created with specified policies and TTL
2. **Renewal**: Tokens can be renewed before expiration (extends lifetime up to max TTL)
3. **Revocation**: Tokens can be manually revoked when no longer needed
4. **Expiration**: Tokens automatically expire after their TTL

## 5. Security Best Practices

### Server Security

1. **Physical Security**:
   - Deploy on dedicated hardware or isolated virtual environments
   - Implement strict access controls to the server hardware

2. **Network Security**:
   - Use TLS 1.3 for all communications
   - Enable only required ports (typically just 8200)
   - Implement network segmentation (private network for vault servers)
   - Use a reverse proxy or load balancer for additional security layers

3. **Operating System Hardening**:
   - Use minimal, hardened OS installations
   - Regular security patching
   - Remove unnecessary services and packages
   - Implement host-based firewalls

### Token Management Best Practices

1. **Minimal Privilege Principle**:
   - Assign the minimum required permissions to each token
   - Create separate policies for different functions
   - Avoid using the root token for regular operations

2. **Token Lifecycle**:
   - Set appropriate TTLs based on use case:
     - Short TTLs (minutes to hours) for user sessions
     - Medium TTLs (hours to days) for applications
     - Longer TTLs (days to weeks) only for critical infrastructure components
   - Implement token rotation schedules
   - Revoke tokens when no longer needed

3. **Monitoring and Auditing**:
   - Enable audit logging for all token operations
   - Monitor for suspicious token creation or usage patterns
   - Alert on unauthorized access attempts
   - Regularly review token usage and permissions

### Data Protection

1. **Encryption**:
   - All secrets are encrypted at rest with AES-256-GCM
   - Enable automatic key rotation (every 30 days recommended)

2. **Backup and Recovery**:
   - Regularly backup encrypted data and configuration
   - Test restoration procedures
   - Consider replication for high availability

3. **Secrets Management**:
   - Regularly rotate secrets stored in the vault
   - Implement versioning for critical secrets
   - Use namespaces to isolate different environments or teams

### Operational Security

1. **Access Controls**:
   - Implement multi-factor authentication for administrative access
   - Use separate admin accounts for vault management
   - Implement just-in-time access for administrative functions

2. **Disaster Recovery**:
   - Maintain disaster recovery plans
   - Document emergency procedures for vault access
   - Regularly test recovery scenarios

3. **Compliance and Auditing**:
   - Maintain detailed audit logs
   - Implement compliance reporting
   - Regularly review security configurations

## Summary

Vaultrix provides a robust system for managing secrets and authentication using a token-based approach. By following the setup and configuration guidelines in this document, you can establish a secure environment for storing and accessing sensitive credentials and other secrets.

Remember that security is a continuous process - regularly review configurations, rotate credentials, and apply updates to maintain a strong security posture.

