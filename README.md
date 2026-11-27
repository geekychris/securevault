![Vaultrix](assets/vaultrix-logo.png)

# Vaultrix — Secure Secrets Management

Vaultrix is a secrets management system that provides encrypted storage, hierarchical access control, versioned secrets, multi-node replication, and client libraries for Go, Java, Python, and Rust.

## Features

- **Seal/Unseal** — Master key split via Shamir's Secret Sharing; vault starts sealed after every restart
- **Encryption at Rest** — AES-256-GCM for all secrets, metadata, and tokens
- **Policy-Based Access Control** — Path-based rules with `read`, `create`, `update`, `delete`, `list` capabilities
- **Multi-Policy Tokens** — Compose fine-grained policies per service for cross-team secret sharing
- **Secret Versioning** — Every write creates a new version; read any previous version or the latest
- **Audit Logging** — Every operation recorded with timestamp, token, path, and result
- **Leader-Follower Replication** — Write to the leader, read from any node
- **Web UI** — Built-in browser interface at `/ui/` for managing secrets, policies, and tokens
- **Rate Limiting** — Configurable token-bucket rate limiter
- **Client Libraries** — Go, Java, Python, Rust
- **Docker & Kubernetes** — Dockerfile, 3-node compose cluster, and K8s manifests included

## Quick Start

```bash
# Build
go build -o bin/securevault ./cmd/server

# Start
./bin/securevault -config configs/dev-config.yaml &

# Initialize (returns unseal keys + root token)
curl -s -X POST http://127.0.0.1:8200/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{"secret_shares": 5, "secret_threshold": 3}'

# Store your first secret
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/db/creds \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"data": {"username": "admin", "password": "s3cret"}}'

# Read it back
curl -s http://127.0.0.1:8200/v1/secret/app/db/creds \
  -H "X-Vault-Token: $ROOT_TOKEN"

# Open the Web UI
open http://127.0.0.1:8200/ui/
```

> After initialization the vault is unsealed and ready. The unseal keys are needed after a **restart** — see [Seal/Unseal](#sealunseal).

## Architecture

```mermaid
graph TB
    subgraph Clients
        GO[Go Client]
        JAVA[Java Client]
        PY[Python Client]
        RUST[Rust Client]
        UI[Web UI]
    end

    subgraph Vaultrix Server
        API[REST API<br/>Rate Limiter + TLS]
        AUTH[Token Auth]
        POLICY[Policy Engine]
        SECRETS[Secret Manager<br/>Versioning]
        AUDIT[Audit Logger]
        SEAL[Seal Manager<br/>Shamir SSS]
        REPL[Replication Engine]
    end

    subgraph Storage
        FILE[File Backend<br/>AES-256-GCM]
    end

    GO & JAVA & PY & RUST & UI -->|HTTP + X-Vault-Token| API
    API --> AUTH --> POLICY --> SECRETS
    SECRETS --> FILE
    SECRETS --> REPL
    API --> AUDIT
    SEAL -.->|encryption key| FILE
```

```mermaid
graph LR
    subgraph Cluster
        LEADER[Leader Node<br/>port 8200]
        F1[Follower 1<br/>port 8210]
        F2[Follower 2<br/>port 8220]
    end

    WRITES[Write Requests] --> LEADER
    LEADER -->|Replicate| F1
    LEADER -->|Replicate| F2
    READS[Read Requests] --> F1 & F2
```

## System Requirements

| Component | Minimum |
|-----------|---------|
| Go | 1.22+ |
| Java (client) | 21+ |
| Rust (client) | 1.70+ |
| Python (client) | 3.9+ |
| Docker (optional) | 20+ |

## Seal/Unseal

Vaultrix uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) to protect the master encryption key. On first run, you **initialize** the vault which generates key shares. After any restart, the vault is **sealed** and you must submit enough key shares to unseal it.

```mermaid
stateDiagram-v2
    [*] --> Uninitialized
    Uninitialized --> Unsealed: POST /v1/sys/init<br/>(returns keys + root token)
    Unsealed --> Sealed: POST /v1/sys/seal<br/>or server restart
    Sealed --> Unsealed: POST /v1/sys/unseal<br/>(submit threshold keys)
    Sealed --> Sealed: All API calls return 503
```

```bash
# Initialize (once)
curl -X POST http://127.0.0.1:8200/v1/sys/init \
  -d '{"secret_shares": 5, "secret_threshold": 3}'

# After restart — submit 3 of 5 keys
curl -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"key": "key-1..."}'
curl -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"key": "key-2..."}'
curl -X POST http://127.0.0.1:8200/v1/sys/unseal -d '{"key": "key-3..."}'
# → {"sealed": false}
```

### Rotating unseal shares

When a share-holder leaves, or you simply want to change the threshold, use
`rotate-shares` to re-split the master key into a brand-new set of shares
without re-encrypting any stored secrets. The vault must be unsealed and the
request must carry a token with `update` capability on `sys/rotate-shares`
(the root policy already has this). Rotation immediately invalidates every
previously issued share — see [the key-rotation runbook](docs/runbooks/key-rotation.md)
for the full procedure and operational guidance.

```bash
curl -X POST http://127.0.0.1:8200/v1/sys/rotate-shares \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"new_secret_shares": 5, "new_secret_threshold": 3}'
# → {"keys": ["..."], "threshold": 3, "num_shares": 5}
```

```go
resp, err := client.RotateShares(ctx, 5, 3)
```

## REST API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/sys/init` | Initialize vault |
| `POST` | `/v1/sys/unseal` | Submit unseal key |
| `POST` | `/v1/sys/seal` | Seal vault |
| `POST` | `/v1/sys/rotate-shares` | Re-share the master key under a new threshold/share set |
| `GET` | `/v1/sys/seal-status` | Seal status |
| `GET` | `/v1/health` | Health check (200 unsealed, 503 sealed) |
| `GET` | `/v1/sys/health` | Vault-compatible health: 200 active, 429 standby, 501 uninitialized, 503 sealed; `standbyok`, `activecode`, `standbycode`, `sealedcode`, `uninitcode` override |
| `POST` | `/v1/secret/{path}` | Write secret |
| `GET` | `/v1/secret/{path}` | Read latest version |
| `GET` | `/v1/secret/versions/{v}/{path}` | Read specific version |
| `DELETE` | `/v1/secret/{path}` | Soft-delete the current version (`?versions=1,2` for others); recoverable |
| `POST` | `/v1/secret/undelete/{path}` | Restore soft-deleted versions (`{"versions": [1]}`, default current) |
| `DELETE` | `/v1/secret/{path}?destroy=true` | Destroy versions permanently (all, or `&versions=...`) |
| `GET` | `/v1/secret/list/{path}` | List secrets |
| `GET` | `/v1/secret/metadata/{path}` | Secret metadata |
| `POST` | `/v1/auth/token/create` | Create a child token (subset of the caller's policies; default: all of them) |
| `GET` | `/v1/auth/token/lookup-self` | Lookup current token |
| `POST` | `/v1/auth/token/renew-self` | Renew token |
| `POST` | `/v1/auth/token/revoke-self` | Revoke token |
| `POST` | `/v1/policies` | Create policy |
| `GET` | `/v1/policies/{name}` | Get policy |
| `PUT` | `/v1/policies/{name}` | Update policy |
| `DELETE` | `/v1/policies/{name}` | Delete policy |
| `GET` | `/v1/policies` | List policies |
| `GET` | `/v1/audit/events` | Query audit log |

Semantics worth knowing, all as in Vault:

- **Tokens.** The root token from `init` never expires; revoke it once you have policy-scoped admin tokens. Other tokens get `auth.token_ttl` (default 1h) and can't be created or renewed past `auth.token_max_ttl` (default 768h) after creation. A child token can only carry policies its parent has (root excepted) and never outlives its parent.
- **Accessors.** Secret metadata (`created_by`, `deleted_by`) and the audit log record a token's accessor (`accessor:<hex>`, also returned by `token/create` and `lookup-self`), never the token.
- **Deletes.** A plain `DELETE` is a soft delete: reads return 404 until `undelete`. Only `destroy=true` removes data.
- **Paths.** Secret paths must be relative with no empty, `.` or `..` segments; the first segments `metadata`, `versions`, `list` and `undelete` are reserved by the API. Policy names are `[A-Za-z0-9][A-Za-z0-9_.-]*`; the `root` policy can't be changed or deleted.

## Client Libraries

### Go

```go
client, _ := securevault.NewClient("http://127.0.0.1:8200", rootToken)

// Write
client.WriteSecret(ctx, "app/db/creds", map[string]interface{}{
    "password": "s3cret",
})

// Read
secret, _ := client.ReadSecret(ctx, "app/db/creds")
fmt.Println(secret.Data["password"])

// Read specific version
v1, _ := client.ReadSecret(ctx, "app/db/creds", securevault.ReadOptions{Version: 1})

// Seal/Unseal
status, _ := client.GetSealStatus(ctx)
client.Unseal(ctx, "unseal-key-hex...")
```

### Java

```java
SecureVaultClient client = SecureVaultClient.builder()
    .address("http://127.0.0.1:8200")
    .token(rootToken)
    .build();

// Write
client.writeSecret("app/db/creds", Map.of("password", "s3cret"));

// Read
Map<String, Object> secret = client.readSecret("app/db/creds");

// Create policy + token
Policy policy = Policy.builder().name("reader").build();
policy.addRule("app/**", List.of("read", "list"));
client.createPolicy(policy);

TokenResponse token = client.createToken(
    TokenCreateOptions.builder()
        .withPolicies(List.of("reader"))
        .withTtl("8h")
        .build());
```

### Python

```python
from securevault import SecureVaultClient

client = SecureVaultClient("http://127.0.0.1:8200", root_token)

client.write_secret("app/db/creds", {"password": "s3cret"})
secret = client.read_secret("app/db/creds")
print(secret.data["password"])
```

### Rust

```rust
use securevault_client::SecureVaultClient;

let client = SecureVaultClient::new("http://127.0.0.1:8200", &root_token);

let mut data = HashMap::new();
data.insert("password".into(), json!("s3cret"));
client.write_secret("app/db/creds", data)?;

let secret = client.read_secret("app/db/creds")?;
println!("{}", secret.data["password"]);
```

## Policies & Cross-Team Sharing

Policies are composable building blocks. A token can have **multiple policies**, and its effective access is the **union** of all of them.

```mermaid
graph LR
    subgraph Policies
        P1[backend-service<br/>app/db/*, app/cache/*]
        P2[payments-service<br/>app/api/*]
        P3[shared-infra<br/>shared/logging/*, shared/messaging/*]
        P4[auth-signing<br/>shared/auth/*]
    end

    subgraph Tokens
        T1[Backend Token]
        T2[Payments Token]
    end

    P1 --> T1
    P3 --> T1
    P2 --> T2
    P3 --> T2
    P4 --> T2
```

```bash
# Create a shared policy
curl -X POST http://127.0.0.1:8200/v1/policies \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"policy": {"name": "shared-infra", "rules": [
    {"path": "shared/logging/*", "capabilities": ["read", "list"]},
    {"path": "shared/messaging/*", "capabilities": ["read", "list"]}
  ]}}'

# Create a token with multiple policies
curl -X POST http://127.0.0.1:8200/v1/auth/token/create \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"policy_ids": ["backend-service", "shared-infra"], "ttl": "8h"}'
```

### Path Patterns

| Pattern | Matches |
|---------|---------|
| `app/db/credentials` | Exactly that path |
| `app/db/*` | One level under `app/db/` |
| `app/**` | Everything under `app/` at any depth |
| `*` | Everything (root/admin only) |

## Secret Versioning

Every write to the same path creates a new version. Previous versions are preserved.

```bash
# Write v1
curl -X POST .../v1/secret/app/key -d '{"data": {"val": "one"}}'
# Write v2
curl -X POST .../v1/secret/app/key -d '{"data": {"val": "two"}}'

# Read latest → v2
curl .../v1/secret/app/key
# Read v1
curl .../v1/secret/versions/1/app/key
# Metadata
curl .../v1/secret/metadata/app/key
# → {"current_version": 2, "versions": {"1": {...}, "2": {...}}}
```

## Docker

```bash
# Single node
docker build -t vaultrix .
docker run -p 8200:8200 vaultrix

# 3-node cluster
docker compose -f docker-compose.cluster.yml up --build
```

## Kubernetes

**In the lab (cloud-stack):** a single-node install with a persistent volume, see [docs/DEPLOY.md](docs/DEPLOY.md). From a cloud-stack checkout: `deploy/app/install.sh geekychris/securevault spark`; standalone against your current `kubectl` cluster: `scripts/install-k8s.sh`.

The example leader/follower cluster:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/leader.yaml
kubectl apply -f deploy/k8s/followers.yaml
```

## Replication, Write Routing & Failover

### How it works

- **Writes** can be sent to **any node**. Followers automatically forward writes to the leader.
- **Reads** are served locally from any node (leader or follower).
- **Replication** happens from leader to all followers after each write.
- **Failover**: if the leader goes down, a follower automatically promotes itself to leader.

```mermaid
sequenceDiagram
    participant Client
    participant Follower
    participant Leader
    participant Follower2

    Note over Client,Follower: Client can write to any node
    Client->>Follower: POST /v1/secret/app/key
    Note over Follower: I'm a follower → forward
    Follower->>Leader: POST /v1/secret/app/key (forwarded)
    Leader->>Leader: Auth + Encrypt + Store
    Leader-->>Follower: 204 No Content
    Leader->>Follower: Replicate data
    Leader->>Follower2: Replicate data
    Follower-->>Client: 204 + X-Vault-Forward: true

    Note over Client,Follower2: Reads are always local
    Client->>Follower2: GET /v1/secret/app/key
    Follower2-->>Client: {"data": {...}}
```

### What replicates, and the limits

- **Only secret data replicates**: writes, deletes, destroys and undeletes, delivered to each follower in order and exactly once while the follower is reachable (the leader retries a follower from where it stopped).
- **Tokens and policies are per node.** Each node is initialized and unsealed with its own keys and root token, so a token issued by the leader is not valid for reads on a follower.
- **The replication log is in memory** (last 10,000 operations). A follower that is down for longer, or a leader restart, needs a manual resync (copy the data directory).
- **Clustered nodes need `replication.shared_secret`**; the server refuses to start in `leader` or `follower` mode without it. Replication traffic is plain HTTP unless TLS is enabled.
- **Failover has no consensus.** Every follower whose leader is unreachable for `failover_timeout_sec` promotes itself, and a returning leader keeps its role, so a partition can produce two leaders. Use it for read replicas and manual failover; for automatic HA, Vault's Raft storage is the reference design.

### Failover

```mermaid
sequenceDiagram
    participant Follower
    participant Leader

    loop Every health_check_sec
        Follower->>Leader: GET /v1/health
        Leader-->>Follower: 200 OK
    end

    Note over Leader: Leader crashes
    Follower->>Leader: GET /v1/health
    Leader--xFollower: Connection refused

    Note over Follower: Down for > failover_timeout_sec

    Follower->>Follower: Promote to leader
    Note over Follower: Now accepts writes directly
```

### Configuration

**Leader node** (`leader-config.yaml`):
```yaml
replication:
  mode: "leader"
  cluster_addr: "10.0.1.10:8201"      # Address for replication traffic
  leader_api_addr: "http://10.0.1.10:8200"  # Public API address (for forwarding)
  peers:                                # Follower cluster addresses
    - "10.0.1.11:8201"
    - "10.0.1.12:8201"
  shared_secret: "your-secret-here"    # Authenticates replication traffic
  health_check_sec: 5                  # How often followers check leader (default: 5)
  failover_timeout_sec: 30             # Seconds before failover (default: 30)
```

**Follower node** (`follower-config.yaml`):
```yaml
replication:
  mode: "follower"
  cluster_addr: "10.0.1.11:8201"
  leader_api_addr: "http://10.0.1.10:8200"  # Where to forward writes
  peers:
    - "10.0.1.10:8201"                # Leader's cluster address
  shared_secret: "your-secret-here"    # Must match leader
  health_check_sec: 5
  failover_timeout_sec: 30
```

### Key configuration fields

| Field | Required | Description |
|-------|----------|-------------|
| `mode` | Yes | `"leader"`, `"follower"`, or `"standalone"` |
| `cluster_addr` | Yes (cluster) | This node's address for replication traffic (port 8201) |
| `leader_api_addr` | Recommended | Leader's public API address (e.g., `http://10.0.1.10:8200`). Followers use this to forward writes. |
| `peers` | Yes (cluster) | Leader: list of follower cluster addrs. Follower: list with leader's cluster addr. |
| `shared_secret` | Yes (cluster) | Shared secret for authenticating replication traffic. Must be the same on all nodes. |
| `health_check_sec` | No | How often followers health-check the leader (default: 5) |
| `failover_timeout_sec` | No | How long leader must be down before a follower promotes itself (default: 30) |

### Load balancer integration

The health endpoint reports each node's role:

```bash
curl http://any-node:8200/v1/health
# → {"status": "ok", "role": "leader", "leader_addr": "http://10.0.1.10:8200", ...}
# → {"status": "ok", "role": "follower", "leader_addr": "http://10.0.1.10:8200", ...}
```

You can use this to configure a load balancer to route writes to the leader and reads to any node. But it's not strictly necessary — followers forward writes transparently.

### Running a 3-node cluster with Docker

```bash
docker compose -f docker-compose.cluster.yml up --build
# Leader: http://localhost:8200
# Follower 1: http://localhost:8210
# Follower 2: http://localhost:8220
```

## Testing

```bash
# Unit tests (all packages)
go test ./pkg/... -count=1

# 3-node replication, write forwarding, and failover tests
go test ./pkg/server/ -run "TestThreeNode|TestWriteForwarding|TestFailover" -v

# Build and run all examples (REST, Go, Python, Java)
bash examples/run-all-examples.sh

# Docker 3-node cluster test (30 assertions: replication + forwarding + failover)
bash deploy/test-cluster.sh
```

## Web UI

The web UI is served at `/ui/` and embedded in the binary — no separate build step.

- Login with any token (root or restricted)
- Browse secrets hierarchically, view/edit key-value pairs
- Create and manage policies and tokens
- View audit log
- Seal/unseal controls

Restricted tokens see an "Access Denied" at root — type the path they have access to (e.g., `app/db`) in the search box.

## Walkthrough

See [`examples/walkthrough/`](examples/walkthrough/README.md) for a complete end-to-end guide covering:

1. **Initial setup** — initialize, unseal, distribute keys
2. **Admin creates secrets & policies** — store secrets, create composable policies, generate multi-policy tokens
3. **Developer uses secrets** — via UI, curl, or client library
4. **Request access to a shared secret** — developer asks admin, admin adds policy to token
5. **Self-service secret management** — team leads create/rotate secrets under their path
6. **After a restart** — key holders unseal the vault

## Project Structure

```
cmd/server/          Server entry point
pkg/
  server/            HTTP handlers, auth, replication
  storage/           File backend (AES-256-GCM encrypted)
  policy/            Policy engine with path matching
  seal/              Shamir's Secret Sharing + seal manager
  audit/             Audit logger
  errors/            Typed error system
  ui/                Embedded web UI
clients/
  go/                Go client library
  java/              Java client (Maven)
  python/            Python client (sync + async)
  rust/              Rust client (reqwest + serde)
examples/
  walkthrough/       End-to-end guide with bash + Java
  go/                Go client example
  python/            Python client example
  rust/              Rust client example
deploy/
  configs/           Docker cluster configs
  k8s/               Kubernetes manifests
  test-cluster.sh    3-node Docker replication test
```

## Security Notes

- Unseal keys and root tokens are shown **once** during initialization — save them securely
- Revoke the root token after initial setup; use policy-scoped tokens for daily operations
- Enable TLS in production (`server.tls.enabled: true`)
- Enable audit logging (`audit.enabled: true`)
- Use short TTLs on tokens and renew programmatically
- Inject tokens via environment variables — never hardcode

## License

MIT
