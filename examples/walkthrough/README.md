# SecureVault Walkthrough: End-to-End Secret Management

This walkthrough demonstrates the complete workflow a team would use with SecureVault, including **cross-team secret sharing**:

1. An **administrator** initializes the vault, stores service-specific and shared secrets, defines composable policies, and generates multi-policy tokens
2. **Applications and teams** use their tokens to access their own secrets AND shared secrets — while being denied access to anything outside their policies

## Prerequisites

- SecureVault server built and available at `./bin/securevault`
- `curl` and `jq` installed (for the REST scripts)
- Java 21+ and Maven 3.6+ (for the Java example)

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                        SecureVault Server                          │
│                                                                    │
│  ┌─────────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │      Secrets         │  │   Policies    │  │     Tokens        │  │
│  │                      │  │               │  │                   │  │
│  │  app/db/*      ──────┼──│ backend-svc   │  │ backend token     │  │
│  │  app/api/*     ──────┼──│ payments-svc  │  │  = backend-svc    │  │
│  │  app/cache/*         │  │               │  │  + shared-infra   │  │
│  │                      │  │ shared-infra ─┼──│                   │  │
│  │  shared/logging/* ───┼──│  (cross-team) │  │ payments token    │  │
│  │  shared/messaging/*  │  │               │  │  = payments-svc   │  │
│  │  shared/auth/*  ─────┼──│ auth-signing  │  │  + shared-infra   │  │
│  │                      │  │               │  │  + auth-signing   │  │
│  │                      │  │ devops-admin  │  │                   │  │
│  └─────────────────────┘  └──────────────┘  └──────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
     ▲          ▲          ▲                │
     │          │          │                │
  Backend   Payments    DevOps           Admin
  (2 policies) (3 policies) (1 policy)
```

### How cross-team sharing works

Policies are **composable building blocks**. A token can have **multiple policies** attached, and its effective access is the **union** of all of them.

```
backend token policies:   [backend-service, shared-infra]
                           ├── app/db/*        (from backend-service)
                           ├── app/cache/*     (from backend-service)
                           ├── shared/logging/*   (from shared-infra)
                           └── shared/messaging/* (from shared-infra)

payments token policies:  [payments-service, shared-infra, auth-signing]
                           ├── app/api/*          (from payments-service)
                           ├── shared/logging/*   (from shared-infra)  ← SAME as backend
                           ├── shared/messaging/* (from shared-infra)  ← SAME as backend
                           └── shared/auth/*      (from auth-signing)
```

Both services can read `shared/logging/datadog` because both tokens include `shared-infra`. But only payments can read `shared/auth/jwt-signing` because only its token includes `auth-signing`.

## Quick Start

```bash
# From the repository root:

# 1. Build the server
go build -o bin/securevault ./cmd/server

# 2. Run the admin setup script (starts server, creates secrets + policies)
cd examples/walkthrough
bash 01-admin-setup.sh

# 3. In another terminal, run the client script to retrieve secrets
bash 02-client-access.sh

# 4. Or run the Java client example
cd java
mvn compile exec:java
```

---

## Real-World Workflows

These workflows describe what actual people do in their day-to-day work with the vault. Each one is a complete story from the perspective of the person doing the work.

---

### Workflow 1: Initial Setup (done once by the Vault Admin)

**Who:** The security/platform team member who owns the vault infrastructure.

**When:** First time setting up the vault for your organization.

```bash
# 1. Build and start the server
go build -o bin/securevault ./cmd/server
./bin/securevault -config configs/dev-config.yaml &

# 2. Initialize — choose how many key holders you need
#    5 shares / 3 threshold means: 5 people each get a key,
#    any 3 of them must be present to unseal after a restart
curl -s -X POST http://127.0.0.1:8200/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{"secret_shares": 5, "secret_threshold": 3}'
```

Save the output. Distribute each unseal key to a different trusted person (security leads, senior engineers, CTO, etc.). The vault is now ready — it auto-unseals after first initialization.

```bash
# 3. Save the root token for the next steps, then continue to Workflow 2
ROOT_TOKEN="s.xxxxx..."   # from the init response
```

> **After initial setup is complete**, revoke the root token and create admin-level tokens with appropriate policies instead. The root token is like a master password — don't leave it lying around.

---

### Workflow 2: Admin Creates Secrets and Policies for Teams

**Who:** The vault admin or a senior engineer with root/admin access.

**When:** Setting up a new project, onboarding a new team, or adding new infrastructure.

**Scenario:** Your organization has a backend team, a payments team, and shared infrastructure (Datadog, RabbitMQ) that everyone uses.

```bash
# ── Step 1: Store the secrets ──

# Backend team's database credentials
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/db/credentials \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": {"host": "db.prod.internal", "username": "app_svc", "password": "xK9#mP2$vL5n"}}'

# Payments team's Stripe keys
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/api/stripe \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": {"secret_key": "sk_live_xxx", "webhook_secret": "whsec_yyy"}}'

# Shared: Datadog logging (ALL teams need this)
curl -s -X POST http://127.0.0.1:8200/v1/secret/shared/logging/datadog \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": {"api_key": "dd_live_abc123", "site": "datadoghq.com"}}'

# Shared: RabbitMQ (ALL teams need this)
curl -s -X POST http://127.0.0.1:8200/v1/secret/shared/messaging/rabbitmq \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": {"host": "rabbitmq.prod.internal", "password": "mQ8$nR4#kW2v"}}'
```

```bash
# ── Step 2: Create policies (reusable building blocks) ──

# Policy: backend team's own secrets
curl -s -X POST http://127.0.0.1:8200/v1/policies \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy": {"name": "backend-service", "rules": [
    {"path": "app/db/*",    "capabilities": ["read", "list"]},
    {"path": "app/cache/*", "capabilities": ["read", "list"]}
  ]}}'

# Policy: payments team's own secrets
curl -s -X POST http://127.0.0.1:8200/v1/policies \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy": {"name": "payments-service", "rules": [
    {"path": "app/api/*", "capabilities": ["read"]}
  ]}}'

# Policy: shared infrastructure (attach to ANY team that needs logging + messaging)
curl -s -X POST http://127.0.0.1:8200/v1/policies \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy": {"name": "shared-infra", "rules": [
    {"path": "shared/logging/*",   "capabilities": ["read", "list"]},
    {"path": "shared/messaging/*", "capabilities": ["read", "list"]}
  ]}}'
```

```bash
# ── Step 3: Generate tokens for each team ──
#    Each token gets MULTIPLE policies — their own + shared

# Backend team token: their secrets + shared infra
curl -s -X POST http://127.0.0.1:8200/v1/auth/token/create \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy_ids": ["backend-service", "shared-infra"], "ttl": "8h"}'
# → Give the client_token to the backend team

# Payments team token: their secrets + shared infra
curl -s -X POST http://127.0.0.1:8200/v1/auth/token/create \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policy_ids": ["payments-service", "shared-infra"], "ttl": "8h"}'
# → Give the client_token to the payments team
```

**Send each team their token securely** (encrypted Slack DM, 1Password, etc. — never in a ticket or email).

---

### Workflow 3: Developer Uses Their Team's Token

**Who:** Any developer on the backend or payments team.

**When:** Day-to-day development, configuring a service, debugging.

**What the admin gave you:** A vault token like `s.f7e8d9c0b1a2...` and told you "use this to get your secrets."

#### Option A: Use the Web UI

1. Open `http://your-vault-server:8200/ui/`
2. Paste your token and click Sign In
3. You'll see "Access Denied" at the root path (that's normal — you only have access to specific paths)
4. Type your path in the search box: `app/db` and click **Go**
5. You'll see your secrets listed — click one to view key-value pairs
6. Click **show** next to any value to reveal it, or **copy** to copy to clipboard

#### Option B: Use curl

```bash
export VAULT_TOKEN="s.f7e8d9c0b1a2..."

# Read your database credentials
curl -s http://127.0.0.1:8200/v1/secret/app/db/credentials \
  -H "X-Vault-Token: $VAULT_TOKEN"

# Read shared Datadog credentials (your token includes shared-infra)
curl -s http://127.0.0.1:8200/v1/secret/shared/logging/datadog \
  -H "X-Vault-Token: $VAULT_TOKEN"
```

#### Option C: Use the Go/Java/Python/Rust client

```go
client, _ := securevault.NewClient("http://127.0.0.1:8200", os.Getenv("VAULT_TOKEN"))
secret, _ := client.ReadSecret(ctx, "app/db/credentials")
dbHost := secret.Data["host"].(string)
dbPass := secret.Data["password"].(string)
```

---

### Workflow 4: Team Needs Access to a Secret They Don't Have

**Who:** A developer who gets `403 Permission denied` when trying to read a secret.

**When:** Your service needs a secret that belongs to another team or a shared resource you haven't been granted yet.

**Example:** The backend team now needs access to `shared/auth/jwt-signing` to validate JWTs.

#### Step 1: Developer identifies what they need

```bash
# This fails — your token doesn't include the auth-signing policy
curl -s http://127.0.0.1:8200/v1/secret/shared/auth/jwt-signing \
  -H "X-Vault-Token: $VAULT_TOKEN"
# → "Permission denied"
```

#### Step 2: Developer requests access

Send a message to the vault admin (or file a ticket):

> "The backend service needs read access to `shared/auth/jwt-signing` for JWT validation. Can you add the `auth-signing` policy to our token?"

#### Step 3: Admin grants access

The admin does **not** need to create a new policy or new secret. They just issue a new token that includes the additional policy:

```bash
# Admin creates a new token with the additional policy
curl -s -X POST http://127.0.0.1:8200/v1/auth/token/create \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_ids": ["backend-service", "shared-infra", "auth-signing"],
    "ttl": "8h"
  }'
# → New token now has 3 policies instead of 2
```

The admin sends the new token to the developer.

#### Step 4: Developer updates their token

```bash
export VAULT_TOKEN="s.new-token-with-more-policies..."

# This now works
curl -s http://127.0.0.1:8200/v1/secret/shared/auth/jwt-signing \
  -H "X-Vault-Token: $VAULT_TOKEN"
# → {"data": {"algorithm": "RS256", "private_key": "...", ...}}
```

> **What happened:** The admin didn't duplicate the secret or create a new policy. They reused the existing `auth-signing` policy and attached it to the team's new token. The secret is "shared" because multiple tokens can reference the same policy.

---

### Workflow 5: Team Creates and Manages Their Own Secrets

**Who:** A team lead or senior developer with write access to their team's path.

**When:** Adding new configuration, rotating a credential, storing a new API key.

**Prerequisite:** The admin created a policy with `create` and `update` capabilities:

```bash
# Admin creates a read-write policy for the team
curl -s -X POST http://127.0.0.1:8200/v1/policies \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"policy": {"name": "backend-readwrite", "rules": [
    {"path": "app/backend/**", "capabilities": ["read", "create", "update", "delete", "list"]}
  ]}}'

# Admin gives the team lead a token with this policy
curl -s -X POST http://127.0.0.1:8200/v1/auth/token/create \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"policy_ids": ["backend-readwrite", "shared-infra"], "ttl": "8h"}'
```

Now the team lead can manage secrets under `app/backend/` without involving the vault admin:

```bash
TEAM_TOKEN="s.team-lead-token..."

# Create a new secret
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/backend/new-api-key \
  -H "X-Vault-Token: $TEAM_TOKEN" \
  -d '{"data": {"key": "ak_prod_xxxxx", "environment": "production"}}'

# Rotate a credential (creates a new version automatically)
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/backend/new-api-key \
  -H "X-Vault-Token: $TEAM_TOKEN" \
  -d '{"data": {"key": "ak_prod_ROTATED", "environment": "production"}}'

# Check version history
curl -s http://127.0.0.1:8200/v1/secret/metadata/app/backend/new-api-key \
  -H "X-Vault-Token: $TEAM_TOKEN"
# → {"current_version": 2, "versions": {"1": {...}, "2": {...}}}

# Read the old version if needed (rollback investigation)
curl -s http://127.0.0.1:8200/v1/secret/versions/1/app/backend/new-api-key \
  -H "X-Vault-Token: $TEAM_TOKEN"

# But they CANNOT touch other teams' secrets
curl -s http://127.0.0.1:8200/v1/secret/app/api/stripe \
  -H "X-Vault-Token: $TEAM_TOKEN"
# → 403 Permission denied
```

---

### Workflow 6: After a Server Restart

**Who:** Any operator who holds an unseal key.

**When:** After a planned restart, deploy, crash, or server migration.

After a restart, the vault is **sealed**. All API requests return `503 Service Unavailable`. The unseal keys (distributed during Workflow 1) are needed.

```bash
# Check status
curl -s http://127.0.0.1:8200/v1/sys/seal-status
# → {"sealed": true, "threshold": 3, "num_shares": 5, "progress": 0}

# Operator 1 submits their key
curl -s -X POST http://127.0.0.1:8200/v1/sys/unseal \
  -d '{"key": "operator-1-key-here..."}'
# → {"sealed": true, "progress": 1}

# Operator 2 submits their key (can be from a different machine/location)
curl -s -X POST http://127.0.0.1:8200/v1/sys/unseal \
  -d '{"key": "operator-2-key-here..."}'
# → {"sealed": true, "progress": 2}

# Operator 3 submits their key — vault unseals
curl -s -X POST http://127.0.0.1:8200/v1/sys/unseal \
  -d '{"key": "operator-3-key-here..."}'
# → {"sealed": false}

# All previously issued tokens resume working. No secrets were lost.
```

This is the core security guarantee: even if someone steals the server, they can't read the encrypted data without enough unseal keys from different people.

---

### Workflow Summary

| Workflow | Who | When | What they do |
|----------|-----|------|-------------|
| 1. Initial Setup | Vault admin | Once | Initialize vault, distribute unseal keys |
| 2. Create Secrets & Policies | Vault admin | New project/team | Store secrets, create policies, generate tokens |
| 3. Use Secrets | Developer | Daily | Read secrets via UI, CLI, or client library |
| 4. Request Access | Developer + Admin | As needed | Developer asks, admin adds policy to token |
| 5. Self-Service Secrets | Team lead | As needed | Create/rotate secrets under their path |
| 6. Unseal After Restart | Key holders | After restarts | Submit unseal keys to restore access |

---

## Detailed Step-by-Step Technical Guide

### Phase 1: Administrator Setup

The admin is responsible for:
- Starting and initializing the vault
- Creating the secrets that applications need
- Defining policies that control who can access what
- Generating restricted tokens for each application/team

#### Step 1: Start and Initialize the Vault

```bash
# Start the server
./bin/securevault -config configs/dev-config.yaml &

# Initialize with 3 key shares, requiring 2 to unseal
curl -s -X POST http://127.0.0.1:8200/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{"secret_shares": 3, "secret_threshold": 2}'
```

Response:
```json
{
  "keys": [
    "abcdef1234...",
    "567890abcd...",
    "ef1234567890..."
  ],
  "root_token": "s.a1b2c3d4e5f6..."
}
```

**Save the unseal keys and root token securely.** The unseal keys should be distributed to different trusted operators. The root token is used for initial administration only.

> **Note:** The vault is automatically unsealed after initialization. You can start using it immediately. The unseal keys are needed later — after a server **restart**, the vault starts sealed and you must submit enough keys to unseal it before it will accept requests.

#### Step 2: Unseal the Vault (after a restart)

After a server restart, the vault is sealed. All secret operations return `503 Service Unavailable` until you unseal it. Submit enough key shares (at least `threshold` of them) to unseal:

```bash
# Check seal status
curl -s http://127.0.0.1:8200/v1/sys/seal-status
# → {"sealed":true, "threshold":2, "num_shares":3, "progress":0, ...}

# Submit first key share
curl -s -X POST http://127.0.0.1:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "abcdef1234..."}'
# → {"sealed":true, "progress":1, "threshold":2, ...}

# Submit second key share — vault unseals
curl -s -X POST http://127.0.0.1:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "567890abcd..."}'
# → {"sealed":false, "progress":0, ...}
```

Each key can come from a different operator. No single person needs all the keys. This is the core security property: even if someone steals the server's disk, they can't read secrets without enough unseal keys.

#### Step 3: Store Secrets

```bash
ROOT_TOKEN="s.a1b2c3d4e5f6..."

# Store database credentials
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/db/credentials \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "host": "db.production.internal",
      "port": 5432,
      "username": "app_service",
      "password": "xK9#mP2$vL5nQ8wR",
      "database": "myapp_production",
      "ssl_mode": "require"
    }
  }'

# Store API keys
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/api/stripe \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "publishable_key": "pk_live_xxxxxxxxxxxxxxxxxxxx",
      "secret_key": "sk_live_xxxxxxxxxxxxxxxxxxxx",
      "webhook_secret": "whsec_xxxxxxxxxxxxxxxxxxxx"
    }
  }'

# Store cache credentials
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/cache/redis \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "host": "redis.production.internal",
      "port": 6379,
      "password": "rD7$kL3#mN9pQ2wX",
      "database": 0
    }
  }'
```

#### Step 4: Create a Policy

Policies define what paths a token can access and what operations it can perform.

```bash
# Create a "backend-readonly" policy
# This allows reading secrets under app/db/* and app/cache/* but NOT app/api/*
curl -s -X POST http://127.0.0.1:8200/v1/policies \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "backend-readonly",
      "description": "Read-only access to backend infrastructure secrets",
      "rules": [
        {
          "path": "app/db/*",
          "capabilities": ["read", "list"]
        },
        {
          "path": "app/cache/*",
          "capabilities": ["read", "list"]
        }
      ]
    }
  }'
```

#### Step 5: Generate a Restricted Token

Create a token bound to the policy. This is what you give to the application.

```bash
# Create a token with the backend-readonly policy, valid for 8 hours
curl -s -X POST http://127.0.0.1:8200/v1/auth/token/create \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_ids": ["backend-readonly"],
    "ttl": "8h"
  }'
```

Response:
```json
{
  "auth": {
    "client_token": "s.f7e8d9c0b1a2...",
    "policies": ["backend-readonly"],
    "ttl": "8h"
  }
}
```

**Give `client_token` to the application team.** In production, this would be injected via environment variable, Kubernetes secret, or similar mechanism — never hardcoded.

#### Step 6: Share Secrets Across Teams with Multi-Policy Tokens

In practice, many secrets need to be accessible by multiple services: logging credentials, message queue connections, JWT signing keys, etc. The pattern is:

1. **Organize shared secrets** under a common prefix (e.g., `shared/`)
2. **Create a reusable policy** for the shared secrets (e.g., `shared-infra`)
3. **Attach multiple policies** to each token

```bash
# Create a shared-infra policy that grants access to common secrets
curl -s -X POST http://127.0.0.1:8200/v1/policies \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "shared-infra",
      "description": "Shared logging and messaging credentials for all services",
      "rules": [
        {"path": "shared/logging/*",   "capabilities": ["read", "list"]},
        {"path": "shared/messaging/*", "capabilities": ["read", "list"]}
      ]
    }
  }'

# Now create a token with BOTH the service-specific and shared policies
curl -s -X POST http://127.0.0.1:8200/v1/auth/token/create \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_ids": ["backend-service", "shared-infra"],
    "ttl": "8h"
  }'
```

The resulting token can access `app/db/*` (from `backend-service`) AND `shared/logging/*` (from `shared-infra`). Give the payments team a token with `["payments-service", "shared-infra"]` and they get `app/api/*` plus the same shared secrets.

---

### Phase 2: Application Access

The application uses the restricted token to fetch only the secrets it needs.

#### Using curl (REST)

```bash
APP_TOKEN="s.f7e8d9c0b1a2..."

# Read database credentials — ALLOWED by policy
curl -s http://127.0.0.1:8200/v1/secret/app/db/credentials \
  -H "X-Vault-Token: $APP_TOKEN"
# Returns: {"data": {"host": "db.production.internal", ...}}

# Read Redis credentials — ALLOWED by policy
curl -s http://127.0.0.1:8200/v1/secret/app/cache/redis \
  -H "X-Vault-Token: $APP_TOKEN"
# Returns: {"data": {"host": "redis.production.internal", ...}}

# Read Stripe API keys — DENIED by policy (403 Forbidden)
curl -s http://127.0.0.1:8200/v1/secret/app/api/stripe \
  -H "X-Vault-Token: $APP_TOKEN"
# Returns: "Permission denied"

# Write to any path — DENIED by policy (403 Forbidden)
curl -s -X POST http://127.0.0.1:8200/v1/secret/app/db/credentials \
  -H "X-Vault-Token: $APP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": {"hacked": true}}'
# Returns: "Permission denied"
```

#### Using the Java Client

See `java/` directory for a complete Maven project, or see the walkthrough script `02-client-access.sh` for the REST version.

---

## Policy Reference

| Capability | Allows |
|-----------|--------|
| `read` | Read secret values |
| `list` | List secret paths under a prefix |
| `create` | Create new secrets |
| `update` | Update existing secrets |
| `delete` | Delete secrets |

### Path Patterns

| Pattern | Matches |
|---------|---------|
| `app/db/credentials` | Exactly `app/db/credentials` |
| `app/db/*` | One level under `app/db/` (e.g., `app/db/credentials`, `app/db/config`) |
| `app/**` | Everything under `app/` at any depth (e.g., `app/db/credentials`, `app/api/stripe`) |
| `*` | Everything (use for root/admin policies only) |

Use `*` for single-segment matching and `**` for deep/recursive matching.

### Example Policies

**Backend service** — reads DB and cache creds:
```json
{"path": "app/db/*", "capabilities": ["read", "list"]},
{"path": "app/cache/*", "capabilities": ["read", "list"]}
```

**Payments service** — reads only API keys:
```json
{"path": "app/api/*", "capabilities": ["read"]}
```

**Shared infrastructure** — cross-team logging and messaging:
```json
{"path": "shared/logging/*",   "capabilities": ["read", "list"]},
{"path": "shared/messaging/*", "capabilities": ["read", "list"]}
```

**Auth signing** — JWT keys (only token-issuing services need this):
```json
{"path": "shared/auth/*", "capabilities": ["read"]}
```

**DevOps admin** — full shared access, read-only app access (using `**` for deep matching):
```json
{"path": "shared/**", "capabilities": ["read", "create", "update", "delete", "list"]},
{"path": "app/**",    "capabilities": ["read", "list"]}
```

### Example Multi-Policy Tokens

| Service | Policies on Token | Effective Access |
|---------|-------------------|-----------------|
| Backend API | `backend-service` + `shared-infra` | app/db/\*, app/cache/\*, shared/logging/\*, shared/messaging/\* |
| Payments | `payments-service` + `shared-infra` + `auth-signing` | app/api/\*, shared/logging/\*, shared/messaging/\*, shared/auth/\* |
| DevOps | `devops-admin` | shared/\* (read+write), app/\* (read) |
| New microservice | `shared-infra` | shared/logging/\*, shared/messaging/\* (add more policies as needed) |

---

## Files in This Directory

| File | Description |
|------|-------------|
| `README.md` | This document |
| `01-admin-setup.sh` | Admin script: starts server, initializes, creates secrets/policies/tokens |
| `02-client-access.sh` | Client script: uses the restricted token to access secrets |
| `java/pom.xml` | Maven project for the Java client example |
| `java/src/.../AdminSetup.java` | Java version of admin setup |
| `java/src/.../ClientAccess.java` | Java version of client access |

## Security Notes

- **Never commit tokens or unseal keys to version control**
- In production, inject the app token via environment variable (`VAULT_TOKEN`)
- Use short TTLs and renew tokens programmatically
- The root token should only be used for initial setup, then revoked
- Enable TLS in production (`server.tls.enabled: true`)
- Enable audit logging to track all access (`audit.enabled: true`)
