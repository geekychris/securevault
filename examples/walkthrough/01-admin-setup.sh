#!/usr/bin/env bash
#
# SecureVault Admin Setup Script
#
# This script demonstrates what an administrator does:
#   1. Start the vault server
#   2. Initialize and unseal it
#   3. Store secrets
#   4. Create policies
#   5. Generate restricted tokens for applications
#
# Usage:
#   bash 01-admin-setup.sh
#
# Prerequisites:
#   - Server binary built: go build -o bin/securevault ./cmd/server
#   - jq installed (for JSON parsing)
#

set -euo pipefail

VAULT_ADDR="http://127.0.0.1:8200"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOKEN_FILE="/tmp/securevault-walkthrough-tokens.env"

echo "============================================"
echo "  SecureVault Admin Setup"
echo "============================================"
echo ""

# ─── Step 1: Start the server ────────────────────────────────────────────────

echo "► Step 1: Starting the vault server..."

# Kill any existing instance
pkill -f "bin/securevault" 2>/dev/null || true
sleep 1

# Clean previous data for a fresh start
rm -rf "$REPO_ROOT/data"
mkdir -p "$REPO_ROOT/data/audit"

cd "$REPO_ROOT"
nohup ./bin/securevault -config configs/dev-config.yaml > /tmp/securevault.log 2>&1 &
SERVER_PID=$!
echo "  Server started (PID: $SERVER_PID)"

# Wait for server to be ready
for i in $(seq 1 10); do
    if curl -sf "$VAULT_ADDR/v1/health" > /dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

echo "  Server is responding."
echo ""

# ─── Step 2: Initialize the vault ────────────────────────────────────────────

echo "► Step 2: Initializing the vault..."
echo "  Using 3 key shares with a threshold of 2."
echo ""

INIT_RESPONSE=$(curl -sf -X POST "$VAULT_ADDR/v1/sys/init" \
    -H "Content-Type: application/json" \
    -d '{"secret_shares": 3, "secret_threshold": 2}')

ROOT_TOKEN=$(echo "$INIT_RESPONSE" | jq -r '.root_token')
KEY_1=$(echo "$INIT_RESPONSE" | jq -r '.keys[0]')
KEY_2=$(echo "$INIT_RESPONSE" | jq -r '.keys[1]')
KEY_3=$(echo "$INIT_RESPONSE" | jq -r '.keys[2]')

echo "  ┌─────────────────────────────────────────────────┐"
echo "  │ SAVE THESE VALUES - THEY CANNOT BE RECOVERED!   │"
echo "  ├─────────────────────────────────────────────────┤"
echo "  │ Root Token: ${ROOT_TOKEN:0:20}...               │"
echo "  │ Unseal Key 1: ${KEY_1:0:16}...                  │"
echo "  │ Unseal Key 2: ${KEY_2:0:16}...                  │"
echo "  │ Unseal Key 3: ${KEY_3:0:16}...                  │"
echo "  └─────────────────────────────────────────────────┘"
echo ""

# ─── Step 3: Unseal the vault ────────────────────────────────────────────────

echo "► Step 3: Unsealing the vault (submitting 2 of 3 keys)..."

# Check if already unsealed (init with threshold=1 auto-unseals, or threshold>1 needs keys)
CURRENT_STATUS=$(curl -s "$VAULT_ADDR/v1/sys/seal-status")
ALREADY_UNSEALED=$(echo "$CURRENT_STATUS" | jq -r '.sealed')

if [ "$ALREADY_UNSEALED" = "false" ]; then
    echo "  Vault was unsealed during initialization."
    echo "  (This happens when you initialize and immediately unseal.)"
else
    UNSEAL_1=$(curl -s -X POST "$VAULT_ADDR/v1/sys/unseal" \
        -H "Content-Type: application/json" \
        -d "{\"key\": \"$KEY_1\"}")
    PROGRESS=$(echo "$UNSEAL_1" | jq -r '.progress')
    echo "  Key 1 submitted. Progress: $PROGRESS/2"

    UNSEAL_2=$(curl -s -X POST "$VAULT_ADDR/v1/sys/unseal" \
        -H "Content-Type: application/json" \
        -d "{\"key\": \"$KEY_2\"}")
    SEALED=$(echo "$UNSEAL_2" | jq -r '.sealed')
    echo "  Key 2 submitted. Sealed: $SEALED"

    if [ "$SEALED" != "false" ]; then
        echo "  ✗ ERROR: Vault is still sealed."
        exit 1
    fi
fi

echo "  ✓ Vault is unsealed and ready!"
echo ""

# ─── Step 4: Store secrets ───────────────────────────────────────────────────

echo "► Step 4: Storing application secrets..."

# Database credentials
curl -s -X POST "$VAULT_ADDR/v1/secret/app/db/credentials" \
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
    }' > /dev/null
echo "  ✓ Stored: app/db/credentials (PostgreSQL connection info)"

# API keys
curl -s -X POST "$VAULT_ADDR/v1/secret/app/api/stripe" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "publishable_key": "pk_live_51ABC123DEF456GHI789",
            "secret_key": "sk_live_51ABC123DEF456GHI789",
            "webhook_secret": "whsec_ABC123DEF456GHI789JKL"
        }
    }' > /dev/null
echo "  ✓ Stored: app/api/stripe (Stripe API keys)"

# Cache credentials
curl -s -X POST "$VAULT_ADDR/v1/secret/app/cache/redis" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "host": "redis.production.internal",
            "port": 6379,
            "password": "rD7kL3mN9pQ2wX",
            "database": 0
        }
    }' > /dev/null
echo "  ✓ Stored: app/cache/redis (Redis connection info)"

# TLS certificates
curl -s -X POST "$VAULT_ADDR/v1/secret/app/tls/internal" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "cert": "-----BEGIN CERTIFICATE-----\nMIIB...example...base64\n-----END CERTIFICATE-----",
            "key": "-----BEGIN PRIVATE KEY-----\nMIIE...example...base64\n-----END PRIVATE KEY-----"
        }
    }' > /dev/null
echo "  ✓ Stored: app/tls/internal (TLS certificates)"

# Shared secrets — used by multiple teams
curl -s -X POST "$VAULT_ADDR/v1/secret/shared/logging/datadog" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "api_key": "dd_live_abc123def456ghi789",
            "app_key": "dd_app_xyz987uvw654rst321",
            "site": "datadoghq.com"
        }
    }' > /dev/null
echo "  ✓ Stored: shared/logging/datadog (shared across all services)"

curl -s -X POST "$VAULT_ADDR/v1/secret/shared/messaging/rabbitmq" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "host": "rabbitmq.production.internal",
            "port": 5672,
            "username": "app_publisher",
            "password": "mQ8$nR4#kW2vP7jL",
            "vhost": "/production"
        }
    }' > /dev/null
echo "  ✓ Stored: shared/messaging/rabbitmq (shared across all services)"

curl -s -X POST "$VAULT_ADDR/v1/secret/shared/auth/jwt-signing" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "algorithm": "RS256",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...example\n-----END RSA PRIVATE KEY-----",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIB...example\n-----END PUBLIC KEY-----",
            "issuer": "myapp.example.com",
            "audience": "api.example.com"
        }
    }' > /dev/null
echo "  ✓ Stored: shared/auth/jwt-signing (shared across backend + auth services)"
echo ""

# ─── Step 5: Create policies ─────────────────────────────────────────────────

echo "► Step 5: Creating access policies..."
echo ""
echo "  These policies demonstrate real-world patterns:"
echo "  • Service-specific policies for isolated access"
echo "  • A shared policy granting cross-team access to common secrets"
echo "  • Tokens with MULTIPLE policies for services that need both"
echo ""

# Backend service policy — can read DB + cache, but NOT API keys or TLS certs
curl -s -X POST "$VAULT_ADDR/v1/policies" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "policy": {
            "name": "backend-service",
            "description": "Backend service: read DB and cache credentials",
            "rules": [
                {"path": "app/db/*",    "capabilities": ["read", "list"]},
                {"path": "app/cache/*", "capabilities": ["read", "list"]}
            ]
        }
    }' > /dev/null
echo "  ✓ Created policy: backend-service"
echo "    → app/db/* (read, list)"
echo "    → app/cache/* (read, list)"

# Payments service policy — can read only API keys
curl -s -X POST "$VAULT_ADDR/v1/policies" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "policy": {
            "name": "payments-service",
            "description": "Payments service: read Stripe API keys only",
            "rules": [
                {"path": "app/api/*", "capabilities": ["read"]}
            ]
        }
    }' > /dev/null
echo "  ✓ Created policy: payments-service"
echo "    → app/api/* (read)"

# Shared infrastructure policy — gives read access to logging, messaging, etc.
# This is the KEY pattern: common secrets that multiple teams need.
curl -s -X POST "$VAULT_ADDR/v1/policies" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "policy": {
            "name": "shared-infra",
            "description": "Shared infrastructure: logging, messaging, and other cross-team secrets",
            "rules": [
                {"path": "shared/logging/*",   "capabilities": ["read", "list"]},
                {"path": "shared/messaging/*", "capabilities": ["read", "list"]}
            ]
        }
    }' > /dev/null
echo "  ✓ Created policy: shared-infra"
echo "    → shared/logging/* (read, list)"
echo "    → shared/messaging/* (read, list)"

# Auth policy — grants access to JWT signing keys (only some services need this)
curl -s -X POST "$VAULT_ADDR/v1/policies" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "policy": {
            "name": "auth-signing",
            "description": "Access to JWT signing keys for services that issue tokens",
            "rules": [
                {"path": "shared/auth/*", "capabilities": ["read"]}
            ]
        }
    }' > /dev/null
echo "  ✓ Created policy: auth-signing"
echo "    → shared/auth/* (read)"

# DevOps policy — broader access for the platform team (read + write)
curl -s -X POST "$VAULT_ADDR/v1/policies" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "policy": {
            "name": "devops-admin",
            "description": "DevOps team: full access to shared infra, read access to app secrets",
            "rules": [
                {"path": "shared/**", "capabilities": ["read", "create", "update", "delete", "list"]},
                {"path": "app/**",    "capabilities": ["read", "list"]}
            ]
        }
    }' > /dev/null
echo "  ✓ Created policy: devops-admin"
echo "    → shared/* (read, create, update, delete, list)"
echo "    → app/* (read, list)"
echo ""

# ─── Step 6: Generate application tokens ─────────────────────────────────────

echo "► Step 6: Generating tokens with single and multiple policies..."
echo ""
echo "  KEY CONCEPT: A token can have MULTIPLE policies attached."
echo "  The effective permission is the UNION of all policies."
echo "  This is how you share secrets across teams without duplicating policies."
echo ""

# Token for the backend service — gets its own policy PLUS the shared infra policy
BACKEND_TOKEN_RESP=$(curl -s -X POST "$VAULT_ADDR/v1/auth/token/create" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"policy_ids": ["backend-service", "shared-infra"], "ttl": "8h"}')
BACKEND_TOKEN=$(echo "$BACKEND_TOKEN_RESP" | jq -r '.auth.client_token')
echo "  ✓ Backend service token:  ${BACKEND_TOKEN:0:20}..."
echo "    Policies: backend-service + shared-infra"
echo "    Can read: app/db/*, app/cache/*, shared/logging/*, shared/messaging/*"

# Token for the payments service — gets its own policy PLUS shared infra AND auth
PAYMENTS_TOKEN_RESP=$(curl -s -X POST "$VAULT_ADDR/v1/auth/token/create" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"policy_ids": ["payments-service", "shared-infra", "auth-signing"], "ttl": "8h"}')
PAYMENTS_TOKEN=$(echo "$PAYMENTS_TOKEN_RESP" | jq -r '.auth.client_token')
echo "  ✓ Payments service token: ${PAYMENTS_TOKEN:0:20}..."
echo "    Policies: payments-service + shared-infra + auth-signing"
echo "    Can read: app/api/*, shared/logging/*, shared/messaging/*, shared/auth/*"

# Token for the DevOps team — broader access
DEVOPS_TOKEN_RESP=$(curl -s -X POST "$VAULT_ADDR/v1/auth/token/create" \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"policy_ids": ["devops-admin"], "ttl": "4h"}')
DEVOPS_TOKEN=$(echo "$DEVOPS_TOKEN_RESP" | jq -r '.auth.client_token')
echo "  ✓ DevOps team token:      ${DEVOPS_TOKEN:0:20}..."
echo "    Policies: devops-admin"
echo "    Can read+write: shared/*, read: app/*"
echo ""

# ─── Save tokens for the client script ──────────────────────────────────────

cat > "$TOKEN_FILE" << EOF
# Generated by 01-admin-setup.sh — do NOT commit this file
VAULT_ADDR=$VAULT_ADDR
ROOT_TOKEN=$ROOT_TOKEN
UNSEAL_KEY_1=$KEY_1
UNSEAL_KEY_2=$KEY_2
UNSEAL_KEY_3=$KEY_3
BACKEND_TOKEN=$BACKEND_TOKEN
PAYMENTS_TOKEN=$PAYMENTS_TOKEN
DEVOPS_TOKEN=$DEVOPS_TOKEN
EOF
chmod 600 "$TOKEN_FILE"

echo "============================================"
echo "  Setup Complete!"
echo "============================================"
echo ""
echo "Tokens saved to: $TOKEN_FILE"
echo ""
echo "Next steps:"
echo "  1. Run the client access script:"
echo "     bash 02-client-access.sh"
echo ""
echo "  2. Or open the Web UI:"
echo "     http://127.0.0.1:8200/ui/"
echo "     (paste the root token to log in)"
echo ""
echo "  3. Or run the Java example:"
echo "     cd java && mvn compile exec:java"
echo ""
