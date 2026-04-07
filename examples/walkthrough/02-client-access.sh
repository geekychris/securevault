#!/usr/bin/env bash
#
# SecureVault Client Access Script
#
# This script demonstrates what an application does:
#   1. Authenticate with a restricted token
#   2. Read secrets it's allowed to access
#   3. Get denied when accessing secrets outside its policy
#
# Usage:
#   bash 02-client-access.sh
#
# Prerequisites:
#   Run 01-admin-setup.sh first to create secrets, policies, and tokens.
#

set -euo pipefail

TOKEN_FILE="/tmp/securevault-walkthrough-tokens.env"

if [ ! -f "$TOKEN_FILE" ]; then
    echo "ERROR: Token file not found at $TOKEN_FILE"
    echo "Run 01-admin-setup.sh first."
    exit 1
fi

source "$TOKEN_FILE"

echo "============================================"
echo "  SecureVault Client Access Demo"
echo "============================================"
echo ""

# ─── Helper function ─────────────────────────────────────────────────────────

request() {
    local method="$1"
    local path="$2"
    local token="$3"
    local label="$4"

    local url="$VAULT_ADDR$path"
    local http_code
    local body

    # Make request and capture both body and status code
    body=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
        -H "X-Vault-Token: $token" \
        -H "Content-Type: application/json")

    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | sed '$d')

    if [ "$http_code" = "200" ]; then
        echo "  ✓ $label"
        echo "    HTTP $http_code — Access GRANTED"
        # Pretty-print the data portion
        if echo "$body" | jq -e '.data' > /dev/null 2>&1; then
            echo "$body" | jq -r '.data | to_entries[] | "    \(.key) = \(.value)"' 2>/dev/null || true
        fi
    elif [ "$http_code" = "403" ]; then
        echo "  ✗ $label"
        echo "    HTTP $http_code — Access DENIED (as expected)"
    elif [ "$http_code" = "204" ]; then
        echo "  ✓ $label"
        echo "    HTTP $http_code — Success (no content)"
    else
        echo "  ? $label"
        echo "    HTTP $http_code — $body"
    fi
    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# Scenario 1: Backend Service
# ═════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scenario 1: Backend Service"
echo "  Token policy: backend-service"
echo "  Allowed: app/db/*, app/cache/*"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "  ── Reads that SHOULD succeed ──"
echo ""

request GET "/v1/secret/app/db/credentials" "$BACKEND_TOKEN" \
    "Read database credentials (app/db/credentials)"

request GET "/v1/secret/app/cache/redis" "$BACKEND_TOKEN" \
    "Read Redis credentials (app/cache/redis)"

echo "  ── Reads that SHOULD be denied ──"
echo ""

request GET "/v1/secret/app/api/stripe" "$BACKEND_TOKEN" \
    "Read Stripe API keys (app/api/stripe)"

request GET "/v1/secret/app/tls/internal" "$BACKEND_TOKEN" \
    "Read TLS certificates (app/tls/internal)"

echo "  ── Write that SHOULD be denied ──"
echo ""

# Try to write — should fail because policy only has read+list
WRITE_RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$VAULT_ADDR/v1/secret/app/db/credentials" \
    -H "X-Vault-Token: $BACKEND_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"data": {"hacked": true}}')
if [ "$WRITE_RESULT" = "403" ]; then
    echo "  ✗ Write to app/db/credentials"
    echo "    HTTP 403 — Access DENIED (as expected)"
else
    echo "  ? Write to app/db/credentials — HTTP $WRITE_RESULT (unexpected)"
fi
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Scenario 2: Backend Service — Shared Secrets
# ═════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scenario 2: Backend Service — Shared Secrets"
echo "  Token policies: backend-service + shared-infra"
echo "  The shared-infra policy lets this service also access"
echo "  secrets in shared/logging/* and shared/messaging/*"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "  ── Shared secrets this service CAN access ──"
echo ""

request GET "/v1/secret/shared/logging/datadog" "$BACKEND_TOKEN" \
    "Read Datadog credentials (shared/logging/datadog)"

request GET "/v1/secret/shared/messaging/rabbitmq" "$BACKEND_TOKEN" \
    "Read RabbitMQ credentials (shared/messaging/rabbitmq)"

echo "  ── Shared secrets this service CANNOT access ──"
echo ""

request GET "/v1/secret/shared/auth/jwt-signing" "$BACKEND_TOKEN" \
    "Read JWT signing keys (shared/auth/jwt-signing)"

# ═════════════════════════════════════════════════════════════════════════════
# Scenario 3: Payments Service (3 policies combined)
# ═════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scenario 3: Payments Service"
echo "  Token policies: payments-service + shared-infra + auth-signing"
echo "  This token combines THREE policies — the effective access"
echo "  is the union of all of them."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "  ── Service-specific secrets (from payments-service policy) ──"
echo ""

request GET "/v1/secret/app/api/stripe" "$PAYMENTS_TOKEN" \
    "Read Stripe API keys (app/api/stripe)"

echo "  ── Shared secrets (from shared-infra policy) ──"
echo ""

request GET "/v1/secret/shared/logging/datadog" "$PAYMENTS_TOKEN" \
    "Read Datadog credentials (shared/logging/datadog)"

request GET "/v1/secret/shared/messaging/rabbitmq" "$PAYMENTS_TOKEN" \
    "Read RabbitMQ credentials (shared/messaging/rabbitmq)"

echo "  ── Auth secrets (from auth-signing policy) ──"
echo ""

request GET "/v1/secret/shared/auth/jwt-signing" "$PAYMENTS_TOKEN" \
    "Read JWT signing keys (shared/auth/jwt-signing)"

echo "  ── Secrets that are STILL denied (no matching policy) ──"
echo ""

request GET "/v1/secret/app/db/credentials" "$PAYMENTS_TOKEN" \
    "Read database credentials (app/db/credentials)"

request GET "/v1/secret/app/cache/redis" "$PAYMENTS_TOKEN" \
    "Read Redis credentials (app/cache/redis)"

# ═════════════════════════════════════════════════════════════════════════════
# Scenario 4: DevOps Team (broad cross-cutting access + write)
# ═════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scenario 4: DevOps Team"
echo "  Token policy: devops-admin"
echo "  Can read+write shared/*, read app/*"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "  ── Can read ALL application and shared secrets ──"
echo ""

request GET "/v1/secret/app/db/credentials" "$DEVOPS_TOKEN" \
    "Read database credentials (app/db/credentials)"

request GET "/v1/secret/app/api/stripe" "$DEVOPS_TOKEN" \
    "Read Stripe API keys (app/api/stripe)"

request GET "/v1/secret/shared/logging/datadog" "$DEVOPS_TOKEN" \
    "Read Datadog credentials (shared/logging/datadog)"

request GET "/v1/secret/shared/auth/jwt-signing" "$DEVOPS_TOKEN" \
    "Read JWT signing keys (shared/auth/jwt-signing)"

echo "  ── Can WRITE to shared secrets (rotate credentials) ──"
echo ""

WRITE_SHARED=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$VAULT_ADDR/v1/secret/shared/logging/datadog" \
    -H "X-Vault-Token: $DEVOPS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"data": {"api_key": "dd_live_ROTATED_KEY", "app_key": "dd_app_ROTATED_KEY", "site": "datadoghq.com"}}')
if [ "$WRITE_SHARED" = "204" ]; then
    echo "  ✓ Write to shared/logging/datadog"
    echo "    HTTP 204 — UPDATED (DevOps can rotate shared credentials)"
else
    echo "  ? Write to shared/logging/datadog — HTTP $WRITE_SHARED"
fi
echo ""

echo "  ── But CANNOT write to app secrets (read-only for app/*) ──"
echo ""

WRITE_APP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$VAULT_ADDR/v1/secret/app/db/credentials" \
    -H "X-Vault-Token: $DEVOPS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"data": {"hacked": true}}')
if [ "$WRITE_APP" = "403" ]; then
    echo "  ✗ Write to app/db/credentials"
    echo "    HTTP 403 — Access DENIED (DevOps can read but not modify app secrets)"
else
    echo "  ? Write to app/db/credentials — HTTP $WRITE_APP"
fi
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Scenario 5: Invalid/expired token
# ═════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scenario 5: Invalid Token"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FAKE_TOKEN="s.this-is-not-a-valid-token"
INVALID_RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
    "$VAULT_ADDR/v1/secret/app/db/credentials" \
    -H "X-Vault-Token: $FAKE_TOKEN")
if [ "$INVALID_RESULT" = "401" ]; then
    echo "  ✗ Read with invalid token"
    echo "    HTTP 401 — Unauthorized (as expected)"
else
    echo "  ? Read with invalid token — HTTP $INVALID_RESULT"
fi
echo ""

NO_TOKEN_RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
    "$VAULT_ADDR/v1/secret/app/db/credentials")
if [ "$NO_TOKEN_RESULT" = "401" ]; then
    echo "  ✗ Read with no token"
    echo "    HTTP 401 — Unauthorized (as expected)"
else
    echo "  ? Read with no token — HTTP $NO_TOKEN_RESULT"
fi
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════

echo "============================================"
echo "  Summary"
echo "============================================"
echo ""
echo "  backend-service token (policies: backend-service + shared-infra):"
echo "    ✓ app/db/*, app/cache/*         (from backend-service policy)"
echo "    ✓ shared/logging/*, shared/messaging/*  (from shared-infra policy)"
echo "    ✗ app/api/*, app/tls/*, shared/auth/*"
echo ""
echo "  payments-service token (policies: payments-service + shared-infra + auth-signing):"
echo "    ✓ app/api/*                     (from payments-service policy)"
echo "    ✓ shared/logging/*, shared/messaging/*  (from shared-infra policy)"
echo "    ✓ shared/auth/*                 (from auth-signing policy)"
echo "    ✗ app/db/*, app/cache/*, app/tls/*"
echo ""
echo "  devops-admin token (policy: devops-admin):"
echo "    ✓ READ  app/*, shared/*         (broad read access)"
echo "    ✓ WRITE shared/*                (can rotate shared credentials)"
echo "    ✗ WRITE app/*                   (app secrets are read-only for DevOps)"
echo ""
echo "  HOW SHARED ACCESS WORKS:"
echo "    • shared/logging/datadog is accessible by BOTH backend and payments"
echo "      because both tokens include the shared-infra policy"
echo "    • shared/auth/jwt-signing is only accessible by payments (not backend)"
echo "      because only payments has the auth-signing policy"
echo "    • A token's effective permissions = UNION of all its policies"
echo "    • Policies are reusable building blocks — compose them per service"
echo ""
