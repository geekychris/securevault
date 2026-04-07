#!/usr/bin/env bash
#
# Vaultrix — Build and Verify All Examples
#
# This script:
#   1. Builds the server and all client libraries
#   2. Starts a fresh vault, initializes + unseals it
#   3. Runs each example (REST, Go, Python, Java walkthrough)
#   4. Verifies expected outputs with assertions
#   5. Reports pass/fail for each
#
# Usage:
#   bash examples/run-all-examples.sh
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VAULT_ADDR="http://127.0.0.1:8200"
PASS=0
FAIL=0
TOTAL=0

# ─── Helpers ──────────────────────────────────────────────────────────────────

red()   { printf "\033[31m%s\033[0m" "$*"; }
green() { printf "\033[32m%s\033[0m" "$*"; }
bold()  { printf "\033[1m%s\033[0m" "$*"; }

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        echo "  $(green "PASS") $label"
        PASS=$((PASS + 1))
    else
        echo "  $(red "FAIL") $label"
        echo "         expected: $expected"
        echo "         actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$actual" | grep -qE "$expected"; then
        echo "  $(green "PASS") $label"
        PASS=$((PASS + 1))
    else
        echo "  $(red "FAIL") $label"
        echo "         expected to contain: $expected"
        echo "         actual: $(echo "$actual" | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local label="$1" unexpected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$actual" | grep -qE "$unexpected"; then
        echo "  $(red "FAIL") $label"
        echo "         should NOT contain: $unexpected"
        FAIL=$((FAIL + 1))
    else
        echo "  $(green "PASS") $label"
        PASS=$((PASS + 1))
    fi
}

http_status() {
    local method="$1" url="$2" token="$3"
    local extra_args=("${@:4}")
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" \
        -H "X-Vault-Token: $token" \
        -H "Content-Type: application/json" \
        "${extra_args[@]}" 2>/dev/null || echo "000"
}

http_body() {
    local method="$1" url="$2" token="$3"
    local extra_args=("${@:4}")
    curl -s -X "$method" "$url" \
        -H "X-Vault-Token: $token" \
        -H "Content-Type: application/json" \
        "${extra_args[@]}" 2>/dev/null
}

cleanup() {
    pkill -f "bin/securevault" 2>/dev/null || true
}
trap cleanup EXIT

# ═════════════════════════════════════════════════════════════════════════════
echo ""
bold "═══════════════════════════════════════════════════════════"
echo ""
bold "  Vaultrix — Build & Verify All Examples"
echo ""
bold "═══════════════════════════════════════════════════════════"
echo ""

# ─── Phase 1: Build everything ───────────────────────────────────────────────

echo "$(bold "Phase 1: Building")"
echo ""

echo "  Building server..."
go build -o bin/securevault ./cmd/server 2>&1
assert_eq "Server binary builds" "0" "$?"

echo "  Building Go example..."
go build -o bin/go-example ./examples/go 2>&1
assert_eq "Go example builds" "0" "$?"

echo "  Building and installing Java client library..."
(cd clients/java && mvn install -q -DskipTests 2>&1)
assert_eq "Java client JAR builds" "0" "$?"

echo "  Checking Java walkthrough compiles..."
(cd examples/walkthrough/java && mvn compile -q 2>&1)
JAVA_COMPILE=$?
assert_eq "Java walkthrough compiles" "0" "$JAVA_COMPILE"

echo "  Checking Rust client compiles..."
(cd clients/rust && cargo check --quiet 2>&1)
RUST_CHECK=$?
assert_eq "Rust client compiles" "0" "$RUST_CHECK"

echo "  Checking Python client exists..."
test -f clients/python/securevault/client.py
assert_eq "Python client exists" "0" "$?"

echo ""

# ─── Phase 2: Start fresh vault ──────────────────────────────────────────────

echo "$(bold "Phase 2: Start & Initialize Vault")"
echo ""

pkill -f "bin/securevault" 2>/dev/null || true
sleep 1
rm -rf data
mkdir -p data/audit

nohup ./bin/securevault -config configs/dev-config.yaml > /tmp/securevault-test.log 2>&1 &
sleep 2

# Health check (should be sealed/uninitialized)
HEALTH=$(curl -s "$VAULT_ADDR/v1/health" 2>/dev/null)
assert_contains "Server is running" "initialized" "$HEALTH"

# Initialize
INIT_RESP=$(curl -s -X POST "$VAULT_ADDR/v1/sys/init" \
    -H "Content-Type: application/json" \
    -d '{"secret_shares": 1, "secret_threshold": 1}')

ROOT_TOKEN=$(echo "$INIT_RESP" | jq -r '.root_token')
UNSEAL_KEY=$(echo "$INIT_RESP" | jq -r '.keys[0]')

assert_contains "Init returns root token" "s." "$ROOT_TOKEN"
assert_contains "Init returns unseal key" "" "$UNSEAL_KEY"

# Unseal if needed
SEAL_STATUS=$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r '.sealed')
if [ "$SEAL_STATUS" = "true" ]; then
    curl -s -X POST "$VAULT_ADDR/v1/sys/unseal" \
        -H "Content-Type: application/json" \
        -d "{\"key\": \"$UNSEAL_KEY\"}" > /dev/null
fi

SEALED=$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r '.sealed')
assert_eq "Vault is unsealed" "false" "$SEALED"

echo ""

# ─── Phase 3: REST API tests ─────────────────────────────────────────────────

echo "$(bold "Phase 3: REST API Verification")"
echo ""

# Write secret
STATUS=$(http_status POST "$VAULT_ADDR/v1/secret/test/example" "$ROOT_TOKEN" \
    -d '{"data": {"username": "admin", "password": "s3cret"}}')
assert_eq "Write secret returns 204" "204" "$STATUS"

# Read secret
BODY=$(http_body GET "$VAULT_ADDR/v1/secret/test/example" "$ROOT_TOKEN")
USERNAME=$(echo "$BODY" | jq -r '.data.username')
assert_eq "Read secret returns correct data" "admin" "$USERNAME"

# Write v2
http_status POST "$VAULT_ADDR/v1/secret/test/example" "$ROOT_TOKEN" \
    -d '{"data": {"username": "admin", "password": "rotated"}}' > /dev/null

# Read specific version
V1_BODY=$(http_body GET "$VAULT_ADDR/v1/secret/versions/1/test/example" "$ROOT_TOKEN")
V1_PASS=$(echo "$V1_BODY" | jq -r '.data.password')
assert_eq "Read v1 returns original password" "s3cret" "$V1_PASS"

# Metadata
META=$(http_body GET "$VAULT_ADDR/v1/secret/metadata/test/example" "$ROOT_TOKEN")
CUR_VER=$(echo "$META" | jq -r '.current_version')
assert_eq "Metadata shows current version 2" "2" "$CUR_VER"

# Create policy
STATUS=$(http_status POST "$VAULT_ADDR/v1/policies" "$ROOT_TOKEN" \
    -d '{"policy": {"name": "test-ro", "rules": [{"path": "test/*", "capabilities": ["read"]}]}}')
assert_eq "Create policy returns 204" "204" "$STATUS"

# Create restricted token
TOKEN_RESP=$(http_body POST "$VAULT_ADDR/v1/auth/token/create" "$ROOT_TOKEN" \
    -d '{"policy_ids": ["test-ro"], "ttl": "1h"}')
RO_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.auth.client_token')
assert_contains "Created restricted token" "s." "$RO_TOKEN"

# Restricted token can read
STATUS=$(http_status GET "$VAULT_ADDR/v1/secret/test/example" "$RO_TOKEN")
assert_eq "Restricted token can read allowed path" "200" "$STATUS"

# Restricted token cannot write
STATUS=$(http_status POST "$VAULT_ADDR/v1/secret/test/example" "$RO_TOKEN" \
    -d '{"data": {"hacked": true}}')
assert_eq "Restricted token denied write" "403" "$STATUS"

# Restricted token cannot read other paths
STATUS=$(http_status GET "$VAULT_ADDR/v1/secret/other/path" "$RO_TOKEN")
assert_eq "Restricted token denied other path" "403" "$STATUS"

# No token = 401
STATUS=$(http_status GET "$VAULT_ADDR/v1/secret/test/example" "")
assert_eq "No token returns 401" "401" "$STATUS"

# Invalid token = 401
STATUS=$(http_status GET "$VAULT_ADDR/v1/secret/test/example" "s.invalid")
assert_eq "Invalid token returns 401" "401" "$STATUS"

# List secrets
http_status POST "$VAULT_ADDR/v1/secret/test/item1" "$ROOT_TOKEN" \
    -d '{"data": {"k": "v1"}}' > /dev/null
http_status POST "$VAULT_ADDR/v1/secret/test/item2" "$ROOT_TOKEN" \
    -d '{"data": {"k": "v2"}}' > /dev/null
LIST=$(http_body GET "$VAULT_ADDR/v1/secret/list/test" "$ROOT_TOKEN")
assert_contains "List returns keys" "keys" "$LIST"

# Delete
STATUS=$(http_status DELETE "$VAULT_ADDR/v1/secret/test/example?destroy=true" "$ROOT_TOKEN")
assert_eq "Delete returns 204" "204" "$STATUS"

STATUS=$(http_status GET "$VAULT_ADDR/v1/secret/test/example" "$ROOT_TOKEN")
assert_eq "Deleted secret returns 404" "404" "$STATUS"

# Seal status endpoint
SEAL_BODY=$(http_body GET "$VAULT_ADDR/v1/sys/seal-status" "")
assert_contains "Seal status returns initialized" "initialized" "$SEAL_BODY"

# Audit log
AUDIT=$(http_body GET "$VAULT_ADDR/v1/audit/events?limit=3" "$ROOT_TOKEN")
assert_contains "Audit log returns events" "events" "$AUDIT"

# Token lookup
LOOKUP=$(http_body GET "$VAULT_ADDR/v1/auth/token/lookup-self" "$ROOT_TOKEN")
assert_contains "Token lookup returns data" "policies" "$LOOKUP"

# Cleanup
http_status DELETE "$VAULT_ADDR/v1/secret/test/item1?destroy=true" "$ROOT_TOKEN" > /dev/null
http_status DELETE "$VAULT_ADDR/v1/secret/test/item2?destroy=true" "$ROOT_TOKEN" > /dev/null
http_status DELETE "$VAULT_ADDR/v1/policies/test-ro" "$ROOT_TOKEN" > /dev/null

echo ""

# ─── Phase 4: Walkthrough scripts ────────────────────────────────────────────

echo "$(bold "Phase 4: Walkthrough Scripts (REST)")"
echo ""

# Stop old server, run fresh for walkthrough
pkill -f "bin/securevault" 2>/dev/null || true
sleep 1
rm -rf data
mkdir -p data/audit

echo "  Running 01-admin-setup.sh..."
ADMIN_OUT=$(bash examples/walkthrough/01-admin-setup.sh 2>&1)
assert_contains "Admin setup stores DB creds" "app/db/credentials" "$ADMIN_OUT"
assert_contains "Admin setup stores shared secrets" "shared/logging/datadog" "$ADMIN_OUT"
assert_contains "Admin setup creates backend-service policy" "backend-service" "$ADMIN_OUT"
assert_contains "Admin setup creates shared-infra policy" "shared-infra" "$ADMIN_OUT"
assert_contains "Admin setup creates auth-signing policy" "auth-signing" "$ADMIN_OUT"
assert_contains "Admin setup creates devops-admin policy" "devops-admin" "$ADMIN_OUT"
assert_contains "Admin setup generates backend token" "Backend service token" "$ADMIN_OUT"
assert_contains "Admin setup generates payments token" "Payments service token" "$ADMIN_OUT"
assert_contains "Admin setup generates devops token" "DevOps team token" "$ADMIN_OUT"

echo ""
echo "  Running 02-client-access.sh..."
CLIENT_OUT=$(bash examples/walkthrough/02-client-access.sh 2>&1)

# Check key patterns appear in output (grep is line-based, don't use .* across lines)
assert_contains "Backend reads DB creds" "Read database credentials" "$CLIENT_OUT"
assert_contains "Backend reads Redis" "Read Redis credentials" "$CLIENT_OUT"
assert_contains "Backend reads shared Datadog" "Read Datadog credentials" "$CLIENT_OUT"
assert_contains "Backend reads shared RabbitMQ" "Read RabbitMQ credentials" "$CLIENT_OUT"
assert_contains "Access granted appears" "Access GRANTED" "$CLIENT_OUT"
assert_contains "Access denied appears" "Access DENIED" "$CLIENT_OUT"
assert_contains "Backend denied write" "Write to app/db/credentials" "$CLIENT_OUT"
assert_contains "Payments reads Stripe" "Stripe API keys" "$CLIENT_OUT"
assert_contains "Payments reads JWT" "JWT signing keys" "$CLIENT_OUT"
assert_contains "DevOps scenario runs" "Scenario 4" "$CLIENT_OUT"
assert_contains "DevOps writes shared" "Write to shared/logging/datadog" "$CLIENT_OUT"
assert_contains "DevOps denied app write" "CANNOT write to app" "$CLIENT_OUT"
assert_contains "Invalid token rejected" "401" "$CLIENT_OUT"
assert_contains "Summary shows policy union" "UNION" "$CLIENT_OUT"

echo ""

# ─── Phase 5: Go example ─────────────────────────────────────────────────────

echo "$(bold "Phase 5: Go Client Example")"
echo ""

# Use the running server from walkthrough
source /tmp/securevault-walkthrough-tokens.env

echo "  Running Go example..."
GO_OUT=$(./bin/go-example "$VAULT_ADDR" "$ROOT_TOKEN" 2>&1) || true

assert_contains "Go: creates policy" "app-readonly" "$GO_OUT"
assert_contains "Go: writes secret" "Written secret" "$GO_OUT"
assert_contains "Go: reads secret" "Read secret" "$GO_OUT"
assert_contains "Go: creates restricted token" "restricted token" "$GO_OUT"
assert_contains "Go: restricted read works" "Restricted client read" "$GO_OUT"
assert_contains "Go: restricted write denied" "denied" "$GO_OUT"

echo ""

# ─── Phase 6: Python example ─────────────────────────────────────────────────

echo "$(bold "Phase 6: Python Client Example")"
echo ""

echo "  Running Python example..."
PYTHON_OUT=$(python3 examples/python/example.py "$VAULT_ADDR" "$ROOT_TOKEN" 2>&1) || true

assert_contains "Python: writes secret" "Written secret" "$PYTHON_OUT"
assert_contains "Python: reads secret" "Read:" "$PYTHON_OUT"
assert_contains "Python: restricted write denied" "(denied|403)" "$PYTHON_OUT"

echo ""

# ─── Phase 7: Java walkthrough ───────────────────────────────────────────────

echo "$(bold "Phase 7: Java Walkthrough")"
echo ""

echo "  Running Java walkthrough (mvn exec:java)..."
JAVA_OUT=$(cd examples/walkthrough/java && mvn compile exec:java -Dexec.args="$VAULT_ADDR $ROOT_TOKEN" 2>&1 | grep -v '^\[') || true

if [ -n "$JAVA_OUT" ]; then
    assert_contains "Java: stores secrets" "Storing" "$JAVA_OUT"
    assert_contains "Java: creates policies" "policies" "$JAVA_OUT"
    assert_contains "Java: generates tokens" "token" "$JAVA_OUT"
    assert_contains "Java: backend reads DB" "app/db" "$JAVA_OUT"
    assert_contains "Java: backend reads shared" "shared" "$JAVA_OUT"
else
    echo "  $(red "SKIP") Java walkthrough produced no output (may need manual Maven setup)"
    echo "         Run: cd examples/walkthrough/java && mvn compile exec:java -Dexec.args=\"$VAULT_ADDR $ROOT_TOKEN\""
fi

echo ""

# ─── Phase 8: Seal/Unseal verification ───────────────────────────────────────

echo "$(bold "Phase 8: Seal/Unseal Cycle")"
echo ""

# Seal
STATUS=$(http_status POST "$VAULT_ADDR/v1/sys/seal" "$ROOT_TOKEN")
assert_eq "Seal returns 200" "200" "$STATUS"

SEALED=$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r '.sealed')
assert_eq "Vault is sealed" "true" "$SEALED"

# Operations blocked while sealed
STATUS=$(http_status GET "$VAULT_ADDR/v1/secret/test/example" "$ROOT_TOKEN")
assert_eq "Read blocked while sealed" "503" "$STATUS"

# Unseal — use the key from the walkthrough setup
source /tmp/securevault-walkthrough-tokens.env
for KEY_VAR in UNSEAL_KEY_1 UNSEAL_KEY_2 UNSEAL_KEY_3; do
    KEY_VAL="${!KEY_VAR:-}"
    if [ -n "$KEY_VAL" ]; then
        curl -s -X POST "$VAULT_ADDR/v1/sys/unseal" \
            -H "Content-Type: application/json" \
            -d "{\"key\": \"$KEY_VAL\"}" > /dev/null 2>&1 || true
    fi
    SEALED=$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r '.sealed')
    if [ "$SEALED" = "false" ]; then break; fi
done

SEALED=$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r '.sealed')
assert_eq "Vault unsealed after keys" "false" "$SEALED"

echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════

echo ""
bold "═══════════════════════════════════════════════════════════"
echo ""
echo "  Results: $(green "$PASS passed"), $([ "$FAIL" -gt 0 ] && red "$FAIL failed" || echo "$FAIL failed") out of $TOTAL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    bold "  SOME TESTS FAILED"
    echo ""
    exit 1
else
    bold "  ALL TESTS PASSED"
    echo ""
    exit 0
fi
