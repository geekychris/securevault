#!/usr/bin/env bash
#
# Test 3-node SecureVault cluster with Docker Compose
#
# This script:
#   1. Builds the Docker image
#   2. Starts a 3-node cluster (1 leader + 2 followers)
#   3. Initializes and unseals all nodes
#   4. Writes secrets to the leader
#   5. Verifies replication to both followers
#   6. Tears down the cluster
#
# Usage:
#   bash deploy/test-cluster.sh
#
# Prerequisites:
#   Docker and Docker Compose
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

LEADER="http://127.0.0.1:8200"
FOLLOWER1="http://127.0.0.1:8210"
FOLLOWER2="http://127.0.0.1:8220"

PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m" "$*"; }
red()   { printf "\033[31m%s\033[0m" "$*"; }
bold()  { printf "\033[1m%s\033[0m" "$*"; }

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  $(green PASS) $label"
        PASS=$((PASS + 1))
    else
        echo "  $(red FAIL) $label (expected: $expected, got: $actual)"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() {
    echo ""
    echo "Tearing down cluster..."
    docker compose -f docker-compose.cluster.yml down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

wait_for_health() {
    local url="$1" name="$2"
    for i in $(seq 1 30); do
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$url/v1/health" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "503" ]; then
            echo "  $name is up (HTTP $HTTP_CODE)"
            return 0
        fi
        sleep 1
    done
    echo "  $(red FAIL) $name did not become healthy"
    FAIL=$((FAIL + 1))
    return 1
}

# ═══════════════════════════════════════════════════════════════════
bold "═══════════════════════════════════════════════════════"
echo ""
bold "  SecureVault 3-Node Cluster Test (Docker)"
echo ""
bold "═══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Build and start ──────────────────────────────────────
echo "$(bold 'Step 1: Build and start cluster')"

docker compose -f docker-compose.cluster.yml down -v --remove-orphans 2>/dev/null || true
docker compose -f docker-compose.cluster.yml up --build -d 2>&1 | tail -5

echo "  Waiting for nodes to start..."
wait_for_health "$LEADER" "Leader"
wait_for_health "$FOLLOWER1" "Follower 1"
wait_for_health "$FOLLOWER2" "Follower 2"
echo ""

# ── Step 2: Initialize all nodes ─────────────────────────────────
echo "$(bold 'Step 2: Initialize and unseal all nodes')"

# Initialize leader
LEADER_INIT=$(curl -sf -X POST "$LEADER/v1/sys/init" \
    -H "Content-Type: application/json" \
    -d '{"secret_shares": 1, "secret_threshold": 1}')
LEADER_TOKEN=$(echo "$LEADER_INIT" | jq -r '.root_token')
assert_eq "Leader initialized" "true" "$([ -n "$LEADER_TOKEN" ] && echo true || echo false)"

# Initialize followers
F1_INIT=$(curl -sf -X POST "$FOLLOWER1/v1/sys/init" \
    -H "Content-Type: application/json" \
    -d '{"secret_shares": 1, "secret_threshold": 1}')
F1_TOKEN=$(echo "$F1_INIT" | jq -r '.root_token')
assert_eq "Follower 1 initialized" "true" "$([ -n "$F1_TOKEN" ] && echo true || echo false)"

F2_INIT=$(curl -sf -X POST "$FOLLOWER2/v1/sys/init" \
    -H "Content-Type: application/json" \
    -d '{"secret_shares": 1, "secret_threshold": 1}')
F2_TOKEN=$(echo "$F2_INIT" | jq -r '.root_token')
assert_eq "Follower 2 initialized" "true" "$([ -n "$F2_TOKEN" ] && echo true || echo false)"

# Verify all are unsealed
LEADER_SEALED=$(curl -s "$LEADER/v1/sys/seal-status" | jq -r '.sealed')
F1_SEALED=$(curl -s "$FOLLOWER1/v1/sys/seal-status" | jq -r '.sealed')
F2_SEALED=$(curl -s "$FOLLOWER2/v1/sys/seal-status" | jq -r '.sealed')
assert_eq "Leader unsealed" "false" "$LEADER_SEALED"
assert_eq "Follower 1 unsealed" "false" "$F1_SEALED"
assert_eq "Follower 2 unsealed" "false" "$F2_SEALED"
echo ""

# ── Step 3: Write secrets to leader ──────────────────────────────
echo "$(bold 'Step 3: Write secrets to leader')"

for i in 1 2 3; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$LEADER/v1/secret/cluster/secret-$i" \
        -H "X-Vault-Token: $LEADER_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"data\": {\"key\": \"value-$i\", \"node\": \"leader\"}}")
    assert_eq "Write secret-$i to leader" "204" "$STATUS"
done
echo ""

# ── Step 4: Verify replication ───────────────────────────────────
echo "$(bold 'Step 4: Verify replication to followers')"
echo "  Waiting for replication sync (up to 15s)..."

# Wait for replication — the leader syncs every 5s
REPLICATED=false
for attempt in $(seq 1 15); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$FOLLOWER1/v1/secret/cluster/secret-1" \
        -H "X-Vault-Token: $F1_TOKEN")
    if [ "$STATUS" = "200" ]; then
        REPLICATED=true
        break
    fi
    sleep 1
done

if [ "$REPLICATED" = "true" ]; then
    echo "  Replication detected after ${attempt}s"
else
    echo "  $(red 'Replication not detected after 15s')"
fi

# Verify all 3 secrets on follower 1
for i in 1 2 3; do
    BODY=$(curl -s "$FOLLOWER1/v1/secret/cluster/secret-$i" -H "X-Vault-Token: $F1_TOKEN")
    KEY_VAL=$(echo "$BODY" | jq -r '.data.key' 2>/dev/null || echo "")
    assert_eq "Follower 1 has secret-$i" "value-$i" "$KEY_VAL"
done

# Verify all 3 secrets on follower 2
for i in 1 2 3; do
    BODY=$(curl -s "$FOLLOWER2/v1/secret/cluster/secret-$i" -H "X-Vault-Token: $F2_TOKEN")
    KEY_VAL=$(echo "$BODY" | jq -r '.data.key' 2>/dev/null || echo "")
    assert_eq "Follower 2 has secret-$i" "value-$i" "$KEY_VAL"
done
echo ""

# ── Step 5: Verify data integrity ────────────────────────────────
echo "$(bold 'Step 5: Verify data integrity across nodes')"

# Write a complex secret
curl -s -X POST "$LEADER/v1/secret/cluster/complex" \
    -H "X-Vault-Token: $LEADER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"data": {"database": "prod-db", "password": "p@ss!w0rd#123", "port": 5432, "ssl": true}}' > /dev/null

sleep 7 # Wait for replication

# Compare leader and follower data
LEADER_DATA=$(curl -s "$LEADER/v1/secret/cluster/complex" -H "X-Vault-Token: $LEADER_TOKEN" | jq -cS '.data')
F1_DATA=$(curl -s "$FOLLOWER1/v1/secret/cluster/complex" -H "X-Vault-Token: $F1_TOKEN" | jq -cS '.data')
F2_DATA=$(curl -s "$FOLLOWER2/v1/secret/cluster/complex" -H "X-Vault-Token: $F2_TOKEN" | jq -cS '.data')

assert_eq "Follower 1 data matches leader" "$LEADER_DATA" "$F1_DATA"
assert_eq "Follower 2 data matches leader" "$LEADER_DATA" "$F2_DATA"
echo ""

# ── Step 6: Replication status ───────────────────────────────────
echo "$(bold 'Step 6: Replication status')"

LEADER_MODE=$(curl -s "$LEADER/v1/sys/replication/status" -H "X-Vault-Token: $LEADER_TOKEN" | jq -r '.mode')
assert_eq "Leader reports leader mode" "leader" "$LEADER_MODE"

echo ""

# ═══════════════════════════════════════════════════════════════════
echo ""
bold "═══════════════════════════════════════════════════════"
echo ""
echo "  Results: $(green "$PASS passed"), $([ "$FAIL" -gt 0 ] && red "$FAIL failed" || echo "$FAIL failed")"
echo ""
if [ "$FAIL" -gt 0 ]; then
    bold "  SOME TESTS FAILED"
    exit 1
else
    bold "  ALL CLUSTER TESTS PASSED"
fi
echo ""
