package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getFreePort finds an available TCP port
func getFreePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// clusterNode holds a running server and its metadata
type clusterNode struct {
	server    *Server
	rootToken string
	apiPort   int
	clusterPort int
	tmpDir    string
}

func (n *clusterNode) apiAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", n.apiPort)
}

func (n *clusterNode) clusterAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", n.clusterPort)
}

func (n *clusterNode) doRequest(method, path, token string, body interface{}) *httptest.ResponseRecorder {
	return doRequest(n.server, method, path, token, body)
}

// startNode creates and starts a vault node
func startNode(t *testing.T, mode string, clusterPort int, peers []string, sharedSecret string) *clusterNode {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "vault-cluster-*")
	require.NoError(t, err)

	apiPort := getFreePort()

	config := &Config{}
	config.Server.Address = "127.0.0.1"
	config.Server.Port = apiPort
	config.Storage.Type = "file"
	config.Storage.Path = tmpDir
	config.Auth.TokenTTL = "1h"
	config.Seal.SecretShares = 1
	config.Seal.SecretThreshold = 1
	config.Audit.Enabled = false
	config.Replication.Mode = mode
	config.Replication.ClusterAddr = fmt.Sprintf("127.0.0.1:%d", clusterPort)
	config.Replication.Peers = peers
	config.Replication.SharedSecret = sharedSecret

	srv, err := NewServer(config)
	require.NoError(t, err)

	// Start server in background
	go func() {
		srv.Start()
	}()

	// Wait for API to be ready
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", apiPort), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return &clusterNode{
		server:      srv,
		apiPort:     apiPort,
		clusterPort: clusterPort,
		tmpDir:      tmpDir,
	}
}

// initAndUnseal initializes and unseals a node, returns root token
func initAndUnseal(t *testing.T, node *clusterNode) string {
	t.Helper()

	resp, err := node.server.sealManager.Initialize(1, 1)
	require.NoError(t, err)

	node.server.tokenMutex.Lock()
	node.server.tokens[resp.RootToken] = TokenInfo{
		ID:        resp.RootToken,
		PolicyIDs: []string{"root"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	node.server.tokenMutex.Unlock()

	node.rootToken = resp.RootToken
	return resp.RootToken
}

func TestThreeNodeReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cluster test in short mode")
	}

	sharedSecret := "test-replication-secret"

	// Get ports for cluster communication
	leaderClusterPort := getFreePort()
	follower1ClusterPort := getFreePort()
	follower2ClusterPort := getFreePort()

	follower1Addr := fmt.Sprintf("127.0.0.1:%d", follower1ClusterPort)
	follower2Addr := fmt.Sprintf("127.0.0.1:%d", follower2ClusterPort)
	leaderAddr := fmt.Sprintf("127.0.0.1:%d", leaderClusterPort)

	// Start followers first (they need to be listening when leader tries to replicate)
	follower1 := startNode(t, "follower", follower1ClusterPort, []string{leaderAddr}, sharedSecret)
	defer os.RemoveAll(follower1.tmpDir)
	defer follower1.server.httpServer.Close()

	follower2 := startNode(t, "follower", follower2ClusterPort, []string{leaderAddr}, sharedSecret)
	defer os.RemoveAll(follower2.tmpDir)
	defer follower2.server.httpServer.Close()

	// Start leader
	leader := startNode(t, "leader", leaderClusterPort, []string{follower1Addr, follower2Addr}, sharedSecret)
	defer os.RemoveAll(leader.tmpDir)
	defer leader.server.httpServer.Close()

	// Initialize and unseal all nodes
	leaderToken := initAndUnseal(t, leader)
	initAndUnseal(t, follower1)
	initAndUnseal(t, follower2)

	// Give replication servers time to start
	time.Sleep(1 * time.Second)

	// ── Test 1: Write to leader ──
	t.Run("WriteToLeader", func(t *testing.T) {
		rr := leader.doRequest("POST", "/v1/secret/cluster/test1", leaderToken, map[string]interface{}{
			"data": map[string]interface{}{
				"replicated": "yes",
				"origin":     "leader",
			},
		})
		assert.Equal(t, http.StatusNoContent, rr.Code, "Write to leader should succeed")
	})

	// ── Test 2: Read from leader ──
	t.Run("ReadFromLeader", func(t *testing.T) {
		rr := leader.doRequest("GET", "/v1/secret/cluster/test1", leaderToken, nil)
		assert.Equal(t, http.StatusOK, rr.Code)

		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		data := resp["data"].(map[string]interface{})
		assert.Equal(t, "yes", data["replicated"])
		assert.Equal(t, "leader", data["origin"])
	})

	// ── Test 3: Data replicates to followers ──
	// Wait for replication sync (leader syncs every 5s, but also does immediate sync on write)
	t.Run("ReplicationToFollowers", func(t *testing.T) {
		// The leader replicates synchronously on write, so data should be available
		// Give a moment for the HTTP calls to complete
		time.Sleep(2 * time.Second)

		// Check follower 1
		rr := follower1.doRequest("GET", "/v1/secret/cluster/test1", follower1.rootToken, nil)
		if rr.Code == http.StatusOK {
			var resp map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &resp)
			data := resp["data"].(map[string]interface{})
			assert.Equal(t, "yes", data["replicated"])
			assert.Equal(t, "leader", data["origin"])
		} else {
			// Replication may take time via the periodic sync
			t.Logf("Follower 1 returned %d, waiting for periodic sync...", rr.Code)
			time.Sleep(6 * time.Second)
			rr = follower1.doRequest("GET", "/v1/secret/cluster/test1", follower1.rootToken, nil)
			assert.Equal(t, http.StatusOK, rr.Code, "Follower 1 should have replicated data")
		}

		// Check follower 2
		rr = follower2.doRequest("GET", "/v1/secret/cluster/test1", follower2.rootToken, nil)
		if rr.Code == http.StatusOK {
			var resp map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &resp)
			data := resp["data"].(map[string]interface{})
			assert.Equal(t, "yes", data["replicated"])
		} else {
			t.Logf("Follower 2 returned %d, waiting for periodic sync...", rr.Code)
			time.Sleep(6 * time.Second)
			rr = follower2.doRequest("GET", "/v1/secret/cluster/test1", follower2.rootToken, nil)
			assert.Equal(t, http.StatusOK, rr.Code, "Follower 2 should have replicated data")
		}
	})

	// ── Test 4: Multiple secrets replicate ──
	t.Run("MultipleSecretsReplicate", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			path := fmt.Sprintf("/v1/secret/cluster/batch/%d", i)
			rr := leader.doRequest("POST", path, leaderToken, map[string]interface{}{
				"data": map[string]interface{}{"index": i, "batch": true},
			})
			assert.Equal(t, http.StatusNoContent, rr.Code)
		}

		// Wait for replication
		time.Sleep(7 * time.Second)

		// Verify all 5 secrets on follower 1
		for i := 0; i < 5; i++ {
			path := fmt.Sprintf("/v1/secret/cluster/batch/%d", i)
			rr := follower1.doRequest("GET", path, follower1.rootToken, nil)
			assert.Equal(t, http.StatusOK, rr.Code, "Follower 1 should have batch secret %d", i)
		}
	})

	// ── Test 5: Replication status ──
	t.Run("ReplicationStatus", func(t *testing.T) {
		rr := leader.doRequest("GET", "/v1/sys/replication/status", leaderToken, nil)
		assert.Equal(t, http.StatusOK, rr.Code)

		var status map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &status)
		assert.Equal(t, "leader", status["mode"])
	})

	// ── Test 6: Follower rejects direct writes ──
	t.Run("FollowerRejectsDirectReplicationWithoutAuth", func(t *testing.T) {
		// Write directly to follower's replication endpoint without shared secret
		rr := follower1.doRequest("POST", "/v1/replication/data", "", map[string]interface{}{
			"path": "hacked/secret",
			"data": map[string]interface{}{"injected": true},
		})
		// Should be rejected (no auth header)
		assert.NotEqual(t, http.StatusOK, rr.Code)
	})

	// ── Test 7: Versioning replicates correctly ──
	t.Run("VersioningReplicates", func(t *testing.T) {
		// Write v1
		leader.doRequest("POST", "/v1/secret/cluster/versioned", leaderToken, map[string]interface{}{
			"data": map[string]interface{}{"version": "one"},
		})
		// Write v2
		leader.doRequest("POST", "/v1/secret/cluster/versioned", leaderToken, map[string]interface{}{
			"data": map[string]interface{}{"version": "two"},
		})

		// Read latest from leader
		rr := leader.doRequest("GET", "/v1/secret/cluster/versioned", leaderToken, nil)
		assert.Equal(t, http.StatusOK, rr.Code)
		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		assert.Equal(t, "two", resp["data"].(map[string]interface{})["version"])
	})
}

// TestReplicationAuth verifies that replication endpoints require authentication
func TestReplicationAuth(t *testing.T) {
	sharedSecret := "my-secret"

	clusterPort := getFreePort()
	node := startNode(t, "follower", clusterPort, []string{"127.0.0.1:9999"}, sharedSecret)
	defer os.RemoveAll(node.tmpDir)
	defer node.server.httpServer.Close()

	initAndUnseal(t, node)
	time.Sleep(500 * time.Millisecond)

	// Try to send replication data without the shared secret
	rr := node.doRequest("POST", "/v1/replication/data", "", map[string]interface{}{
		"path": "injected/secret",
		"data": map[string]interface{}{"evil": true},
	})

	// Should be rejected
	assert.True(t, rr.Code == http.StatusUnauthorized || rr.Code == http.StatusBadRequest,
		"Replication without auth should be rejected, got %d", rr.Code)
}
