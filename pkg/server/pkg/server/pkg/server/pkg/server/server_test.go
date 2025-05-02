package server

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// setupTestServer creates a test server with a temporary storage directory
func setupTestServer(t *testing.T) (*Server, string) {
    // Create a temporary directory for storage
    tempDir, err := os.MkdirTemp("", "securevault-test-")
    require.NoError(t, err)

    // Set up a basic configuration
    config := &Config{
        Server: struct {
            Address string `yaml:"address"`
            Port    int    `yaml:"port"`
            TLS     struct {
                Enabled  bool   `yaml:"enabled"`
                CertFile string `yaml:"cert_file"`
                KeyFile  string `yaml:"key_file"`
            } `yaml:"tls"`
        }{
            Address: "127.0.0.1",
            Port:    0, // Let the OS assign a port
            TLS: struct {
                Enabled  bool   `yaml:"enabled"`
                CertFile string `yaml:"cert_file"`
                KeyFile  string `yaml:"key_file"`
            }{
                Enabled: false,
            },
        },
        Storage: struct {
            Type string `yaml:"type"`
            Path string `yaml:"path"`
        }{
            Type: "file",
            Path: tempDir,
        },
        Auth: struct {
            TokenTTL string `yaml:"token_ttl"`
        }{
            TokenTTL: "24h",
        },
        Replication: struct {
            Mode        string   `yaml:"mode"`
            ClusterAddr string   `yaml:"cluster_addr"`
            Peers       []string `yaml:"peers"`
        }{
            Mode: "standalone",
        },
    }

    // Create the server
    server, err := NewServer(config)
    require.NoError(t, err)

    // Enable test mode
    os.Setenv("TEST_MODE", "true")

    return server, tempDir
}

// cleanupTestServer cleans up the temporary storage directory
func cleanupTestServer(t *testing.T, tempDir string) {
    err := os.RemoveAll(tempDir)
    require.NoError(t, err)
    os.Unsetenv("TEST_MODE")
}

// writeSecret is a helper function to write a secret to the server
func writeSecret(t *testing.T, server *Server, path string, data map[string]interface{}, token string) {
    reqBody, err := json.Marshal(map[string]interface{}{
        "data": data,
    })
    require.NoError(t, err)

    req := httptest.NewRequest("POST", "/v1/secret/"+path, bytes.NewBuffer(reqBody))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Vault-Token", token)

    w := httptest.NewRecorder()
    server.writeSecretHandler(w, req)

    resp := w.Result()
    require.Equal(t, http.StatusNoContent, resp.StatusCode)
    resp.Body.Close()
}

// readSecret is a helper function to read a secret from the server
func readSecret(t *testing.T, server *Server, path, token string) map[string]interface{} {
    req := httptest.NewRequest("GET", "/v1/secret/"+path, nil)
    req.Header.Set("X-Vault-Token", token)

    w := httptest.NewRecorder()
    server.readSecretHandler(w, req)

    resp := w.Result()
    require.Equal(t, http.StatusOK, resp.StatusCode)

    var respData map[string]interface{}
    err := json.NewDecoder(resp.Body).Decode(&respData)
    require.NoError(t, err)
    resp.Body.Close()

    return respData
}

// TestBasicSecretOperations tests basic CRUD operations on secrets
func TestBasicSecretOperations(t *testing.T) {
    server, tempDir := setupTestServer(t)
    defer cleanupTestServer(t, tempDir)

    // Test write secret
    path := "test/secret1"
    data := map[string]interface{}{
        "key1": "value1",
        "key2": 42,
    }

    // Mock HTTP request for writing a secret
    reqBody, err := json.Marshal(map[string]interface{}{
        "data": data,
    })
    require.NoError(t, err)

    req := httptest.NewRequest("POST", "/v1/secret/"+path, bytes.NewBuffer(reqBody))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Vault-Token", "test-token")

    // Capture HTTP response
    w := httptest.NewRecorder()
    server.writeSecretHandler(w, req)

    // Verify response
    resp := w.Result()
    assert.Equal(t, http.StatusNoContent, resp.StatusCode)

    // Test read secret
    req = httptest.NewRequest("GET", "/v1/secret/"+path, nil)
    req.Header.Set("X-Vault-Token", "test-token")

    w = httptest.NewRecorder()
    server.readSecretHandler(w, req)

    // Verify response
    resp = w.Result()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // Parse response
    var readResp map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&readResp)
    require.NoError(t, err)

    // Check data
    respData, ok := readResp["data"].(map[string]interface{})
    require.True(t, ok)
    assert.Equal(t, "value1", respData["key1"])
    assert.Equal(t, float64(42), respData["key2"])

    // Test list secrets
    req = httptest.NewRequest("GET", "/v1/secret/list/test", nil)
    req.Header.Set("X-Vault-Token", "test-token")

    w = httptest.NewRecorder()
    server.listSecretsHandler(w, req)

    // Verify response
    resp = w.Result()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // Parse response
    var listResp map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&listResp)
    require.NoError(t, err)

    // Check keys
    keys, ok := listResp["keys"].([]interface{})
    require.True(t, ok)
    assert.Contains(t, keys, "secret1")

    // Test delete secret
    req = httptest.NewRequest("DELETE", "/v1/secret/"+path, nil)
    req.Header.Set("X-Vault-Token", "test-token")

    w = httptest.NewRecorder()
    server.deleteSecretHandler(w, req)

    // Verify response
    resp = w.Result()
    assert.Equal(t, http.StatusNoContent, resp.StatusCode)

    // Verify secret is deleted
    req = httptest.NewRequest("GET", "/v1/secret/"+path, nil)
    req.Header.Set("X-Vault-Token", "test-token")

    w = httptest.NewRecorder()
    server.readSecretHandler(w, req)

    // Verify response
    resp = w.Result()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestReplicationWithFollowerOutage tests that replication works correctly when a follower
// is temporarily unavailable and then comes back online
func TestReplicationWithFollowerOutage(t *testing.T) {
    // Skip in short mode
    if testing.Short() {
        t.Skip("Skipping replication outage test in short mode")
    }

    // Set TEST_MODE environment variable for testing
    os.Setenv("TEST_MODE", "true")
    defer os.Unsetenv("TEST_MODE")

    // Create temp directories for servers
    leaderDir, err := os.MkdirTemp("", "securevault-leader")
    require.NoError(t, err)
    defer os.RemoveAll(leaderDir)

    followerDir, err := os.MkdirTemp("", "securevault-follower")
    require.NoError(t, err)
    defer os.RemoveAll(followerDir)

    // Create leader server
    leaderConfig := &Config{
        Server: struct {
            Address string `yaml:"address"`
            Port    int    `yaml:"port"`
            TLS     struct {
                Enabled  bool   `yaml:"enabled"`
                CertFile string `yaml:"cert_file"`
                KeyFile  string `yaml:"key_file"`
            } `yaml:"tls"`
        }{
            Address: "127.0.0.1",
            Port:    8501, // Use different ports from other tests
            TLS: struct {
                Enabled  bool   `yaml:"enabled"`
                CertFile string `yaml:"cert_file"`
                KeyFile  string `yaml:"key_file"`
            }{
                Enabled: false,
            },
        },
        Storage: struct {
            Type string `yaml:"type"`
            Path string `yaml:"path"`
        }{
            Type: "file",
            Path: leaderDir,
        },
        Auth: struct {
            TokenTTL string `yaml:"token_ttl"`
        }{
            TokenTTL: "24h",
        },
        Replication: struct {
            Mode        string   `yaml:"mode"`
            ClusterAddr string   `yaml:"cluster_addr"`
            Peers       []string `yaml:"peers"`
        }{
            Mode:        "leader",
            ClusterAddr: "127.0.0.1:9501",
            Peers:       []string{"127.0.0.1:9502"}, // Will be follower's address
        },
    }

    leaderServer, err := NewServer(leaderConfig)
    require.NoError(t, err)

    // Create follower server
    followerConfig := &Config{
        Server: struct {
            Address string `yaml:"address"`
            Port    int    `yaml:"port"`
            TLS     struct {
                Enabled  bool   `yaml:"enabled"`
                CertFile string `yaml:"cert_file"`
                KeyFile  string `yaml:"key_file"`
            } `yaml:"tls"`
        }{
            Address: "127.0.0.1",
            Port:    8502,
            TLS: struct {
                Enabled  bool   `yaml:"enabled"`
                CertFile string `yaml:"cert_file"`
                KeyFile  string `yaml:"key_file"`
            }{
                Enabled: false,
            },
        },
        Storage: struct {
            Type string `yaml:"type"`
            Path string `yaml:"path"`
        }{
            Type: "file",
            Path: followerDir,
        },
        Auth: struct {
            TokenTTL string `yaml:"token_ttl"`
        }{
            TokenTTL: "24h",
        },
        Replication: struct {
            Mode        string   `yaml:"mode"`
            ClusterAddr string   `yaml:"cluster_addr"`
            Peers       []string `yaml:"peers"`
        }{
            Mode:        "follower",
            ClusterAddr: "127.0.0.1:9502",
            Peers:       []string{"127.0.0.1:9501"}, // Leader's address
        },
    }

    followerServer, err := NewServer(followerConfig)
    require.NoError(t, err)

    // Start leader server
    leaderStartCh := make(chan struct{})
    go func() {
        leaderStartCh <- struct{}{}
        if err := leaderServer.Start(); err != nil && err != http.ErrServerClosed {
            t.Logf("Leader server error: %v", err)
        }
    }()
    <-leaderStartCh // Wait for goroutine to start

    // Start follower server
    followerStartCh := make(chan struct{})
    go func() {
        followerStartCh <- struct{}{}
        if err := followerServer.Start(); err != nil && err != http.ErrServerClosed {
            t.Logf("Follower server error: %v", err)
        }
    }()
    <-followerStartCh // Wait for goroutine to start

    // Create test token
    token := "s.test-outage-token"
    leaderServer.tokenMutex.Lock()
    leaderServer.tokens[token] = TokenInfo{
        ID:        token,
        PolicyIDs: []string{"root"},
        ExpiresAt: time.Now().Add(time.Hour),
    }
    leaderServer.tokenMutex.Unlock()

    followerServer.tokenMutex.Lock()
    followerServer.tokens[token] = TokenInfo{
        ID:        token,
        PolicyIDs: []string{"root"},
        ExpiresAt: time.Now().Add(time.Hour),
    }
    followerServer.tokenMutex.Unlock()

    // Wait for servers to start
    time.Sleep(1 * time.Second)

    // HTTP client for testing
    client := &http.Client{
        Timeout: 2 * time.Second,
    }

    // Phase 1: Write initial data to leader while follower is online
    t.Log("Phase 1: Writing initial data with follower online")
    secretPath := "test/outage"
    initialData := map[string]interface{}{
        "phase": "initial",
        "value": "before-outage",
    }

    // Write to leader
    leaderURL := fmt.Sprintf("http://%s:%d/v1/secret/%s",
        leaderConfig.Server.Address, leaderConfig.Server.Port, secretPath)

    reqBody, err := json.Marshal(initialData)
    require.NoError(t, err)

    req, err := http.NewRequest(http.MethodPost, leaderURL, bytes.NewBuffer(reqBody))
    require.NoError(t, err)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Vault-Token", token)

    resp, err := client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusNoContent, resp.StatusCode)
    resp.Body.Close()

    // Wait for replication to occur
    time.Sleep(1 * time.Second)

    // Verify data replicated to follower
    followerURL := fmt.Sprintf("http://%s:%d/v1/secret/%s",
        followerConfig.Server.Address, followerConfig.Server.Port, secretPath)

    req, err = http.NewRequest(http.MethodGet, followerURL, nil)
    require.NoError(t, err)
    req.Header.Set("X-Vault-Token", token)

    resp, err = client.
