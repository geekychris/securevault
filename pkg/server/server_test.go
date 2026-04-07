package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"securevault/pkg/seal"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServer creates a server for testing, initializes and unseals it, returns server + root token
func testServer(t *testing.T) (*Server, string, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "securevault-test")
	require.NoError(t, err)

	config := &Config{}
	config.Server.Address = "127.0.0.1"
	config.Server.Port = 0
	config.Storage.Type = "file"
	config.Storage.Path = tmpDir
	config.Auth.TokenTTL = "1h"
	config.Seal.SecretShares = 1
	config.Seal.SecretThreshold = 1
	config.Audit.Enabled = true
	config.Audit.Path = tmpDir + "/audit/audit.log"

	srv, err := NewServer(config)
	require.NoError(t, err)

	// Initialize vault
	initResp, err := srv.sealManager.Initialize(1, 1)
	require.NoError(t, err)

	// Store root token
	rootToken := initResp.RootToken
	srv.tokenMutex.Lock()
	srv.tokens[rootToken] = TokenInfo{
		ID:        rootToken,
		PolicyIDs: []string{"root"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	srv.tokenMutex.Unlock()

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return srv, rootToken, cleanup
}

func doRequest(srv *Server, method, path, token string, body interface{}) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func TestServerSetup(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()

	assert.NotNil(t, srv)
	assert.False(t, srv.sealManager.IsSealed())
	assert.True(t, srv.sealManager.IsInitialized())
}

func TestHealthCheck(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()

	rr := doRequest(srv, "GET", "/v1/health", "", nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "ok", resp["status"])
	assert.Equal(t, false, resp["sealed"])
}

func TestHealthCheckWhenSealed(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Seal the vault
	rr := doRequest(srv, "POST", "/v1/sys/seal", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Health should show sealed
	rr = doRequest(srv, "GET", "/v1/health", "", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "sealed", resp["status"])
}

func TestSealUnsealCycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securevault-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	config := &Config{}
	config.Server.Address = "127.0.0.1"
	config.Server.Port = 0
	config.Storage.Type = "file"
	config.Storage.Path = tmpDir
	config.Auth.TokenTTL = "1h"
	config.Seal.SecretShares = 3
	config.Seal.SecretThreshold = 2

	srv, err := NewServer(config)
	require.NoError(t, err)

	// Check initial seal status
	rr := doRequest(srv, "GET", "/v1/sys/seal-status", "", nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	var status seal.SealStatus
	json.Unmarshal(rr.Body.Bytes(), &status)
	assert.True(t, status.Sealed)
	assert.False(t, status.Initialized)

	// Initialize
	rr = doRequest(srv, "POST", "/v1/sys/init", "", map[string]int{
		"secret_shares":    3,
		"secret_threshold": 2,
	})
	assert.Equal(t, http.StatusOK, rr.Code)

	var initResp seal.InitResponse
	json.Unmarshal(rr.Body.Bytes(), &initResp)
	assert.Len(t, initResp.Keys, 3)
	assert.NotEmpty(t, initResp.RootToken)

	rootToken := initResp.RootToken

	// Seal the vault
	rr = doRequest(srv, "POST", "/v1/sys/seal", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Try to access a secret while sealed
	rr = doRequest(srv, "GET", "/v1/secret/test", rootToken, nil)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	// Unseal with first key
	rr = doRequest(srv, "POST", "/v1/sys/unseal", "", map[string]string{
		"key": initResp.Keys[0],
	})
	assert.Equal(t, http.StatusOK, rr.Code)
	json.Unmarshal(rr.Body.Bytes(), &status)
	assert.True(t, status.Sealed) // Still sealed, need one more
	assert.Equal(t, 1, status.Progress)

	// Unseal with second key
	rr = doRequest(srv, "POST", "/v1/sys/unseal", "", map[string]string{
		"key": initResp.Keys[1],
	})
	assert.Equal(t, http.StatusOK, rr.Code)
	json.Unmarshal(rr.Body.Bytes(), &status)
	assert.False(t, status.Sealed) // Now unsealed
}

func TestSecretCRUD(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Write a secret
	rr := doRequest(srv, "POST", "/v1/secret/app/db/password", rootToken, map[string]interface{}{
		"data": map[string]interface{}{
			"username": "admin",
			"password": "secret123",
		},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Read the secret
	rr = doRequest(srv, "GET", "/v1/secret/app/db/password", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	var readResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &readResp)
	data := readResp["data"].(map[string]interface{})
	assert.Equal(t, "admin", data["username"])
	assert.Equal(t, "secret123", data["password"])

	// Read non-existent secret
	rr = doRequest(srv, "GET", "/v1/secret/nonexistent", rootToken, nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Delete the secret
	rr = doRequest(srv, "DELETE", "/v1/secret/app/db/password?destroy=true", rootToken, nil)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify it's deleted
	rr = doRequest(srv, "GET", "/v1/secret/app/db/password", rootToken, nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSecretVersioning(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Write v1
	rr := doRequest(srv, "POST", "/v1/secret/app/config", rootToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "value1"},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Write v2
	rr = doRequest(srv, "POST", "/v1/secret/app/config", rootToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "value2"},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Read latest (should be v2)
	rr = doRequest(srv, "GET", "/v1/secret/app/config", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "value2", resp["data"].(map[string]interface{})["key"])

	// Read v1
	rr = doRequest(srv, "GET", "/v1/secret/versions/1/app/config", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "value1", resp["data"].(map[string]interface{})["key"])

	// Check metadata
	rr = doRequest(srv, "GET", "/v1/secret/metadata/app/config", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, float64(2), resp["current_version"])
}

func TestAuthentication(t *testing.T) {
	srv, _, cleanup := testServer(t)
	defer cleanup()

	// No token
	rr := doRequest(srv, "GET", "/v1/secret/test", "", nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// Invalid token
	rr = doRequest(srv, "GET", "/v1/secret/test", "invalid-token", nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestTokenManagement(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Create a token
	rr := doRequest(srv, "POST", "/v1/auth/token/create", rootToken, map[string]interface{}{
		"policy_ids": []string{"root"},
		"ttl":        "1h",
	})
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	auth := tokenResp["auth"].(map[string]interface{})
	newToken := auth["client_token"].(string)
	assert.NotEmpty(t, newToken)
	assert.True(t, len(newToken) > 20) // Cryptographically generated, should be long

	// Lookup the new token
	rr = doRequest(srv, "GET", "/v1/auth/token/lookup-self", newToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Use the new token to read
	rr = doRequest(srv, "POST", "/v1/secret/test/key", newToken, map[string]interface{}{
		"data": map[string]interface{}{"value": "test"},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Revoke the token
	rr = doRequest(srv, "POST", "/v1/auth/token/revoke-self", newToken, nil)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Token should no longer work
	rr = doRequest(srv, "GET", "/v1/secret/test/key", newToken, nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestPolicyEnforcement(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Create a read-only policy
	rr := doRequest(srv, "POST", "/v1/policies", rootToken, map[string]interface{}{
		"policy": map[string]interface{}{
			"name":        "readonly",
			"description": "Read-only access to app/*",
			"rules": []map[string]interface{}{
				{
					"path":         "app/*",
					"capabilities": []string{"read", "list"},
				},
			},
		},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Create a token with the read-only policy
	rr = doRequest(srv, "POST", "/v1/auth/token/create", rootToken, map[string]interface{}{
		"policy_ids": []string{"readonly"},
		"ttl":        "1h",
	})
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	readOnlyToken := tokenResp["auth"].(map[string]interface{})["client_token"].(string)

	// Write a secret with root token first
	rr = doRequest(srv, "POST", "/v1/secret/app/data", rootToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Read should work with read-only token
	rr = doRequest(srv, "GET", "/v1/secret/app/data", readOnlyToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Write should fail with read-only token
	rr = doRequest(srv, "POST", "/v1/secret/app/data", readOnlyToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "updated"},
	})
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Delete should fail
	rr = doRequest(srv, "DELETE", "/v1/secret/app/data?destroy=true", readOnlyToken, nil)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Access outside allowed path should fail
	rr = doRequest(srv, "GET", "/v1/secret/other/data", readOnlyToken, nil)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestPolicyCRUD(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Create policy
	rr := doRequest(srv, "POST", "/v1/policies", rootToken, map[string]interface{}{
		"policy": map[string]interface{}{
			"name":        "test-policy",
			"description": "Test policy",
			"rules": []map[string]interface{}{
				{
					"path":         "secret/*",
					"capabilities": []string{"read"},
				},
			},
		},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Get policy
	rr = doRequest(srv, "GET", "/v1/policies/test-policy", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	// List policies
	rr = doRequest(srv, "GET", "/v1/policies", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Update policy
	rr = doRequest(srv, "PUT", "/v1/policies/test-policy", rootToken, map[string]interface{}{
		"policy": map[string]interface{}{
			"name":        "test-policy",
			"description": "Updated test policy",
			"rules": []map[string]interface{}{
				{
					"path":         "secret/*",
					"capabilities": []string{"read", "list"},
				},
			},
		},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Delete policy
	rr = doRequest(srv, "DELETE", "/v1/policies/test-policy", rootToken, nil)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify deleted
	rr = doRequest(srv, "GET", "/v1/policies/test-policy", rootToken, nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSealedOperationsBlocked(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Write a secret
	rr := doRequest(srv, "POST", "/v1/secret/test", rootToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Seal the vault
	rr = doRequest(srv, "POST", "/v1/sys/seal", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	// All secret operations should return 503
	rr = doRequest(srv, "GET", "/v1/secret/test", rootToken, nil)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	rr = doRequest(srv, "POST", "/v1/secret/test2", rootToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	rr = doRequest(srv, "POST", "/v1/auth/token/create", rootToken, map[string]interface{}{
		"policy_ids": []string{"root"},
	})
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	// But seal status should still work
	rr = doRequest(srv, "GET", "/v1/sys/seal-status", "", nil)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestAuditLog(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Perform some operations
	doRequest(srv, "POST", "/v1/secret/audit-test", rootToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	doRequest(srv, "GET", "/v1/secret/audit-test", rootToken, nil)

	// Query audit log
	rr := doRequest(srv, "GET", "/v1/audit/events", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	events := resp["events"].([]interface{})
	assert.Greater(t, len(events), 0)
}

func TestTokenExpiration(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Create a token with very short TTL
	rr := doRequest(srv, "POST", "/v1/auth/token/create", rootToken, map[string]interface{}{
		"policy_ids": []string{"root"},
		"ttl":        "1ms",
	})
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	shortToken := tokenResp["auth"].(map[string]interface{})["client_token"].(string)

	// Wait for it to expire
	time.Sleep(10 * time.Millisecond)

	// Should be unauthorized
	rr = doRequest(srv, "GET", "/v1/secret/test", shortToken, nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestListSecrets(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Write some secrets
	for i := 0; i < 3; i++ {
		rr := doRequest(srv, "POST", fmt.Sprintf("/v1/secret/list-test/item%d", i), rootToken, map[string]interface{}{
			"data": map[string]interface{}{"key": fmt.Sprintf("value%d", i)},
		})
		assert.Equal(t, http.StatusNoContent, rr.Code)
	}

	// List secrets
	rr := doRequest(srv, "GET", "/v1/secret/list/list-test", rootToken, nil)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	keys := resp["keys"].([]interface{})
	assert.Equal(t, 3, len(keys))
}

func TestDuplicatePolicyCreation(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	pol := map[string]interface{}{
		"policy": map[string]interface{}{
			"name": "dup-policy",
			"rules": []map[string]interface{}{
				{"path": "test/*", "capabilities": []string{"read"}},
			},
		},
	}

	rr := doRequest(srv, "POST", "/v1/policies", rootToken, pol)
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Second creation should fail
	rr = doRequest(srv, "POST", "/v1/policies", rootToken, pol)
	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestWriteRequiresCreateForNewSecrets(t *testing.T) {
	srv, rootToken, cleanup := testServer(t)
	defer cleanup()

	// Create a policy with only update capability (no create)
	rr := doRequest(srv, "POST", "/v1/policies", rootToken, map[string]interface{}{
		"policy": map[string]interface{}{
			"name": "update-only",
			"rules": []map[string]interface{}{
				{"path": "app/*", "capabilities": []string{"update", "read"}},
			},
		},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Create token with update-only policy
	rr = doRequest(srv, "POST", "/v1/auth/token/create", rootToken, map[string]interface{}{
		"policy_ids": []string{"update-only"},
		"ttl":        "1h",
	})
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	updateToken := tokenResp["auth"].(map[string]interface{})["client_token"].(string)

	// Writing a NEW secret should fail (needs create capability)
	rr = doRequest(srv, "POST", "/v1/secret/app/new-secret", updateToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Create the secret with root token first
	rr = doRequest(srv, "POST", "/v1/secret/app/existing", rootToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "original"},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Updating existing secret should work
	rr = doRequest(srv, "POST", "/v1/secret/app/existing", updateToken, map[string]interface{}{
		"data": map[string]interface{}{"key": "updated"},
	})
	assert.Equal(t, http.StatusNoContent, rr.Code)
}
