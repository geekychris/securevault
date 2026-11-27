package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"securevault/pkg/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for the behaviour fixed in the "Vault-parity correctness"
// change: token leakage, privilege escalation, KV v2 delete semantics, TTL
// caps, path traversal, replication auth and ordering, and health codes.

func decodeJSON(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &m), string(body))
	return m
}

func createPolicy(t *testing.T, srv *Server, root, name string, rules []map[string]interface{}) {
	t.Helper()
	rr := doRequest(srv, "POST", "/v1/policies", root, map[string]interface{}{
		"policy": map[string]interface{}{"name": name, "rules": rules},
	})
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())
}

func createToken(t *testing.T, srv *Server, parent string, body map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()
	rr := doRequest(srv, "POST", "/v1/auth/token/create", parent, body)
	if rr.Code != http.StatusOK {
		return rr.Code, nil
	}
	return rr.Code, decodeJSON(t, rr.Body.Bytes())["auth"].(map[string]interface{})
}

func TestCreatedByNeverExposesToken(t *testing.T) {
	srv, root, cleanup := testServer(t)
	defer cleanup()

	createPolicy(t, srv, root, "reader", []map[string]interface{}{
		{"path": "app/*", "capabilities": []string{"read"}},
	})
	_, auth := createToken(t, srv, root, map[string]interface{}{"policy_ids": []string{"reader"}})
	reader := auth["client_token"].(string)

	rr := doRequest(srv, "POST", "/v1/secret/app/db", root, map[string]interface{}{"data": map[string]interface{}{"pw": "x"}})
	require.Equal(t, http.StatusNoContent, rr.Code)

	for _, url := range []string{"/v1/secret/app/db", "/v1/secret/versions/1/app/db", "/v1/secret/metadata/app/db"} {
		rr = doRequest(srv, "GET", url, reader, nil)
		if url == "/v1/secret/metadata/app/db" {
			rr = doRequest(srv, "GET", url, root, nil)
		}
		require.Equal(t, http.StatusOK, rr.Code, url)
		assert.NotContains(t, rr.Body.String(), root, "%s leaks the writer's token", url)
		assert.Contains(t, rr.Body.String(), tokenAccessor(root), "%s should name the writer by accessor", url)
	}

	// Nor does the audit log on disk
	logBytes, err := os.ReadFile(srv.config.Audit.Path)
	require.NoError(t, err)
	assert.NotContains(t, string(logBytes), root)
	assert.Contains(t, string(logBytes), tokenAccessor(root))
}

func TestTokenCreateCannotEscalate(t *testing.T) {
	srv, root, cleanup := testServer(t)
	defer cleanup()

	createPolicy(t, srv, root, "app", []map[string]interface{}{
		{"path": "app/*", "capabilities": []string{"read"}},
		{"path": "auth/token/create", "capabilities": []string{"create"}},
	})
	createPolicy(t, srv, root, "other", []map[string]interface{}{
		{"path": "other/*", "capabilities": []string{"read"}},
	})
	_, auth := createToken(t, srv, root, map[string]interface{}{"policy_ids": []string{"app"}, "ttl": "10m"})
	app := auth["client_token"].(string)

	code, _ := createToken(t, srv, app, map[string]interface{}{"policy_ids": []string{"root"}})
	assert.Equal(t, http.StatusForbidden, code, "a non-root token must not mint root")

	code, _ = createToken(t, srv, app, map[string]interface{}{"policy_ids": []string{"app", "other"}})
	assert.Equal(t, http.StatusForbidden, code, "a token must not grant a policy it lacks")

	code, child := createToken(t, srv, app, map[string]interface{}{"ttl": "100h"})
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, []interface{}{"app"}, child["policies"], "child inherits the parent's policies by default")
	assert.LessOrEqual(t, child["lease_duration"].(float64), float64(600), "child must not outlive its parent")

	code, _ = createToken(t, srv, root, map[string]interface{}{"policy_ids": []string{"no-such-policy"}})
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestTokenTTLsAreCapped(t *testing.T) {
	srv, root, cleanup := testServer(t)
	defer cleanup()
	srv.maxTokenTTL = 2 * time.Hour

	code, auth := createToken(t, srv, root, map[string]interface{}{"policy_ids": []string{"root"}, "ttl": "876000h"})
	require.Equal(t, http.StatusOK, code)
	assert.InDelta(t, 7200, auth["lease_duration"].(float64), 2)
	tok := auth["client_token"].(string)

	rr := doRequest(srv, "POST", "/v1/auth/token/renew-self", tok, map[string]interface{}{"ttl": "876000h"})
	require.Equal(t, http.StatusNoContent, rr.Code)
	rr = doRequest(srv, "GET", "/v1/auth/token/lookup-self", tok, nil)
	ttl := decodeJSON(t, rr.Body.Bytes())["data"].(map[string]interface{})["ttl"].(float64)
	assert.LessOrEqual(t, ttl, float64(7200), "renewal must not extend past token_max_ttl from creation")

	rr = doRequest(srv, "POST", "/v1/auth/token/create", root, map[string]interface{}{"ttl": "-5m"})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestInitRootTokenDoesNotExpire(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{}
	config.Server.Address = "127.0.0.1"
	config.Storage.Type = "file"
	config.Storage.Path = tmpDir
	srv, err := NewServer(config)
	require.NoError(t, err)

	rr := doRequest(srv, "POST", "/v1/sys/init", "", map[string]interface{}{"secret_shares": 1, "secret_threshold": 1})
	require.Equal(t, http.StatusOK, rr.Code)
	root := decodeJSON(t, rr.Body.Bytes())["root_token"].(string)

	rr = doRequest(srv, "GET", "/v1/auth/token/lookup-self", root, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	data := decodeJSON(t, rr.Body.Bytes())["data"].(map[string]interface{})
	assert.Nil(t, data["expire_time"])
	assert.Equal(t, float64(0), data["ttl"])

	// Survives a restart (token store reload) and stays valid
	srv.persistTokens()
	srv.tokens = map[string]TokenInfo{}
	srv.loadTokens()
	_, err = srv.validateToken(root)
	assert.NoError(t, err)
}

func TestDeleteIsSoftAndUndeleteRestores(t *testing.T) {
	srv, root, cleanup := testServer(t)
	defer cleanup()

	write := func(v string) {
		rr := doRequest(srv, "POST", "/v1/secret/kv/item", root, map[string]interface{}{"data": map[string]interface{}{"v": v}})
		require.Equal(t, http.StatusNoContent, rr.Code)
	}
	write("one")
	write("two")

	// Plain DELETE soft-deletes the current version
	rr := doRequest(srv, "DELETE", "/v1/secret/kv/item", root, nil)
	require.Equal(t, http.StatusNoContent, rr.Code)
	rr = doRequest(srv, "GET", "/v1/secret/kv/item", root, nil)
	assert.Equal(t, http.StatusNotFound, rr.Code, "a deleted secret must not be readable")
	rr = doRequest(srv, "GET", "/v1/secret/versions/1/kv/item", root, nil)
	assert.Equal(t, http.StatusOK, rr.Code, "older versions stay readable")

	// Undelete restores it
	rr = doRequest(srv, "POST", "/v1/secret/undelete/kv/item", root, map[string]interface{}{"versions": []int{2}})
	require.Equal(t, http.StatusNoContent, rr.Code)
	rr = doRequest(srv, "GET", "/v1/secret/kv/item", root, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "two", decodeJSON(t, rr.Body.Bytes())["data"].(map[string]interface{})["v"])

	// Destroying a version is permanent
	rr = doRequest(srv, "DELETE", "/v1/secret/kv/item?versions=1&destroy=true", root, nil)
	require.Equal(t, http.StatusNoContent, rr.Code)
	rr = doRequest(srv, "GET", "/v1/secret/versions/1/kv/item", root, nil)
	assert.Equal(t, http.StatusGone, rr.Code)
	rr = doRequest(srv, "POST", "/v1/secret/undelete/kv/item", root, map[string]interface{}{"versions": []int{1}})
	require.Equal(t, http.StatusNoContent, rr.Code)
	rr = doRequest(srv, "GET", "/v1/secret/versions/1/kv/item", root, nil)
	assert.Equal(t, http.StatusGone, rr.Code, "a destroyed version cannot be undeleted")
}

func TestUnsafePathsAndNamesRejected(t *testing.T) {
	srv, root, cleanup := testServer(t)
	defer cleanup()

	for _, p := range []string{"../x", "a/../../x", "a//b", "./a", "a/.", "/abs", `a\b`, "a\x00b"} {
		assert.Error(t, storage.ValidatePath(p, false), p)
	}
	assert.NoError(t, storage.ValidatePath("", true))
	assert.NoError(t, storage.ValidatePath("app/", true))
	assert.NoError(t, storage.ValidatePath("app/db-1.prod_x", false))

	rr := doRequest(srv, "POST", "/v1/policies", root, map[string]interface{}{
		"policy": map[string]interface{}{"name": "../../escape", "rules": []map[string]interface{}{{"path": "x", "capabilities": []string{"read"}}}},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	_, err := os.Stat(srv.config.Storage.Path + "/../escape.yaml")
	assert.True(t, os.IsNotExist(err), "policy file must not be written outside the policies dir")

	rr = doRequest(srv, "POST", "/v1/policies", root, map[string]interface{}{
		"policy": map[string]interface{}{"name": "bad-cap", "rules": []map[string]interface{}{{"path": "x", "capabilities": []string{"sudo"}}}},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code, "an invalid policy is a client error")

	rr = doRequest(srv, "DELETE", "/v1/policies/root", root, nil)
	assert.Equal(t, http.StatusForbidden, rr.Code, "the root policy cannot be deleted")

	for _, reserved := range []string{"metadata/x", "versions/x", "list/x"} {
		rr = doRequest(srv, "POST", "/v1/secret/"+reserved, root, map[string]interface{}{"data": map[string]interface{}{"a": 1}})
		assert.Equal(t, http.StatusBadRequest, rr.Code, reserved)
	}
}

func TestClusterModeRequiresSharedSecret(t *testing.T) {
	for _, mode := range []string{"leader", "follower"} {
		config := &Config{}
		config.Storage.Type = "file"
		config.Storage.Path = t.TempDir()
		config.Replication.Mode = mode
		_, err := NewServer(config)
		assert.Error(t, err, mode)
	}
	config := &Config{}
	config.Storage.Type = "file"
	config.Storage.Path = t.TempDir()
	config.Replication.Mode = "leeder"
	_, err := NewServer(config)
	assert.Error(t, err, "unknown modes are rejected")
}

func TestReplicationEndpointRejectsUnsafeInput(t *testing.T) {
	node := startNode(t, "follower", getFreePort(), []string{"127.0.0.1:1"}, "s3cret")
	defer os.RemoveAll(node.tmpDir)
	defer node.server.httpServer.Close()
	initAndUnseal(t, node)

	post := func(token string, body map[string]interface{}) int {
		rr := doRequestWithHeader(node.server, "POST", "/v1/replication/data", body, "X-Replication-Token", token)
		return rr.Code
	}
	assert.Equal(t, http.StatusUnauthorized, post("wrong", map[string]interface{}{"path": "a", "data": map[string]interface{}{}}))
	assert.Equal(t, http.StatusBadRequest, post("s3cret", map[string]interface{}{"path": "../../escaped", "data": map[string]interface{}{"a": 1}}))
	_, err := os.Stat(node.tmpDir + "/../escaped")
	assert.True(t, os.IsNotExist(err))
	assert.Equal(t, http.StatusOK, post("s3cret", map[string]interface{}{"path": "ok/x", "data": map[string]interface{}{"a": 1}}))

	node.server.sealManager.Seal()
	assert.Equal(t, http.StatusServiceUnavailable, post("s3cret", map[string]interface{}{"path": "ok/y", "data": map[string]interface{}{"a": 1}}))
}

func TestReplicationDeliversOnceInOrderIncludingDeletes(t *testing.T) {
	secret := "repl-once"
	fPort, lPort := getFreePort(), getFreePort()
	follower := startNode(t, "follower", fPort, []string{fmt.Sprintf("127.0.0.1:%d", lPort)}, secret)
	defer os.RemoveAll(follower.tmpDir)
	defer follower.server.httpServer.Close()
	fRoot := initAndUnseal(t, follower)

	leader := startNode(t, "leader", lPort, []string{fmt.Sprintf("127.0.0.1:%d", fPort)}, secret)
	defer os.RemoveAll(leader.tmpDir)
	defer leader.server.Shutdown(context.Background())
	lRoot := initAndUnseal(t, leader)
	time.Sleep(700 * time.Millisecond)

	for _, v := range []string{"one", "two"} {
		rr := leader.doRequest("POST", "/v1/secret/r/item", lRoot, map[string]interface{}{"data": map[string]interface{}{"v": v}})
		require.Equal(t, http.StatusNoContent, rr.Code)
	}

	// Wait well past a periodic sync tick: a replayed log would add versions
	require.Eventually(t, func() bool {
		return follower.doRequest("GET", "/v1/secret/r/item", fRoot, nil).Code == http.StatusOK
	}, 5*time.Second, 100*time.Millisecond)
	time.Sleep(6 * time.Second)

	rr := follower.doRequest("GET", "/v1/secret/metadata/r/item", fRoot, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, float64(2), decodeJSON(t, rr.Body.Bytes())["current_version"], "each write must apply exactly once")

	rr = leader.doRequest("DELETE", "/v1/secret/r/item", lRoot, nil)
	require.Equal(t, http.StatusNoContent, rr.Code)
	assert.Eventually(t, func() bool {
		return follower.doRequest("GET", "/v1/secret/r/item", fRoot, nil).Code == http.StatusNotFound
	}, 5*time.Second, 100*time.Millisecond, "deletes must replicate")
}

func TestSysHealthStatusCodes(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{}
	config.Storage.Type = "file"
	config.Storage.Path = tmpDir
	srv, err := NewServer(config)
	require.NoError(t, err)

	code := func(q string) int { return doRequest(srv, "GET", "/v1/sys/health"+q, "", nil).Code }

	assert.Equal(t, http.StatusNotImplemented, code(""))
	assert.Equal(t, http.StatusOK, code("?uninitcode=200"))

	_, err = srv.sealManager.Initialize(1, 1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code(""))

	srv.clusterMu.Lock()
	srv.activeRole = "follower"
	srv.clusterMu.Unlock()
	assert.Equal(t, http.StatusTooManyRequests, code(""))
	assert.Equal(t, http.StatusOK, code("?standbyok=true"))

	require.NoError(t, srv.sealManager.Seal())
	assert.Equal(t, http.StatusServiceUnavailable, code(""))
	assert.Equal(t, http.StatusOK, code("?sealedcode=200&uninitcode=200"))
}

func doRequestWithHeader(srv *Server, method, path string, body interface{}, header, value string) *httptest.ResponseRecorder {
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(header, value)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}
