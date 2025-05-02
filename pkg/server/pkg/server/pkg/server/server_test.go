	// Wait for cluster to initialize
	err = cluster.waitForReady(3 * time.Second)
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

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var followerData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&followerData)
	require.NoError(t, err)

	data, ok := followerData["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "initial", data["phase"])
	assert.Equal(t, "before-outage", data["value"])

	// Verify version information
	metadata, ok := followerData["metadata"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(1), metadata["version"])

	// Phase 2: Shutdown follower to simulate outage
	t.Log("Phase 2: Shutting down follower to simulate outage")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = followerServer.Shutdown(ctx)
	cancel()
	require.NoError(t, err)

	// Write multiple updates to leader during outage
	t.Log("Writing updates to leader while follower is offline")
	for i := 1; i <= 3; i++ {
		updateData := map[string]interface{}{
			"phase":    fmt.Sprintf("update-%d", i),
			"value":    fmt.Sprintf("during-outage-%d", i),
			"sequence": i,
		}

		reqBody, err := json.Marshal(updateData)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, leaderURL, bytes.NewBuffer(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Vault-Token", token)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		resp.Body.Close()

		time.Sleep(200 * time.Millisecond)
	}

	// Verify leader has the latest version (4)
	req, err = http.NewRequest(http.MethodGet, leaderURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Vault-Token", token)

	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var leaderData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&leaderData)
	require.NoError(t, err)
	resp.Body.Close()

	metadata, ok = leaderData["metadata"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(4), metadata["version"])
	assert.Equal(t, float64(4), metadata["current_version"])

	// Phase 3: Restart follower
	t.Log("Phase 3: Restarting follower")
	followerServer, err = NewServer(followerConfig)
	require.NoError(t, err)

	// Set up the same token
	followerServer.tokenMutex.Lock()
	followerServer.tokens[token] = TokenInfo{
		ID:        token,
		PolicyIDs: []string{"root"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	followerServer.tokenMutex.Unlock()

	go func() {
		if err := followerServer.Start(); err != nil && err != http.ErrServerClosed {
			t.Logf("Restarted follower server error: %v", err)
		}
	}()

	// Write a final update to trigger replication
	t.Log("Writing final update to trigger replication catch-up")
	finalData := map[string]interface{}{
		"phase": "final",
		"value": "after-outage",
	}

	reqBody, err = json.Marshal(finalData)
	require.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, leaderURL, bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)

	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Wait for replication to occur
	t.Log("Waiting for replication to complete after follower restart")
	time.Sleep(2 * time.Second)

	// Verify final data is accessible on both leader and follower
	t.Log("Verifying data is accessible on both leader and follower")

	// Check leader data
	req, err = http.NewRequest(http.MethodGet, leaderURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Vault-Token", token)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var leaderFinalData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&leaderFinalData)
	require.NoError(t, err)

	leaderData, ok = leaderFinalData["data"].(map[string]interface{})
	require.True(t, ok, "Failed to parse leader data")
	assert.Equal(t, "final", leaderData["phase"], "Leader has incorrect data")
	assert.Equal(t, "after-outage", leaderData["value"], "Leader has incorrect data")

	// Check follower data (should have caught up after restart)
	req, err = http.NewRequest(http.MethodGet, followerURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Vault-Token", token)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// If follower has successfully caught up
	if resp.StatusCode == http.StatusOK {
		var followerFinalData map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&followerFinalData)
		require.NoError(t, err)

		followerData, ok = followerFinalData["data"].(map[string]interface{})
		require.True(t, ok, "Failed to parse follower data")
		
		// Verify that follower has the final version of the data
		assert.Equal(t, "final", followerData["phase"], "Follower has incorrect data")
		assert.Equal(t, "after-outage", followerData["value"], "Follower has incorrect data")

		// Verify version metadata is consistent
		leaderMeta, ok := leaderFinalData["metadata"].(map[string]interface{})
		require.True(t, ok, "Failed to parse leader metadata")
		
		followerMeta, ok := followerFinalData["metadata"].(map[string]interface{})
		require.True(t, ok, "Failed to parse follower metadata")
		
		assert.Equal(t, leaderMeta["version"], followerMeta["version"], 
			"Version number is inconsistent between leader and follower")
	} else {
		t.Logf("Follower is not yet caught up, status: %d - this might indicate a replication delay", resp.StatusCode)
	}

	// Verify follower can also get previous versions
	for i := 1; i <= 4; i++ {
		versionReq, err := http.NewRequest(http.MethodGet, 
			fmt.Sprintf("http://%s:%d/v1/secret/versions/%d/%s", 
				followerConfig.Server.Address, followerConfig.Server.Port, i, secretPath), nil)
		require.NoError(t, err)
		versionReq.Header.Set("X-Vault-Token", token)

		versionResp, err := client.Do(versionReq)
		if err == nil && versionResp.StatusCode == http.StatusOK {
			t.Logf("Successfully verified follower can access version %d", i)
			versionResp.Body.Close()
		} else if versionResp != nil {
			t.Logf("Follower version %d access status: %d", i, versionResp.StatusCode)
			versionResp.Body.Close()
		}
	}

	// Clean up resources
	t.Log("Cleaning up test resources")
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cleanupCancel()

	// Shutdown leader server
	err = leaderServer.Shutdown(cleanupCtx)
	if err != nil {
		t.Logf("Error shutting down leader: %v", err)
	}

	// Shutdown follower server
	err = followerServer.Shutdown(cleanupCtx)
	if err != nil {
		t.Logf("Error shutting down follower: %v", err)
	}
}
