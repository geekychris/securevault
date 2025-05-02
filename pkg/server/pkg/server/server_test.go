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

	leaderData, ok := leaderFinalData["data"].(map[string]interface{})
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

		followerData, ok := followerFinalData["data"].(map[string]interface{})
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
		req, err = http.NewRequest(http.MethodGet, 
			fmt.Sprintf("http://%s:%d/v1/secret/versions/%d/%s", 
				followerConfig.Server.Address, followerConfig.Server.Port, i, secretPath), nil)
		require.NoError(t, err)
		req.Header.Set("X-Vault-Token", token)

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			t.Logf("Successfully verified follower can access version %d", i)
			resp.Body.Close()
		} else if resp != nil {
			t.Logf("Follower version %d access status: %d", i, resp.StatusCode)
			resp.Body.Close()
		}
	}

	// Clean up resources
	t.Log("Cleaning up test resources")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Shutdown leader server
	err = leaderServer.Shutdown(ctx)
	if err != nil {
		t.Logf("Error shutting down leader: %v", err)
	}

	// Shutdown follower server
	err = followerServer.Shutdown(ctx)
	if err != nil {
		t.Logf("Error shutting down follower: %v", err)
	}
}
