package policy

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testDir   string         // Temporary directory for testing
	policyMgr *Manager       // Policy manager for tests
	testMutex sync.Mutex     // Mutex to synchronize test execution
)

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	// Create a temporary directory for test policies
	var err error
	testDir, err = os.MkdirTemp("", "securevault-policy-test")
	if err != nil {
		fmt.Printf("Failed to create temp directory: %v\n", err)
		os.Exit(1)
	}

	// Create a policy manager for tests
	policyMgr, err = NewManager(testDir)
	if err != nil {
		fmt.Printf("Failed to create policy manager: %v\n", err)
		os.RemoveAll(testDir)
		os.Exit(1)
	}

	// Run tests
	exitCode := m.Run()

	// Clean up
	os.RemoveAll(testDir)
	os.Exit(exitCode)
}

// TestPolicyManagement tests the basic policy management operations
func TestPolicyManagement(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	// Create test policies
	adminPolicy := &Policy{
		Name:        "admin",
		Description: "Administrator policy",
		Rules: []PathRule{
			{
				Path:         "secret/*",
				Capabilities: []Capability{CreateCapability, ReadCapability, UpdateCapability, DeleteCapability, ListCapability},
			},
			{
				Path:         "system/*",
				Capabilities: []Capability{ReadCapability, ListCapability},
			},
		},
	}

	appPolicy := &Policy{
		Name:        "app",
		Description: "Application policy",
		Rules: []PathRule{
			{
				Path:         "secret/app/*",
				Capabilities: []Capability{ReadCapability, ListCapability},
			},
		},
	}

	// Test policy creation
	t.Run("CreatePolicy", func(t *testing.T) {
		err := policyMgr.CreatePolicy(adminPolicy)
		require.NoError(t, err, "Failed to create admin policy")

		err = policyMgr.CreatePolicy(appPolicy)
		require.NoError(t, err, "Failed to create app policy")

		// Creating a duplicate policy should fail
		err = policyMgr.CreatePolicy(adminPolicy)
		assert.Error(t, err, "Creating duplicate policy should fail")
		assert.Contains(t, err.Error(), "already exists", "Error should mention policy already exists")
	})

	// Test policy retrieval
	t.Run("GetPolicy", func(t *testing.T) {
		// Get existing policy
		policy, err := policyMgr.GetPolicy("admin")
		require.NoError(t, err, "Failed to get admin policy")
		assert.Equal(t, "admin", policy.Name, "Policy name mismatch")
		assert.Equal(t, "Administrator policy", policy.Description, "Policy description mismatch")
		assert.Len(t, policy.Rules, 2, "Policy rules count mismatch")

		// Getting non-existent policy should fail
		_, err = policyMgr.GetPolicy("non-existent")
		assert.Error(t, err, "Getting non-existent policy should fail")
		assert.Contains(t, err.Error(), "not found", "Error should mention policy not found")
	})

	// Test policy update
	t.Run("UpdatePolicy", func(t *testing.T) {
		// Get policy
		policy, err := policyMgr.GetPolicy("admin")
		require.NoError(t, err, "Failed to get admin policy")

		// Update policy
		policy.Description = "Updated admin policy"
		policy.Rules = append(policy.Rules, PathRule{
			Path:         "audit/*",
			Capabilities: []Capability{ReadCapability},
		})

		err = policyMgr.UpdatePolicy(policy)
		require.NoError(t, err, "Failed to update admin policy")

		// Verify update
		updatedPolicy, err := policyMgr.GetPolicy("admin")
		require.NoError(t, err, "Failed to get updated admin policy")
		assert.Equal(t, "Updated admin policy", updatedPolicy.Description, "Updated description mismatch")
		assert.Len(t, updatedPolicy.Rules, 3, "Updated rules count mismatch")

		// Updating non-existent policy should fail
		nonExistentPolicy := &Policy{
			Name:        "non-existent",
			Description: "Non-existent policy",
		}
		err = policyMgr.UpdatePolicy(nonExistentPolicy)
		assert.Error(t, err, "Updating non-existent policy should fail")
		assert.Contains(t, err.Error(), "not found", "Error should mention policy not found")
	})

	// Test policy deletion
	t.Run("DeletePolicy", func(t *testing.T) {
		// Delete policy
		err := policyMgr.DeletePolicy("app")
		require.NoError(t, err, "Failed to delete app policy")

		// Verify deletion
		_, err = policyMgr.GetPolicy("app")
		assert.Error(t, err, "Getting deleted policy should fail")
		assert.Contains(t, err.Error(), "not found", "Error should mention policy not found")

		// Deleting non-existent policy should fail
		err = policyMgr.DeletePolicy("non-existent")
		assert.Error(t, err, "Deleting non-existent policy should fail")
		assert.Contains(t, err.Error(), "not found", "Error should mention policy not found")
	})

	// Test listing policies
	t.Run("ListPolicies", func(t *testing.T) {
		// Only admin policy should be left
		policies := policyMgr.ListPolicies()
		assert.Len(t, policies, 1, "Should have 1 policy")
		assert.Equal(t, "admin", policies[0].Name, "Policy name mismatch")
	})
}

// TestPathMatching tests path matching with various patterns
func TestPathMatching(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	// Create a test policy with various path patterns
	patternPolicy := &Policy{
		Name:        "patterns",
		Description: "Policy with various path patterns",
		Rules: []PathRule{
			{
				Path:         "exact/path",
				Capabilities: []Capability{ReadCapability},
			},
			{
				Path:         "wildcard/*",
				Capabilities: []Capability{ReadCapability},
			},
			{
				Path:         "nested/*/paths",
				Capabilities: []Capability{ReadCapability},
			},
			{
				Path:         "multiple/*/wildcards/*",
				Capabilities: []Capability{ReadCapability},
			},
		},
	}

	// Compile the policy (normally done by CreatePolicy, but we're testing the internal method)
	err := policyMgr.validateAndCompilePolicy(patternPolicy)
	require.NoError(t, err, "Failed to validate and compile policy")

	// Test cases for path matching
	testCases := []struct {
		path    string
		matches bool
		rule    int
	}{
		// Exact path
		{"exact/path", true, 0},
		{"exact/other", false, 0},
		{"exact/path/sub", false, 0},

		// Wildcard
		{"wildcard/anything", true, 1},
		{"wildcard/nested/deep", false, 1},
		{"wildcard", false, 1},

		// Nested wildcards
		{"nested/anything/paths", true, 2},
		{"nested/multi/segment/paths", false, 2},

		// Multiple wildcards
		{"multiple/one/wildcards/two", true, 3},
		{"multiple/wildcards", false, 3},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			if tc.matches {
				assert.True(t, patternPolicy.Rules[tc.rule].compiledPath.MatchString(tc.path),
					"Path %s should match rule %d", tc.path, tc.rule)
			} else {
				// If it shouldn't match this rule, either compiledPath is nil or it doesn't match
				if patternPolicy.Rules[tc.rule].compiledPath != nil {
					assert.False(t, patternPolicy.Rules[tc.rule].compiledPath.MatchString(tc.path),
						"Path %s should not match rule %d", tc.path, tc.rule)
				}
			}
		})
	}
}

// TestCapabilityChecking tests the capability checking logic
func TestCapabilityChecking(t *testing.T) {
	// Create policies with a clean directory
	testPolicyDir := "./capability-test-policies-" + fmt.Sprintf("%d", time.Now().UnixNano())
	policyMgr, err := NewManager(testPolicyDir)
	require.NoError(t, err)
	defer os.RemoveAll(testPolicyDir)
	
	// Define test policies
	adminPolicy := &Policy{
		Name:        "admin",
		Description: "Administrator policy",
		Rules: []PathRule{
			{
				Path:         "*",
				Capabilities: []Capability{CreateCapability, ReadCapability, UpdateCapability, DeleteCapability, ListCapability},
			},
		},
	}
	
	appReadOnlyPolicy := &Policy{
		Name:        "app-readonly",
		Description: "Read-only access to app secrets",
		Rules: []PathRule{
			{
				Path:         "secret/app/*",
				Capabilities: []Capability{ReadCapability, ListCapability},
			},
		},
	}

	dbWritePolicy := &Policy{
		Name:        "db-write",
		Description: "Write access to database secrets",
		Rules: []PathRule{
			{
				Path:         "secret/database/*",
				Capabilities: []Capability{CreateCapability, ReadCapability, UpdateCapability},
			},
		},
	}

	// Create policies
	require.NoError(t, policyMgr.CreatePolicy(adminPolicy), "Failed to create admin policy")
	require.NoError(t, policyMgr.CreatePolicy(appReadOnlyPolicy), "Failed to create app-readonly policy")
	require.NoError(t, policyMgr.CreatePolicy(dbWritePolicy), "Failed to create db-write policy")

	// Test capability checking
	tests := []struct {
		name       string
		policyIDs  []string
		path       string
		capability Capability
		allowed    bool
	}{
		// Admin policy tests
		{"AdminAllAccess", []string{"admin"}, "secret/any/path", ReadCapability, true},
		{"AdminCreateAccess", []string{"admin"}, "system/config", CreateCapability, true},

		// App read-only policy tests
		{"AppReadAccess", []string{"app-readonly"}, "secret/app/config", ReadCapability, true},
		{"AppListAccess", []string{"app-readonly"}, "secret/app", ListCapability, true},
		{"AppNoWriteAccess", []string{"app-readonly"}, "secret/app/config", CreateCapability, false},
		{"AppNoDeleteAccess", []string{"app-readonly"}, "secret/app/config", DeleteCapability, false},
		{"AppNoSystemAccess", []string{"app-readonly"}, "system/config", ReadCapability, false},

		// DB write policy tests
		{"DBWriteAccess", []string{"db-write"}, "secret/database/creds", CreateCapability, true},
		{"DBReadAccess", []string{"db-write"}, "secret/database/creds", ReadCapability, true},
		{"DBUpdateAccess", []string{"db-write"}, "secret/database/creds", UpdateCapability, true},
		{"DBNoDeleteAccess", []string{"db-write"}, "secret/database/creds", DeleteCapability, false},

		// Multiple policies
		{"MultiplePoliciesAllow", []string{"app-readonly", "db-write"}, "secret/app/config", ReadCapability, true},
		{"MultiplePoliciesAllow2", []string{"app-readonly", "db-write"}, "secret/database/creds", CreateCapability, true},
		{"MultiplePoliciesDeny", []string{"app-readonly", "db-write"}, "system/config", CreateCapability, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := policyMgr.CheckPermission(tc.policyIDs, tc.path, tc.capability)
			assert.Equal(t, tc.allowed, result, "Unexpected permission result")
		})
	}
}

// TestConcurrentPolicyOperations tests concurrent policy operations
func TestConcurrentPolicyOperations(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	// Reset the policy manager to start fresh
	var err error
	policyMgr, err = NewManager(testDir)
	require.NoError(t, err, "Failed to create fresh policy manager")

	const (
		numGoroutines = 10
		policiesPerGoroutine = 5
	)

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*policiesPerGoroutine)

	// Launch goroutines to create, read, update, and delete policies concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < policiesPerGoroutine; j++ {
				policyName := fmt.Sprintf("concurrent-policy-%d-%d", id, j)
				
				// Create policy
				policy := &Policy{
					Name:        policyName,
					Description: fmt.Sprintf("Concurrent test policy %d-%d", id, j),
					Rules: []PathRule{
						{
							Path:         fmt.Sprintf("test/%d/%d/*", id, j),
							Capabilities: []Capability{ReadCapability, ListCapability},
						},
					},
				}

				if err := policyMgr.CreatePolicy(policy); err != nil {
					errors <- fmt.Errorf("failed to create policy %s: %v", policyName, err)
					return
				}

				// Read and verify policy
				readPolicy, err := policyMgr.GetPolicy(policyName)
				if err != nil {
					errors <- fmt.Errorf("failed to read policy %s: %v", policyName, err)
					return
				}

				if readPolicy.Name != policyName {
					errors <- fmt.Errorf("policy name mismatch: expected %s, got %s", policyName, readPolicy.Name)
					return
				}

				// Update policy
				readPolicy.Description = fmt.Sprintf("Updated concurrent test policy %d-%d", id, j)
				readPolicy.Rules = append(readPolicy.Rules, PathRule{
					Path:         fmt.Sprintf("test/%d/%d/extra/*", id, j),
					Capabilities: []Capability{CreateCapability, ReadCapability},
				})

				if err := policyMgr.UpdatePolicy(readPolicy); err != nil {
					errors <- fmt.Errorf("failed to update policy %s: %v", policyName, err)
					return
				}

				// Delete policy
				if err := policyMgr.DeletePolicy(policyName); err != nil {
					errors <- fmt.Errorf("failed to delete policy %s: %v", policyName, err)
					return
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)

	// Check for any errors
	errorCount := 0
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
		errorCount++
	}

	assert.Zero(t, errorCount, "Should have no errors in concurrent operations")

	// Cleanup: make sure all policies are deleted
	for _, policy := range policyMgr.ListPolicies() {
		_ = policyMgr.DeletePolicy(policy.Name)
	}

	// Verify all policies were properly deleted
	policies := policyMgr.ListPolicies()
	assert.Empty(t, policies, "All policies should have been deleted")
}

// Helper function to create a test policy with the specified rules
func createTestPolicy(name, description string, rules map[string][]Capability) *Policy {
	policy := &Policy{
		Name:        name,
		Description: description,
		Rules:       make([]PathRule, 0, len(rules)),
	}

	for path, capabilities := range rules {
		policy.Rules = append(policy.Rules, PathRule{
			Path:         path,
			Capabilities: capabilities,
		})
	}

	return policy
}
