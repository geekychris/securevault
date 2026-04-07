package policy

import (
	"os"
	"testing"

	vaulterrors "securevault/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testManager(t *testing.T) (*Manager, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "securevault-policy-test")
	require.NoError(t, err)

	manager, err := NewManager(tmpDir)
	require.NoError(t, err)

	return manager, func() { os.RemoveAll(tmpDir) }
}

func TestCreateAndGetPolicy(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	policy := &Policy{
		Name:        "test-policy",
		Description: "Test policy",
		Rules: []PathRule{
			{
				Path:         "secret/*",
				Capabilities: []Capability{ReadCapability, ListCapability},
			},
		},
	}

	err := manager.CreatePolicy(policy)
	require.NoError(t, err)

	retrieved, err := manager.GetPolicy("test-policy")
	require.NoError(t, err)
	assert.Equal(t, "test-policy", retrieved.Name)
	assert.Len(t, retrieved.Rules, 1)
}

func TestCreateDuplicatePolicy(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	policy := &Policy{
		Name:  "dup",
		Rules: []PathRule{{Path: "test/*", Capabilities: []Capability{ReadCapability}}},
	}

	err := manager.CreatePolicy(policy)
	require.NoError(t, err)

	err = manager.CreatePolicy(policy)
	assert.Error(t, err)
	assert.True(t, vaulterrors.IsAlreadyExists(err))
}

func TestGetNonExistentPolicy(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	_, err := manager.GetPolicy("nonexistent")
	assert.Error(t, err)
	assert.True(t, vaulterrors.IsNotFound(err))
}

func TestUpdatePolicy(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	policy := &Policy{
		Name:  "update-me",
		Rules: []PathRule{{Path: "test/*", Capabilities: []Capability{ReadCapability}}},
	}
	require.NoError(t, manager.CreatePolicy(policy))

	updated := &Policy{
		Name:        "update-me",
		Description: "Updated",
		Rules:       []PathRule{{Path: "test/*", Capabilities: []Capability{ReadCapability, ListCapability}}},
	}
	require.NoError(t, manager.UpdatePolicy(updated))

	retrieved, err := manager.GetPolicy("update-me")
	require.NoError(t, err)
	assert.Equal(t, "Updated", retrieved.Description)
	assert.Len(t, retrieved.Rules[0].Capabilities, 2)
}

func TestDeletePolicy(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	policy := &Policy{
		Name:  "delete-me",
		Rules: []PathRule{{Path: "test/*", Capabilities: []Capability{ReadCapability}}},
	}
	require.NoError(t, manager.CreatePolicy(policy))

	require.NoError(t, manager.DeletePolicy("delete-me"))

	_, err := manager.GetPolicy("delete-me")
	assert.Error(t, err)
	assert.True(t, vaulterrors.IsNotFound(err))
}

func TestListPolicies(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	for i := 0; i < 3; i++ {
		policy := &Policy{
			Name:  "policy-" + string(rune('a'+i)),
			Rules: []PathRule{{Path: "test/*", Capabilities: []Capability{ReadCapability}}},
		}
		require.NoError(t, manager.CreatePolicy(policy))
	}

	policies := manager.ListPolicies()
	assert.Len(t, policies, 3)
}

func TestCheckPermission(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	policy := &Policy{
		Name: "app-reader",
		Rules: []PathRule{
			{Path: "app/*", Capabilities: []Capability{ReadCapability, ListCapability}},
		},
	}
	require.NoError(t, manager.CreatePolicy(policy))

	// Should allow read on app/data
	assert.True(t, manager.CheckPermission([]string{"app-reader"}, "app/data", ReadCapability))
	assert.True(t, manager.CheckPermission([]string{"app-reader"}, "app/data", ListCapability))

	// Should deny write
	assert.False(t, manager.CheckPermission([]string{"app-reader"}, "app/data", UpdateCapability))
	assert.False(t, manager.CheckPermission([]string{"app-reader"}, "app/data", CreateCapability))
	assert.False(t, manager.CheckPermission([]string{"app-reader"}, "app/data", DeleteCapability))

	// Should deny access to other paths
	assert.False(t, manager.CheckPermission([]string{"app-reader"}, "other/data", ReadCapability))
}

func TestWildcardPolicy(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	policy := &Policy{
		Name: "root-like",
		Rules: []PathRule{
			{Path: "*", Capabilities: []Capability{
				ReadCapability, CreateCapability, UpdateCapability, DeleteCapability, ListCapability,
			}},
		},
	}
	require.NoError(t, manager.CreatePolicy(policy))

	assert.True(t, manager.CheckPermission([]string{"root-like"}, "any/path", ReadCapability))
	assert.True(t, manager.CheckPermission([]string{"root-like"}, "deep/nested/path", UpdateCapability))
	assert.True(t, manager.CheckPermission([]string{"root-like"}, "anything", DeleteCapability))
}

func TestMultiplePolicies(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	reader := &Policy{
		Name:  "reader",
		Rules: []PathRule{{Path: "app/*", Capabilities: []Capability{ReadCapability}}},
	}
	writer := &Policy{
		Name:  "writer",
		Rules: []PathRule{{Path: "app/*", Capabilities: []Capability{CreateCapability, UpdateCapability}}},
	}
	require.NoError(t, manager.CreatePolicy(reader))
	require.NoError(t, manager.CreatePolicy(writer))

	// With both policies, should have read + create + update
	assert.True(t, manager.CheckPermission([]string{"reader", "writer"}, "app/data", ReadCapability))
	assert.True(t, manager.CheckPermission([]string{"reader", "writer"}, "app/data", CreateCapability))
	assert.True(t, manager.CheckPermission([]string{"reader", "writer"}, "app/data", UpdateCapability))
}

func TestInvalidCapabilityRejected(t *testing.T) {
	manager, cleanup := testManager(t)
	defer cleanup()

	policy := &Policy{
		Name:  "invalid",
		Rules: []PathRule{{Path: "test/*", Capabilities: []Capability{"invalid-cap"}}},
	}

	err := manager.CreatePolicy(policy)
	assert.Error(t, err)
}

func TestPolicyFilePermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securevault-policy-perms")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	manager, err := NewManager(tmpDir)
	require.NoError(t, err)

	policy := &Policy{
		Name:  "perms-test",
		Rules: []PathRule{{Path: "test/*", Capabilities: []Capability{ReadCapability}}},
	}
	require.NoError(t, manager.CreatePolicy(policy))

	// Check file permissions are 0600
	info, err := os.Stat(tmpDir + "/perms-test.yaml")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
