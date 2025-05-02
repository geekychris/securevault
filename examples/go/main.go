package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"securevault/clients/go"
)

func main() {
	// Command-line arguments for basic configuration
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <vault-address> <token>")
		fmt.Println("Example: go run main.go https://vault.example.com:8200 s.your-token-here")
		os.Exit(1)
	}

	vaultAddr := os.Args[1]
	token := os.Args[2]

	// Create a client with custom configuration
	client, err := securevault.NewClient(
		vaultAddr,
		token,
		securevault.WithTimeout(10*time.Second),
		securevault.WithMaxRetries(3),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// EXAMPLE 1: Create and manage policies
	fmt.Println("\n=== Policy Management ===")
	if err := policyManagementExample(ctx, client); err != nil {
		log.Printf("Policy management failed: %v", err)
	}

	// EXAMPLE 2: Secret CRUD operations
	fmt.Println("\n=== Secret Management ===")
	if err := secretManagementExample(ctx, client); err != nil {
		log.Printf("Secret management failed: %v", err)
	}

	// EXAMPLE 3: Secret versioning
	fmt.Println("\n=== Secret Versioning ===")
	if err := secretVersioningExample(ctx, client); err != nil {
		log.Printf("Secret versioning failed: %v", err)
	}

	// EXAMPLE 4: Token management
	fmt.Println("\n=== Token Management ===")
	if err := tokenManagementExample(ctx, client, vaultAddr); err != nil {
		log.Printf("Token management failed: %v", err)
	}

	fmt.Println("\nAll examples completed")
}

// policyManagementExample demonstrates creating and managing policies
func policyManagementExample(ctx context.Context, client *securevault.Client) error {
	// Create a policy for application access
	appPolicy := &securevault.Policy{
		Name:        "app-db-access",
		Description: "Policy for application database access",
		Rules: []securevault.PolicyRule{
			{
				Path:         "secret/database/*",
				Capabilities: []string{"read", "list"},
			},
			{
				Path:         "secret/application/*",
				Capabilities: []string{"create", "read", "update", "list"},
			},
		},
	}

	fmt.Println("Creating policy...")
	err := client.CreatePolicy(ctx, appPolicy)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}
	fmt.Println("Policy created successfully")

	// List all policies
	fmt.Println("Listing policies...")
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}
	fmt.Println("Available policies:")
	for _, p := range policies {
		fmt.Printf("  - %s\n", p)
	}

	// Get a specific policy
	fmt.Println("Getting policy details...")
	policy, err := client.GetPolicy(ctx, "app-db-access")
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	fmt.Printf("Policy details: %s - %s\n", policy.Name, policy.Description)
	for _, rule := range policy.Rules {
		fmt.Printf("  Path: %s, Capabilities: %v\n", rule.Path, rule.Capabilities)
	}

	// Update the policy
	fmt.Println("Updating policy...")
	policy.Rules = append(policy.Rules, securevault.PolicyRule{
		Path:         "secret/logs/*",
		Capabilities: []string{"create", "update"},
	})
	err = client.UpdatePolicy(ctx, policy)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}
	fmt.Println("Policy updated successfully")

	return nil
}

// secretManagementExample demonstrates CRUD operations for secrets
func secretManagementExample(ctx context.Context, client *securevault.Client) error {
	// Path for our secret
	secretPath := "application/config/database"

	// Secret data to store
	secretData := map[string]interface{}{
		"username": "appuser",
		"password": "securePassword123",
		"host":     "db.example.com",
		"port":     5432,
		"database": "appdb",
	}

	// Create a secret with metadata
	fmt.Println("Creating secret...")
	metadata := map[string]interface{}{
		"description": "Database credentials for the application",
		"environment": "production",
		"owner":       "platform-team",
	}
	err := client.WriteSecret(ctx, secretPath, secretData, securevault.WriteOptions{
		Metadata: metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}
	fmt.Println("Secret created successfully")

	// Read the secret
	fmt.Println("Reading secret...")
	secret, err := client.ReadSecret(ctx, secretPath)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}
	fmt.Println("Secret data:")
	for k, v := range secret.Data {
		fmt.Printf("  %s: %v\n", k, v)
	}
	fmt.Printf("Secret version: %d\n", secret.Metadata.Version)

	// List secrets
	fmt.Println("Listing secrets...")
	secrets, err := client.ListSecrets(ctx, "application/config")
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}
	fmt.Println("Available secrets:")
	for _, s := range secrets {
		fmt.Printf("  - %s\n", s)
	}

	// Get secret metadata
	fmt.Println("Getting secret metadata...")
	secretMeta, err := client.GetSecretMetadata(ctx, secretPath)
	if err != nil {
		return fmt.Errorf("failed to get secret metadata: %w", err)
	}

	fmt.Printf("Secret metadata: current version: %d, created: %s\n",
		secretMeta.CurrentVersion, secretMeta.CreatedTime.Format(time.RFC3339))
	return nil
}

// secretVersioningExample demonstrates working with different versions of secrets
func secretVersioningExample(ctx context.Context, client *securevault.Client) error {
	// Path for our versioned secret
	secretPath := "application/config/api-keys"

	// Create multiple versions of the secret
	fmt.Println("Creating multiple versions of secret...")

	// Version 1
	v1Data := map[string]interface{}{
		"api_key":    "v1-key-abc123",
		"api_secret": "v1-secret-xyz789",
		"active":     true,
	}
	err := client.WriteSecret(ctx, secretPath, v1Data)
	if err != nil {
		return fmt.Errorf("failed to write v1 secret: %w", err)
	}
	fmt.Println("Created version 1")

	// Version 2
	v2Data := map[string]interface{}{
		"api_key":    "v2-key-def456",
		"api_secret": "v2-secret-uvw987",
		"active":     true,
		"rate_limit": 1000,
	}
	err = client.WriteSecret(ctx, secretPath, v2Data)
	if err != nil {
		return fmt.Errorf("failed to write v2 secret: %w", err)
	}
	fmt.Println("Created version 2")

	// Version 3
	v3Data := map[string]interface{}{
		"api_key":      "v3-key-ghi789",
		"api_secret":   "v3-secret-rst654",
		"active":       true,
		"rate_limit":   5000,
		"access_level": "premium",
	}
	err = client.WriteSecret(ctx, secretPath, v3Data)
	if err != nil {
		return fmt.Errorf("failed to write v3 secret: %w", err)
	}
	fmt.Println("Created version 3")

	// Get latest version (should be v3)
	fmt.Println("Reading latest version...")
	latest, err := client.ReadSecret(ctx, secretPath)
	if err != nil {
		return fmt.Errorf("failed to read latest secret: %w", err)
	}
	fmt.Printf("Latest version: %d\n", latest.Metadata.Version)
	fmt.Printf("Latest API key: %v\n", latest.Data["api_key"])

	// Get specific versions
	fmt.Println("Reading specific versions...")
	for version := 1; version <= 3; version++ {
		fmt.Printf("Reading version %d...\n", version)
		secret, err := client.ReadSecret(ctx, secretPath, securevault.ReadOptions{
			Version: version,
		})
		if err != nil {
			return fmt.Errorf("failed to read v%d secret: %w", version, err)
		}
		fmt.Printf("  API key v%d: %v\n", version, secret.Data["api_key"])
	}

	// Get metadata with version history
	fmt.Println("Getting version metadata...")
	metadata, err := client.GetSecretMetadata(ctx, secretPath)
	if err != nil {
		return fmt.Errorf("failed to get secret metadata: %w", err)
	}
	fmt.Printf("Secret has %d versions\n", len(metadata.Versions))
	fmt.Printf("Current version: %d\n", metadata.CurrentVersion)

	// Delete a specific version (v1)
	fmt.Println("Deleting version 1...")
	err = client.DeleteSecret(ctx, secretPath, securevault.DeleteOptions{
		Versions: []int{1},
	})
	if err != nil {
		return fmt.Errorf("failed to delete v1: %w", err)
	}
	fmt.Println("Version 1 deleted")

	// Try to read deleted version
	fmt.Println("Trying to read deleted version...")
	_, err = client.ReadSecret(ctx, secretPath, securevault.ReadOptions{
		Version: 1,
	})
	if err != nil {
		fmt.Printf("Expected error reading deleted version: %v\n", err)
	} else {
		fmt.Println("Warning: Could still read deleted version, soft delete might not be implemented")
	}

	return nil
}

// tokenManagementExample demonstrates token creation and management
func tokenManagementExample(ctx context.Context, client *securevault.Client, vaultAddr string) error {
	// Create a token with specific policies
	fmt.Println("Creating token for app-db-access policy...")
	token, err := client.CreateToken(ctx, securevault.TokenOptions{
		PolicyIDs: []string{"app-db-access"},
		TTL:       "1h",
	})
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}
	fmt.Printf("Created token: %s...\n", token[:10]+"***") // Show only prefix for security

	// Create a new client with the limited token
	fmt.Println("Creating new client with the limited token...")
	limitedClient, err := securevault.NewClient(
		vaultAddr,  // Use the same address as the main client
		token,
		securevault.WithTimeout(10*time.Second),
	)
	if err != nil {
		return fmt.Errorf("failed to create limited client: %w", err)
	}

	// Try to use the limited client
	fmt.Println("Testing limited client permissions...")

	// This should succeed - reading database secret
	fmt.Println("Reading permitted secret...")
	_, err = limitedClient.ReadSecret(ctx, "application/config/database")
	if err != nil {
		fmt.Printf("Error reading permitted secret: %v\n", err)
	} else {
		fmt.Println("Successfully read permitted secret")
	}

	// This should fail - creating policy
	fmt.Println("Attempting to create policy (should fail)...")
	testPolicy := &securevault.Policy{
		Name:        "test-policy",
		Description: "Test policy",
		Rules: []securevault.PolicyRule{
			{
				Path:         "secret/test/*",
				Capabilities: []string{"read"},
			},
		},
	}
	err = limitedClient.CreatePolicy(ctx, testPolicy)
	if err != nil {
		fmt.Printf("Expected error creating policy with limited token: %v\n", err)
	} else {
		fmt.Println("Warning: Could create policy with limited token, permissions may not be enforced")
	}

	return nil
}

