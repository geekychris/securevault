package securevault

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// This is a demo test file to show how to use the SecureVault client
	// In a real project, you would use a proper testing framework with mocks
	
	fmt.Println("SecureVault Go Client Usage Examples")
	fmt.Println("------------------------------------")
	
	// Run the tests
	os.Exit(m.Run())
}

func TestClientUsage(t *testing.T) {
	// Skip in automated test environments
	if os.Getenv("CI") != "" {
		t.Skip("Skipping test in CI environment")
	}
	
	// Example: Create a client
	client, err := NewClient(
		"https://vault.example.com:8200",
		"s.your-auth-token-here",
		WithTimeout(15*time.Second),
		WithMaxRetries(3),
		WithInsecureSkipVerify(false),
	)
	
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Example: Create a policy
	adminPolicy := &Policy{
		Name:        "admin",
		Description: "Administrator policy",
		Rules: []PolicyRule{
			{
				Path:         "secret/*",
				Capabilities: []string{"create", "read", "update", "delete", "list"},
			},
			{
				Path:         "sys/*",
				Capabilities: []string{"read", "list"},
			},
		},
	}
	
	fmt.Println("Creating policy...")
	if err := client.CreatePolicy(ctx, adminPolicy); err != nil {
		t.Logf("Policy creation error (expected in demo): %v", err)
	}
	
	// Example: Create a token with the admin policy
	fmt.Println("Creating token...")
	token, err := client.CreateToken(ctx, TokenOptions{
		PolicyIDs: []string{"admin"},
		TTL:       "1h",
	})
	
	if err != nil {
		t.Logf("Token creation error (expected in demo): %v", err)
		// In a demo, we'll continue with the existing token
	} else {
		fmt.Printf("Created token: %s\n", token)
		// Use the new token
		client.SetToken(token)
	}
	
	// Example: Write a secret
	fmt.Println("Writing secret...")
	secretData := map[string]interface{}{
		"username": "dbuser",
		"password": "dbpassword",
		"host":     "db.example.com",
		"port":     5432,
	}
	
	secretMetadata := map[string]interface{}{
		"description": "PostgreSQL database credentials",
		"owner":       "app-team",
		"environment": "production",
	}
	
	err = client.WriteSecret(ctx, "database/postgres", secretData, WriteOptions{
		Metadata: secretMetadata,
	})
	
	if err != nil {
		t.Logf("Write secret error (expected in demo): %v", err)
	} else {
		fmt.Println("Secret written successfully")
	}
	
	// Example: Read a secret
	fmt.Println("Reading secret...")
	secret, err := client.ReadSecret(ctx, "database/postgres")
	
	if err != nil {
		t.Logf("Read secret error (expected in demo): %v", err)
	} else {
		fmt.Println("Secret data:")
		for key, value := range secret.Data {
			fmt.Printf("  %s: %v\n", key, value)
		}
		fmt.Printf("Version: %d\n", secret.Metadata.Version)
	}
	
	// Example: Read a specific version of a secret
	fmt.Println("Reading specific version...")
	versionedSecret, err := client.ReadSecret(ctx, "database/postgres", ReadOptions{
		Version: 1,
	})
	
	if err != nil {
		t.Logf("Read version error (expected in demo): %v", err)
	} else {
		fmt.Printf("Secret version %d data:\n", versionedSecret.Metadata.Version)
		for key, value := range versionedSecret.Data {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}
	
	// Example: Get secret metadata
	fmt.Println("Getting metadata...")
	metadata, err := client.GetSecretMetadata(ctx, "database/postgres")
	
	if err != nil {
		t.Logf("Get metadata error (expected in demo): %v", err)
	} else {
		fmt.Printf("Secret has %d versions\n", len(metadata.Versions))
		fmt.Printf("Current version: %d\n", metadata.CurrentVersion)
		fmt.Printf("Created: %s\n", metadata.CreatedTime.Format(time.RFC3339))
	}
	
	// Example: List secrets
	fmt.Println("Listing secrets...")
	secrets, err := client.ListSecrets(ctx, "database")
	
	if err != nil {
		t.Logf("List secrets error (expected in demo): %v", err)
	} else {
		fmt.Println("Secrets:")
		for _, secretPath := range secrets {
			fmt.Printf("  %s\n", secretPath)
		}
	}
	
	// Example: Delete a secret (soft delete)
	fmt.Println("Soft deleting specific version...")
	err = client.DeleteSecret(ctx, "database/postgres", DeleteOptions{
		Versions: []int{1},
	})
	
	if err != nil {
		t.Logf("Delete version error (expected in demo): %v", err)
	} else {
		fmt.Println("Version 1 deleted (soft delete)")
	}
	
	// Example: Permanently delete all versions
	fmt.Println("Permanently deleting all versions...")
	err = client.DeleteSecret(ctx, "database/postgres", DeleteOptions{
		Destroy: true,
	})
	
	if err != nil {
		t.Logf("Delete secret error (expected in demo): %v", err)
	} else {
		fmt.Println("Secret permanently deleted")
	}
	
	fmt.Println("\nAll examples completed")
}

// ExampleClient provides a simple example of client usage that can be included in documentation
func ExampleClient() {
	// Create a new client
	client, err := NewClient("https://vault.example.com:8200", "your-token")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	
	// Create a context
	ctx := context.Background()
	
	// Write a secret
	err = client.WriteSecret(ctx, "app/database/credentials", map[string]interface{}{
		"username": "dbuser",
		"password": "dbpassword",
	})
	if err != nil {
		log.Fatalf("Failed to write secret: %v", err)
	}
	
	// Read a secret
	secret, err := client.ReadSecret(ctx, "app/database/credentials")
	if err != nil {
		log.Fatalf("Failed to read secret: %v", err)
	}
	
	fmt.Printf("Username: %s\n", secret.Data["username"])
	fmt.Printf("Password: %s\n", secret.Data["password"])
	
	// Output:
	// Username: dbuser
	// Password: dbpassword
}

