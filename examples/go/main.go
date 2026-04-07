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
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <vault-address> [token]")
		fmt.Println("Example: go run main.go http://127.0.0.1:8200")
		fmt.Println("")
		fmt.Println("If no token is provided, the vault will be initialized and unsealed.")
		os.Exit(1)
	}

	vaultAddr := os.Args[1]
	ctx := context.Background()

	client, err := securevault.NewClient(
		vaultAddr,
		"", // token will be set after init/unseal
		securevault.WithTimeout(10*time.Second),
		securevault.WithMaxRetries(3),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	var token string
	if len(os.Args) >= 3 {
		token = os.Args[2]
	}

	// --- Initialize and Unseal (if needed) ---
	if token == "" {
		fmt.Println("=== Checking Vault Status ===")
		status, err := client.GetSealStatus(ctx)
		if err != nil {
			log.Fatalf("Failed to get seal status: %v", err)
		}

		if !status.Initialized {
			fmt.Println("Vault is not initialized. Initializing...")
			initResp, err := client.Initialize(ctx, 3, 2)
			if err != nil {
				log.Fatalf("Failed to initialize: %v", err)
			}

			fmt.Println("Vault initialized!")
			fmt.Printf("Root Token: %s\n", initResp.RootToken)
			fmt.Println("Unseal Keys:")
			for i, key := range initResp.Keys {
				fmt.Printf("  Key %d: %s\n", i+1, key)
			}
			fmt.Println("\n*** SAVE THESE KEYS SECURELY ***\n")

			token = initResp.RootToken

			// Unseal with the first 2 keys (threshold)
			for i := 0; i < 2; i++ {
				sealStatus, err := client.Unseal(ctx, initResp.Keys[i])
				if err != nil {
					log.Fatalf("Failed to unseal: %v", err)
				}
				fmt.Printf("Unseal progress: %d/%d\n", sealStatus.Progress, sealStatus.Threshold)
				if !sealStatus.Sealed {
					fmt.Println("Vault is unsealed!")
				}
			}
		} else if status.Sealed {
			fmt.Println("Vault is sealed. Please provide unseal keys.")
			os.Exit(1)
		}
	}

	client.SetToken(token)

	// --- Policy Management ---
	fmt.Println("\n=== Policy Management ===")

	err = client.CreatePolicy(ctx, &securevault.Policy{
		Name:        "app-readonly",
		Description: "Read-only access to app secrets",
		Rules: []securevault.PolicyRule{
			{Path: "app/**", Capabilities: []string{"read", "list"}},
		},
	})
	if err != nil {
		fmt.Printf("Create policy: %v\n", err)
	} else {
		fmt.Println("Created 'app-readonly' policy")
	}

	// --- Secret Operations ---
	fmt.Println("\n=== Secret Operations ===")

	// Write a secret
	err = client.WriteSecret(ctx, "app/database/config", map[string]interface{}{
		"host":     "db.internal.example.com",
		"port":     5432,
		"username": "app_user",
		"password": "super-secret-db-password",
	})
	if err != nil {
		log.Fatalf("Failed to write secret: %v", err)
	}
	fmt.Println("Written secret to app/database/config")

	// Read the secret
	secret, err := client.ReadSecret(ctx, "app/database/config")
	if err != nil {
		log.Fatalf("Failed to read secret: %v", err)
	}
	fmt.Printf("Read secret: host=%s, username=%s (version %d)\n",
		secret.Data["host"], secret.Data["username"], secret.Metadata.Version)

	// Update the secret (creates version 2)
	err = client.WriteSecret(ctx, "app/database/config", map[string]interface{}{
		"host":     "db.internal.example.com",
		"port":     5432,
		"username": "app_user",
		"password": "rotated-password-2024",
	})
	if err != nil {
		log.Fatalf("Failed to update secret: %v", err)
	}
	fmt.Println("Updated secret (new version)")

	// Read a specific version
	secretV1, err := client.ReadSecret(ctx, "app/database/config", securevault.ReadOptions{Version: 1})
	if err != nil {
		fmt.Printf("Read v1: %v\n", err)
	} else {
		fmt.Printf("Version 1 password: %s\n", secretV1.Data["password"])
	}

	// List secrets
	keys, err := client.ListSecrets(ctx, "app/database")
	if err != nil {
		fmt.Printf("List secrets: %v\n", err)
	} else {
		fmt.Printf("Secrets under app/database: %v\n", keys)
	}

	// --- Token Management ---
	fmt.Println("\n=== Token Management ===")

	// Create a restricted token
	newToken, err := client.CreateToken(ctx, securevault.TokenOptions{
		PolicyIDs: []string{"app-readonly"},
		TTL:       "2h",
	})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("Created restricted token: %s...\n", newToken[:10])

	// Use the restricted token
	restrictedClient, _ := securevault.NewClient(vaultAddr, newToken)

	// This should work (read-only access to app/*)
	secret, err = restrictedClient.ReadSecret(ctx, "app/database/config")
	if err != nil {
		fmt.Printf("Restricted read: %v\n", err)
	} else {
		fmt.Printf("Restricted client read: host=%s\n", secret.Data["host"])
	}

	// This should fail (no write access)
	err = restrictedClient.WriteSecret(ctx, "app/database/config", map[string]interface{}{
		"hacked": true,
	})
	if err != nil {
		fmt.Printf("Restricted write correctly denied: %v\n", err)
	}

	// Lookup token info
	tokenInfo, err := client.LookupToken(ctx)
	if err != nil {
		fmt.Printf("Token lookup: %v\n", err)
	} else {
		fmt.Printf("Token policies: %v\n", tokenInfo["policies"])
	}

	// --- Cleanup ---
	fmt.Println("\n=== Cleanup ===")
	err = client.DeleteSecret(ctx, "app/database/config", securevault.DeleteOptions{Destroy: true})
	if err != nil {
		fmt.Printf("Delete secret: %v\n", err)
	} else {
		fmt.Println("Secret destroyed")
	}

	err = client.DeletePolicy(ctx, "app-readonly")
	if err != nil {
		fmt.Printf("Delete policy: %v\n", err)
	} else {
		fmt.Println("Policy deleted")
	}

	fmt.Println("\n=== Example Complete ===")
}
