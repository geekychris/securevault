package com.example.securevault.examples;

import com.example.securevault.SecureVaultClient;
import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.exception.SecureVaultForbiddenException;
import com.example.securevault.exception.SecureVaultNotFoundException;
import com.example.securevault.model.*;

import java.util.*;

/**
 * Example application demonstrating the usage of the SecureVault Java client.
 *
 * This example shows various operations including:
 * - Authentication and token management
 * - Secret CRUD operations
 * - Policy management
 * - Secret versioning
 */
public class SecureVaultExample {
    
    public static void main(String[] args) {
        // Check for required command line arguments
        if (args.length < 2) {
            System.out.println("Usage: java SecureVaultExample <vault-address> <token>");
            System.out.println("Example: java SecureVaultExample https://vault.example.com:8200 s.your-token-here");
            System.exit(1);
        }
        
        String vaultAddress = args[0];
        String token = args[1];
        
        // Create a SecureVault client
        try (SecureVaultClient client = SecureVaultClient.builder()
                .address(vaultAddress)
                .token(token)
                .requestTimeout(10000) // 10 seconds
                .maxConnections(5)
                .build()) {
            
            System.out.println("Connected to SecureVault at " + vaultAddress);
            
            // Run the examples
            try {
                // EXAMPLE 1: Policy Management
                System.out.println("\n=== Policy Management ===");
                policyManagementExample(client);
                
                // EXAMPLE 2: Secret Management
                System.out.println("\n=== Secret Management ===");
                secretManagementExample(client);
                
                // EXAMPLE 3: Secret Versioning
                System.out.println("\n=== Secret Versioning ===");
                secretVersioningExample(client);
                
                // EXAMPLE 4: Token Management
                System.out.println("\n=== Token Management ===");
                tokenManagementExample(client);
                
                System.out.println("\nAll examples completed");
            } catch (SecureVaultException e) {
                System.err.println("SecureVault error: " + e.getMessage());
            } catch (Exception e) {
                System.err.println("Unexpected error: " + e.getMessage());
                e.printStackTrace();
            }
        } catch (Exception e) {
            System.err.println("Failed to create SecureVault client: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Demonstrates creating and managing policies.
     */
    private static void policyManagementExample(SecureVaultClient client) {
        System.out.println("Creating policy...");
        
        try {
            // Create a policy for application access
            Policy appPolicy = Policy.builder()
                    .name("app-db-access")
                    .description("Policy for application database access")
                    .rules(Arrays.asList(
                            PolicyRule.builder()
                                    .path("secret/database/*")
                                    .capabilities(Arrays.asList("read", "list"))
                                    .build(),
                            PolicyRule.builder()
                                    .path("secret/application/*")
                                    .capabilities(Arrays.asList("create", "read", "update", "list"))
                                    .build()
                    ))
                    .build();
            
            client.createPolicy(appPolicy);
            System.out.println("Policy created successfully");
            
            // List all policies
            System.out.println("Listing policies...");
            List<String> policies = client.listPolicies();
            System.out.println("Available policies:");
            for (String p : policies) {
                System.out.println("  - " + p);
            }
            
            // Get a specific policy
            System.out.println("Getting policy details...");
            Policy policy = client.getPolicy("app-db-access");
            System.out.println("Policy details: " + policy.getName() + " - " + policy.getDescription());
            for (PolicyRule rule : policy.getRules()) {
                System.out.println("  Path: " + rule.getPath() + ", Capabilities: " + rule.getCapabilities());
            }
            
            // Update the policy
            System.out.println("Updating policy...");
            List<PolicyRule> updatedRules = new ArrayList<>(policy.getRules());
            updatedRules.add(PolicyRule.builder()
                    .path("secret/logs/*")
                    .capabilities(Arrays.asList("create", "update"))
                    .build());
            policy.setRules(updatedRules);
            
            client.updatePolicy(policy);
            System.out.println("Policy updated successfully");
            
        } catch (SecureVaultException e) {
            System.err.println("Policy management error: " + e.getMessage());
        }
    }
    
    /**
     * Demonstrates CRUD operations for secrets.
     */
    private static void secretManagementExample(SecureVaultClient client) {
        // Path for our secret
        String secretPath = "application/config/database";
        
        try {
            // Secret data to store
            Map<String, Object> secretData = new HashMap<>();
            secretData.put("username", "appuser");
            secretData.put("password", "securePassword123");
            secretData.put("host", "db.example.com");
            secretData.put("port", 5432);
            secretData.put("database", "appdb");
            
            // Create a secret with metadata
            System.out.println("Creating secret...");
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("description", "Database credentials for the application");
            metadata.put("environment", "production");
            metadata.put("owner", "platform-team");
            
            client.writeSecret(secretPath, secretData, WriteOptions.builder()
                    .metadata(metadata)
                    .build());
            System.out.println("Secret created successfully");
            
            // Read the secret
            System.out.println("Reading secret...");
            Secret secret = client.readSecret(secretPath);
            System.out.println("Secret data:");
            for (Map.Entry<String, Object> entry : secret.getData().entrySet()) {
                System.out.println("  " + entry.getKey() + ": " + entry.getValue());
            }
            System.out.println("Secret version: " + secret.getMetadata().getVersion());
            
            // List secrets
            System.out.println("Listing secrets...");
            List<String> secrets = client.listSecrets("application/config");
            System.out.println("Available secrets:");
            for (String s : secrets) {
                System.out.println("  - " + s);
            }
            
            // Get secret metadata
            System.out.println("Getting secret metadata...");
            SecretMetadata metadataObj = client.getSecretMetadata(secretPath);
            System.out.println("Current version: " + metadataObj.getCurrentVersion());
            System.out.println("Created time: " + metadataObj.getCreatedTime());
            
        } catch (SecureVaultNotFoundException e) {
            System.err.println("Secret not found: " + e.getMessage());
        } catch (SecureVaultException e) {
            System.err.println("Secret management error: " + e.getMessage());
        }
    }
    
    /**
     * Demonstrates working with different versions of secrets.
     */
    private static void secretVersioningExample(SecureVaultClient client) {
        // Path for our versioned secret
        String secretPath = "application/config/api-keys";
        
        try {
            // Create multiple versions of the secret
            System.out.println("Creating multiple versions of secret...");
            
            // Version 1
            Map<String, Object> v1Data = new HashMap<>();
            v1Data.put("api_key", "v1-key-abc123");
            v1Data.put("api_secret", "v1-secret-xyz789");
            v1Data.put("active", true);
            
            client.writeSecret(secretPath, v1Data);
            System.out.println("Created version 1");
            
            // Version 2
            Map<String, Object> v2Data = new HashMap<>();
            v2Data.put("api_key", "v2-key-def456");
            v2Data.put("api_secret", "v2-secret-uvw987");
            v2Data.put("active", true);
            v2Data.put("rate_limit", 1000);
            
            client.writeSecret(secretPath, v2Data);
            System.out.println("Created version 2");
            
            // Version 3
            Map<String, Object> v3Data = new HashMap<>();
            v3Data.put("api_key", "v3-key-ghi789");
            v3Data.put("api_secret", "v3-secret-rst654");
            v3Data.put("active", true);
            v3Data.put("rate_limit", 5000);
            v3Data.put("access_level", "premium");
            
            client.writeSecret(secretPath, v3Data);
            System.out.println("Created version 3");
            
            // Get latest version (should be v3)
            System.out.println("Reading latest version...");
            Secret latest = client.readSecret(secretPath);
            System.out.println("Latest version: " + latest.getMetadata().getVersion());
            System.out.println("Latest API key: " + latest.getData().get("api_key"));
            
            // Get specific versions
            System.out.println("Reading specific versions...");
            for (int version = 1; version <= 3; version++) {
                System.out.println("Reading version " + version + "...");
                Secret secret = client.readSecret(secretPath, ReadOptions.builder()
                        .version(version)
                        .build());
                System.out.println("  API key v" + version + ": " + secret.getData().get("api_key"));
            }
            
            // Get metadata with version history
            System.out.println("Getting version metadata...");
            SecretMetadata metadata = client.getSecretMetadata(secretPath);
            System.out.println("Secret has " + metadata.getVersions().size() + " versions");
            System.out.println("Current version: " + metadata.getCurrentVersion());
            
            // Delete a specific version (v1)
            System.out.println("Deleting version 1...");
            client.deleteSecret(secretPath, DeleteOptions.builder()
                    .versions(Collections.singletonList(1))
                    .build());
            System.out.println("Version 1 deleted");
            
            // Try to read deleted version
            System.out.println("Trying to read deleted version...");
            try {
                client.readSecret(secretPath, ReadOptions.builder()
                        .version(1)
                        .build());
                System.out.println("Warning: Could still read deleted version, soft delete might not be implemented");
            } catch (SecureVaultException e) {
                System.out.println("Expected error reading deleted version: " + e.getMessage());
            }
            
        } catch (SecureVaultException e) {
            System.err.println("Secret versioning error: " + e.getMessage());
        }
    }
    
    /**
     * Demonstrates token creation and management.
     */
    private static void tokenManagementExample(SecureVaultClient client) {
        try {
            // Create a token with specific policies
            System.out.println("Creating token for app-db-access policy...");
            String token = client.createToken(TokenOptions.builder()
                    .policyIds(Collections.singletonList("app-db-access"))
                    .ttl("1h")
                    .build());
            
            System.out.println("Created token: " + token.substring(0, 10) + "***"); // Show only prefix for security
            
            // Create a new client with the limited token
            System.out.println("Creating new client with the limited token...");
            SecureVaultClient limitedClient = SecureVaultClient.builder()
                    .address(client.toString().replaceAll("SecureVaultClient\\{address='([^']+)'.*", "$1"))
                    .token(token)
                    .requestTimeout(10000)
                    .build();
            
            // Try to use the limited client
            System.out.println("Testing limited client permissions...");
            
            // This should succeed - reading database secret
            System.out.println("Reading permitted secret...");
            try {
                limitedClient.readSecret("application/config/database");
                System.out.println("Successfully read permitted secret");
            } catch (SecureVaultException e) {
                System.out.println("Error reading permitted secret: " + e.getMessage());
            }
            
            // This should fail - creating policy
            System.out.println("Attempting to create policy (should fail)...");
            try {
                Policy testPolicy = Policy.builder()
                        .name("test-policy")
                        .description("Test policy")
                        .rules(Collections.singletonList(
                                PolicyRule.builder()
                                        .path("secret/test/*")
                                        .capabilities(Collections.singletonList("read"))
                                        .build()
                        ))
                        .build();
                
                limitedClient.createPolicy(testPolicy);
                System.out.println("Warning: Could create policy with limited token, permissions may not be enforced");
            } catch (SecureVaultForbiddenException e) {
                System.out.println("Expected error creating policy with limited token: " + e.getMessage());
            }
            
            // Close the limited client
            limitedClient.close();
            
        } catch (SecureVaultException e) {
            System.err.println("Token management error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error in token management: " + e.getMessage());
        }
    }
}
