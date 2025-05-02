package com.example.securevault;

import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.model.*;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tests for the SecureVault client.
 * 
 * Note: These tests are designed to demonstrate usage and are not meant to be run automatically.
 * They require a running SecureVault server to connect to.
 */
@Disabled("These tests require a running SecureVault server")
public class SecureVaultClientTest {

    /**
     * Demonstrates basic client usage.
     */
    @Test
    public void demonstrateClientUsage() {
        // Create a client
        SecureVaultClient client = SecureVaultClient.builder()
                .address("https://vault.example.com:8200")
                .token("s.your-auth-token-here")
                .requestTimeout(15000) // 15 seconds
                .build();

        try {
            // Example: Create a policy
            System.out.println("Creating policy...");
            
            Policy adminPolicy = Policy.builder()
                    .name("admin")
                    .description("Administrator policy")
                    .rules(Arrays.asList(
                            PolicyRule.builder()
                                    .path("secret/*")
                                    .capabilities(Arrays.asList("create", "read", "update", "delete", "list"))
                                    .build(),
                            PolicyRule.builder()
                                    .path("sys/*")
                                    .capabilities(Arrays.asList("read", "list"))
                                    .build()
                    ))
                    .build();
            
            try {
                boolean created = client.createPolicy(adminPolicy);
                System.out.println("Policy created: " + created);
            } catch (SecureVaultException e) {
                System.out.println("Policy creation error (expected in demo): " + e.getMessage());
            }

            // Example: Create a token with the admin policy
            System.out.println("\nCreating token...");
            
            try {
                String token = client.createToken(TokenOptions.builder()
                        .policyIds(Arrays.asList("admin"))
                        .ttl("1h")
                        .build());
                
                System.out.println("Created token: " + token);
                
                // Use the new token
                client.setToken(token);
            } catch (SecureVaultException e) {
                System.out.println("Token creation error (expected in demo): " + e.getMessage());
            }

            // Example: Write a secret
            System.out.println("\nWriting secret...");
            
            Map<String, Object> secretData = new HashMap<>();
            secretData.put("username", "dbuser");
            secretData.put("password", "dbpassword");
            secretData.put("host", "db.example.com");
            secretData.put("port", 5432);
            
            Map<String, Object> secretMetadata = new HashMap<>();
            secretMetadata.put("description", "PostgreSQL database credentials");
            secretMetadata.put("owner", "app-team");
            secretMetadata.put("environment", "production");
            
            try {
                boolean written = client.writeSecret("database/postgres", secretData, 
                        WriteOptions.builder().metadata(secretMetadata).build());
                
                System.out.println("Secret written: " + written);
            } catch (SecureVaultException e) {
                System.out.println("Write secret error (expected in demo): " + e.getMessage());
            }

            // Example: Read a secret
            System.out.println("\nReading secret...");
            
            try {
                Secret secret = client.readSecret("database/postgres");
                
                System.out.println("Secret data:");
                for (Map.Entry<String, Object> entry : secret.getData().entrySet()) {
                    System.out.println("  " + entry.getKey() + ": " + entry.getValue());
                }
                
                System.out.println("Version: " + secret.getMetadata().getVersion());
            } catch (SecureVaultException e) {
                System.out.println("Read secret error (expected in demo): " + e.getMessage());
            }

            // Example: Read a specific version of a secret
            System.out.println("\nReading specific version...");
            
            try {
                Secret versionedSecret = client.readSecret("database/postgres", 
                        ReadOptions.builder().version(1).build());
                
                System.out.println("Secret version " + versionedSecret.getMetadata().getVersion() + " data:");
                for (Map.Entry<String, Object> entry : versionedSecret.getData().entrySet()) {
                    System.out.println("  " + entry.getKey() + ": " + entry.getValue());
                }
            } catch (SecureVaultException e) {
                System.out.println("Read version error (expected in demo): " + e.getMessage());
            }

            // Example: Get secret metadata
            System.out.println("\nGetting metadata...");
            
            try {
                SecretMetadata metadata = client.getSecretMetadata("database/postgres");
                
                System.out.println("Secret has " + metadata.getVersions().size() + " versions");
                System.out.println("Current version: " + metadata.getCurrentVersion());
                System.out.println("Created: " + metadata.getCreatedTime());
            } catch (SecureVaultException e) {
                System.out.println("Get metadata error (expected in demo): " + e.getMessage());
            }

            // Example: List secrets
            System.out.println("\nListing secrets...");
            
            try {
                List<String> secrets = client.listSecrets("database");
                
                System.out.println("Secrets:");
                for (String secretPath : secrets) {
                    System.out.println("  " + secretPath);
                }
            } catch (SecureVaultException e) {
                System.out.println("List secrets error (expected in demo): " + e.getMessage());
            }

            // Example: Delete a secret (soft delete)
            System.out.println("\nSoft deleting specific version...");
            
            try {
                boolean deleted = client.deleteSecret("database/postgres", 
                        DeleteOptions.builder().versions(Arrays.asList(1)).build());
                
                System.out.println("Version 1 deleted: " + deleted);
            } catch (SecureVaultException e) {
                System.out.println("Delete version error (expected in demo): " + e.getMessage());
            }

            // Example: Permanently delete all versions
            System.out.println("\nPermanently deleting all versions...");
            
            try {
                boolean destroyed = client.deleteSecret("database/postgres", 
                        DeleteOptions.builder().destroy(true).build());
                
                System.out.println("Secret permanently deleted: " + destroyed);
            } catch (SecureVaultException e) {
                System.out.println("Delete secret error (expected in demo): " + e.getMessage());
            }

        } finally {
            // Close the client
            try {
                client.close();
                System.out.println("\nClient closed");
            } catch (Exception e) {
                System.out.println("Error closing client: " + e.getMessage());
            }
        }
    }

    /**
     * Demonstrates a simpler code example for documentation.
     */
    @Test
    @Disabled
    public void simpleExample() {
        // Create a client
        try (SecureVaultClient client = SecureVaultClient.builder()
                .address("https://vault.example.com:8200")
                .token("your-token")
                .build()) {
            
            // Write a secret
            Map<String, Object> credentials = new HashMap<>();
            credentials.put("username", "dbuser");
            credentials.put("password", "dbpassword");
            
            client.writeSecret("app/database/credentials", credentials);
            
            // Read a secret
            Secret secret = client.readSecret("app/database/credentials");
            
            System.out.println("Username: " + secret.getData().get("username"));
            System.out.println("Password: " + secret.getData().get("password"));
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}

