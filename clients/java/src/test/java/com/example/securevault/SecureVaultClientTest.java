package com.example.securevault;

import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.exception.SecureVaultNotFoundException;
import com.example.securevault.model.*;
import org.junit.jupiter.api.*;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for SecureVaultClient.
 * These tests require a running SecureVault server.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SecureVaultClientTest {
    private static SecureVaultClient client;
    private static List<String> secretPaths = new ArrayList<>();
    
    @BeforeAll
    public static void setUp() {
        client = TestConfig.createRootClient();
        System.out.println("Using test namespace: " + TestConfig.TEST_NAMESPACE);
    }
    
    @AfterAll
    public static void tearDown() throws Exception {
        // Clean up all secrets created during tests
        for (String path : secretPaths) {
            try {
                client.deleteSecret(path);
            } catch (Exception e) {
                System.err.println("Failed to clean up secret at path: " + path);
            }
        }
        
        client.close();
    }
    
    @Test
    @Order(1)
    public void testWriteAndReadSecret() throws SecureVaultException {
        // Arrange
        String path = TestConfig.generateTestPath("write-read");
        secretPaths.add(path);
        Map<String, Object> secretData = new HashMap<>();
        secretData.put("username", "testuser");
        secretData.put("password", "testpassword");
        secretData.put("url", "https://example.com");
        secretData.put("port", 8080);
        secretData.put("enabled", true);
        
        // Write secret
        client.writeSecret(path, secretData);
        
        // Act
        Map<String, Object> readData = client.readSecret(path);
        Secret secret = Secret.fromMap(readData);
        
        // Assert
        assertNotNull(secret, "Secret should not be null");
        assertEquals("testuser", secret.getData().get("username"), "Username should match");
        assertEquals("testpassword", secret.getData().get("password"), "Password should match");
        assertEquals("https://example.com", secret.getData().get("url"), "URL should match");
        assertEquals(8080, secret.getData().get("port"), "Port should match");
        assertEquals(true, secret.getData().get("enabled"), "Enabled flag should match");
    }
    
    @Test
    @Order(2)
    public void testUpdateSecret() throws SecureVaultException {
        // Arrange
        String path = TestConfig.generateTestPath("update");
        secretPaths.add(path);
        
        // Initial write
        Map<String, Object> initialData = new HashMap<>();
        initialData.put("username", "initial");
        initialData.put("password", "initialpass");
        client.writeSecret(path, initialData);
        
        // Update data
        Map<String, Object> updatedData = new HashMap<>();
        updatedData.put("username", "updated");
        updatedData.put("password", "updatedpass");
        updatedData.put("username", "updated");
        updatedData.put("password", "updatedpass");
        updatedData.put("newfield", "newvalue");
        
        // Write updated data
        client.writeSecret(path, updatedData);
        
        // Act
        Map<String, Object> secretData = client.readSecret(path);
        Secret secret = Secret.fromMap(secretData);
        
        // Assert
        assertNotNull(secret, "Secret should not be null");
        assertEquals("updated", secret.getData().get("username"), "Username should match");
        assertEquals("updatedpass", secret.getData().get("password"), "Password should match");
        assertEquals("newvalue", secret.getData().get("newfield"), "New field should be present");
    }
    
    @Test
    @Order(3)
    public void testDeleteSecret() throws SecureVaultException {
        // Arrange
        String path = TestConfig.generateTestPath("delete");
        secretPaths.add(path);
        Map<String, Object> secretData = new HashMap<>();
        secretData.put("username", "deleteuser");
        secretData.put("password", "deletepass");
        client.writeSecret(path, secretData);
        
        // Act
        boolean deleteResult = client.deleteSecret(path);
        
        // Assert
        assertTrue(deleteResult, "Delete operation should succeed");
        
        // Verify the secret is gone
        assertThrows(SecureVaultNotFoundException.class, () -> {
            client.readSecret(path);
        }, "Reading deleted secret should throw NotFoundException");
    }
    
    @Test
    @Order(4)
    public void testListSecrets() throws SecureVaultException {
        // Arrange
        String basePath = TestConfig.generateTestPath("list");
        
        // Create a few secrets under the base path
        for (int i = 0; i < 3; i++) {
            String path = basePath + "/secret" + i;
            secretPaths.add(path);
            Map<String, Object> secretData = new HashMap<>();
            secretData.put("key", "value" + i);
            client.writeSecret(path, secretData);
        }
        
        // Act
        List<String> secrets = client.listSecrets(basePath);
        
        // Assert
        assertNotNull(secrets, "Secret list should not be null");
        assertEquals(3, secrets.size(), "Should have 3 secrets");
        assertTrue(secrets.contains("secret0"), "Should contain secret0");
        assertTrue(secrets.contains("secret1"), "Should contain secret1");
        assertTrue(secrets.contains("secret2"), "Should contain secret2");
    }
    
    @Test
    @Order(5)
    public void testSecretMetadata() throws SecureVaultException {
        // Arrange
        String path = TestConfig.generateTestPath("metadata");
        secretPaths.add(path);
        
        Map<String, Object> secretData = new HashMap<>();
        secretData.put("key", "metadata-value");
        
        // Write the secret (without metadata for now)
        client.writeSecret(path, secretData);
        
        // Act
        SecretMetadata secretMetadata = client.getSecretMetadata(path);
        
        // Assert
        assertNotNull(secretMetadata, "Metadata should not be null");
        
        // We're not setting custom metadata in this test, but we can verify
        // some system metadata
        assertNotNull(secretMetadata.getCreatedTime(), "Created time should not be null");
        assertEquals(1, secretMetadata.getVersion(), "Initial version should be 1");
        assertEquals(1, secretMetadata.getCurrentVersion(), "Current version should be 1");
    }
    
    @Test
    @Order(6)
    public void testSecretVersions() throws SecureVaultException {
        // Arrange
        String path = TestConfig.generateTestPath("versions");
        secretPaths.add(path);
        
        // Version 1
        Map<String, Object> v1Data = new HashMap<>();
        v1Data.put("username", "v1user");
        client.writeSecret(path, v1Data);
        
        // Version 2
        Map<String, Object> v2Data = new HashMap<>();
        v2Data.put("username", "v2user");
        client.writeSecret(path, v2Data);
        
        // Version 3
        Map<String, Object> v3Data = new HashMap<>();
        v3Data.put("username", "v3user");
        client.writeSecret(path, v3Data);
        
        // Act
        // Read version 1
        Long v1 = 1L;
        Map<String, Object> v1SecretData = client.readSecret(path, v1);
        Secret v1Secret = Secret.fromMap(v1SecretData);
        
        // Read version 2
        Long v2 = 2L;
        Map<String, Object> v2SecretData = client.readSecret(path, v2);
        Secret v2Secret = Secret.fromMap(v2SecretData);
        
        // Read version 3
        Long v3 = 3L;
        Map<String, Object> v3SecretData = client.readSecret(path, v3);
        Secret v3Secret = Secret.fromMap(v3SecretData);
        
        // Current version (3)
        Map<String, Object> latestSecretData = client.readSecret(path);
        Secret latestSecret = Secret.fromMap(latestSecretData);
        
        // Assert
        assertEquals("v1user", v1Secret.getData().get("username"), "Version 1 username should match");
        assertEquals("v2user", v2Secret.getData().get("username"), "Version 2 username should match");
        assertEquals("v3user", v3Secret.getData().get("username"), "Version 3 username should match");
        assertEquals("v3user", latestSecret.getData().get("username"), "Latest username should match version 3");
    }
    
    @Test
    @Order(7)
    public void testErrorHandling() {
        // Test reading non-existent secret
        assertThrows(SecureVaultNotFoundException.class, () -> {
            client.readSecret("non/existent/path");
        }, "Reading non-existent secret should throw NotFoundException");
        
        // Test deleting non-existent secret
        assertThrows(SecureVaultNotFoundException.class, () -> {
            client.deleteSecret("non/existent/path");
        }, "Deleting non-existent secret should throw NotFoundException");
    }
}
