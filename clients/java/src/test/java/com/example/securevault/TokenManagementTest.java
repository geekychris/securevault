package com.example.securevault;

import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.exception.SecureVaultForbiddenException;
import com.example.securevault.exception.SecureVaultUnauthorizedException;
import com.example.securevault.model.*;

import java.io.IOException;
import java.time.Duration;
import java.util.*;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for token management in SecureVaultClient.
 * These tests require a running SecureVault server.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class TokenManagementTest {
    private static SecureVaultClient rootClient;
    private static final List<String> createdTokens = new ArrayList<>();
    private static final List<String> createdPolicies = new ArrayList<>();
    
    @BeforeAll
    public static void setUp() {
        rootClient = TestConfig.createRootClient();
        System.out.println("Using test namespace: " + TestConfig.TEST_NAMESPACE);
        
        // Create a test policy
        try {
            String policyName = "test-policy-" + UUID.randomUUID().toString().substring(0, 8);
            createdPolicies.add(policyName);
            
            Policy policy = new Policy();
            policy.setName(policyName);
            
            // Create a policy rule
            PolicyRule rule = new PolicyRule();
            rule.setPath("secret/*");
            rule.setCapabilities(Arrays.asList("read", "list"));
            
            // Set rules for the policy
            policy.setRules(Collections.singletonList(rule));
            
            rootClient.createPolicy(policy);
        } catch (Exception e) {
            System.err.println("Failed to create test policy: " + e.getMessage());
        }
    }
    
    @AfterAll
    public static void tearDown() throws Exception {
        // Revoke all tokens created during tests
        for (String tokenId : createdTokens) {
            try {
                TokenRevokeOptions options = TokenRevokeOptions.builder()
                        .withToken(tokenId)
                        .build();
                rootClient.revokeToken(options);
            } catch (Exception e) {
                System.err.println("Failed to revoke token: " + tokenId);
            }
        }
        
        // Delete all policies created during tests
        for (String policyName : createdPolicies) {
            try {
                rootClient.deletePolicy(policyName);
            } catch (Exception e) {
                System.err.println("Failed to delete policy: " + policyName);
            }
        }
        
        try {
            rootClient.close();
        } catch (IOException e) {
            System.err.println("Error closing root client: " + e.getMessage());
        }
    }
    
    @Test
    @Order(1)
    public void testCreateToken() throws SecureVaultException {
        // Arrange
        TokenCreateOptions options = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList("default", createdPolicies.get(0)))
                .withTtl(Duration.ofMinutes(60))
                .withDisplayName("test-token")
                .withRenewable(true)
                .build();
        
        // Act
        TokenResponse token = rootClient.createToken(options);
        if (token != null && token.getTokenId() != null) {
            createdTokens.add(token.getTokenId());
        }
        
        // Assert
        assertNotNull(token, "Token response should not be null");
        assertNotNull(token.getTokenId(), "Token ID should not be null");
        assertFalse(token.getTokenId().isEmpty(), "Token ID should not be empty");
        assertTrue(token.getPolicies().contains("default"), "Token should have default policy");
        assertTrue(token.getPolicies().contains(createdPolicies.get(0)), "Token should have test policy");
        assertNotNull(token.getCreationTime(), "Creation time should not be null");
        assertNotNull(token.getExpirationTime(), "Expiration time should not be null");
        assertTrue(token.isRenewable(), "Token should be renewable");
    }
    
    @Test
    @Order(2)
    public void testLookupToken() throws SecureVaultException {
        // Arrange
        // First create a token to look up
        TokenCreateOptions createOptions = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList("default"))
                .withTtl(Duration.ofMinutes(60))
                .withDisplayName("lookup-test-token")
                .build();
        
        TokenResponse createdToken = rootClient.createToken(createOptions);
        assertNotNull(createdToken, "Created token should not be null");
        String tokenId = createdToken.getTokenId();
        createdTokens.add(tokenId);
        
        // Act
        TokenLookupResponse lookupResponse = rootClient.lookupToken(tokenId);
        
        // Assert
        assertNotNull(lookupResponse, "Lookup response should not be null");
        assertEquals(tokenId, lookupResponse.getId(), "Token ID should match");
        assertTrue(lookupResponse.getPolicies().contains("default"), "Token should have default policy");
        assertEquals("lookup-test-token", lookupResponse.getDisplayName(), "Display name should match");
        assertNotNull(lookupResponse.getCreationTime(), "Creation time should not be null");
        assertNotNull(lookupResponse.getExpireTime(), "Expiration time should not be null");
    }
    
    @Test
    @Order(3)
    public void testLookupSelfToken() throws SecureVaultException {
        // Act
        TokenLookupResponse lookupResponse = rootClient.lookupSelfToken();
        
        // Assert
        assertNotNull(lookupResponse, "Self token lookup response should not be null");
        assertTrue(lookupResponse.getPolicies().contains("root"), "Root token should have root policy");
    }
    
    @Test
    @Order(4)
    public void testRenewToken() throws SecureVaultException {
        // Arrange
        // Create a renewable token with a short TTL
        TokenCreateOptions createOptions = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList("default"))
                .withTtl(Duration.ofMinutes(5))
                .withDisplayName("renew-test-token")
                .withRenewable(true)
                .build();
        
        TokenResponse createdToken = rootClient.createToken(createOptions);
        assertNotNull(createdToken, "Created token should not be null");
        String tokenId = createdToken.getTokenId();
        createdTokens.add(tokenId);
        
        // Get the original expiration time
        TokenLookupResponse originalLookup = rootClient.lookupToken(tokenId);
        assertNotNull(originalLookup, "Original lookup should not be null");
        assertNotNull(originalLookup.getExpireTime(), "Original expiration time should not be null");
        
        // Act
        TokenRenewOptions renewOptions = TokenRenewOptions.builder()
                .withToken(tokenId)
                .withIncrement(Duration.ofMinutes(30))
                .build();
        
        TokenResponse renewedToken = rootClient.renewToken(renewOptions);
        
        // Assert
        assertNotNull(renewedToken, "Renewed token response should not be null");
        assertEquals(tokenId, renewedToken.getTokenId(), "Token ID should match original");
        
        // Verify the expiration time was extended
        TokenLookupResponse renewedLookup = rootClient.lookupToken(tokenId);
        assertNotNull(renewedLookup, "Renewed lookup should not be null");
        assertNotNull(renewedLookup.getExpireTime(), "Renewed expiration time should not be null");
        
        assertTrue(renewedLookup.getExpireTime().isAfter(originalLookup.getExpireTime()), 
                "Renewed expiration time should be later than original expiration time");
    }
    
    @Test
    @Order(5)
    public void testRenewSelfToken() throws SecureVaultException {
        // Create a client with a renewable token
        TokenCreateOptions createOptions = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList("default"))
                .withTtl(Duration.ofMinutes(10))
                .withDisplayName("renew-self-test-token")
                .withRenewable(true)
                .build();
        
        TokenResponse newToken = rootClient.createToken(createOptions);
        assertNotNull(newToken, "New token should not be null");
        String tokenId = newToken.getTokenId();
        createdTokens.add(tokenId);
        
        // Create a client that uses this token
        SecureVaultClient tokenClient = SecureVaultClient.builder()
                .address(TestConfig.SERVER_ADDRESS)
                .token(tokenId)
                .build();
        
        try {
            // Get original info
            TokenLookupResponse originalLookup = tokenClient.lookupSelfToken();
            assertNotNull(originalLookup, "Original lookup should not be null");
            
            // Renew the token
            TokenResponse renewedToken = tokenClient.renewSelfToken("20m");
            
            // Verify renewal
            assertNotNull(renewedToken, "Renewed token should not be null");
            TokenLookupResponse renewedLookup = tokenClient.lookupSelfToken();
            
            assertTrue(renewedLookup.getExpireTime().isAfter(originalLookup.getExpireTime()),
                    "Renewed expiration time should be later than original expiration time");
        } finally {
            try {
                tokenClient.close();
            } catch (IOException e) {
                System.err.println("Error closing token client: " + e.getMessage());
            }
        }
    }
    
    @Test
    @Order(6)
    public void testRevokeToken() throws SecureVaultException {
        // Arrange - create a token to revoke
        TokenCreateOptions createOptions = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList("default"))
                .withTtl(Duration.ofHours(1))
                .withDisplayName("revoke-test-token")
                .build();
        
        TokenResponse token = rootClient.createToken(createOptions);
        assertNotNull(token, "Token should not be null");
        String tokenId = token.getTokenId();
        
        // First verify we can look it up
        TokenLookupResponse lookupResponse = rootClient.lookupToken(tokenId);
        assertNotNull(lookupResponse, "Lookup response should not be null");
        
        // Act - revoke the token
        TokenRevokeOptions revokeOptions = TokenRevokeOptions.builder()
                .withToken(tokenId)
                .build();
        
        boolean revoked = rootClient.revokeToken(revokeOptions);
        
        // Assert
        assertTrue(revoked, "Token should be successfully revoked");
        
        // Verify token is no longer valid by trying to look it up
        assertThrows(SecureVaultException.class, () -> {
            rootClient.lookupToken(tokenId);
        }, "Looking up revoked token should throw exception");
        
        // No need to add to createdTokens for cleanup since we've already revoked it
    }
    
    @Test
    @Order(7)
    public void testTokenWithMetadata() throws SecureVaultException {
        // Arrange
        Map<String, String> metadata = new HashMap<>();
        metadata.put("owner", "test-user");
        metadata.put("application", "securevault-test");
        metadata.put("environment", "testing");
        
        TokenCreateOptions options = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList("default"))
                .withTtl(Duration.ofMinutes(30))
                .withDisplayName("metadata-test-token")
                .withMetadata(metadata)
                .build();
        
        // Act
        TokenResponse token = rootClient.createToken(options);
        if (token != null && token.getTokenId() != null) {
            createdTokens.add(token.getTokenId());
        }
        
        TokenLookupResponse lookupResponse = rootClient.lookupToken(token.getTokenId());
        
        // Assert
        assertNotNull(lookupResponse, "Lookup response should not be null");
        Map<String, String> retrievedMetadata = lookupResponse.getMetadata();
        assertNotNull(retrievedMetadata, "Metadata should not be null");
        
        assertEquals("test-user", retrievedMetadata.get("owner"), "Owner metadata should match");
        assertEquals("securevault-test", retrievedMetadata.get("application"), "Application metadata should match");
        assertEquals("testing", retrievedMetadata.get("environment"), "Environment metadata should match");
    }
    
    @Test
    @Order(8)
    public void testTokenPolicyEnforcement() throws SecureVaultException {
        // Create a token with limited permissions (only to a specific path)
        String policyName = "limited-policy-" + UUID.randomUUID().toString().substring(0, 8);
        createdPolicies.add(policyName);
        
        // Create a limited policy
        Policy limitedPolicy = new Policy();
        limitedPolicy.setName(policyName);
        
        // Create a policy rule
        PolicyRule allowedRule = new PolicyRule();
        allowedRule.setPath("secret/" + TestConfig.TEST_NAMESPACE + "/allowed/*");
        allowedRule.setCapabilities(Arrays.asList("read", "list"));
        
        // Set rules for the policy
        limitedPolicy.setRules(Collections.singletonList(allowedRule));
        
        // Create a token with the limited policy
        TokenCreateOptions options = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList(policyName))
                .withTtl(Duration.ofMinutes(30))
                .build();
        
        TokenResponse token = rootClient.createToken(options);
        String tokenId = token.getTokenId();
        createdTokens.add(tokenId);
        
        // Create a client that uses this limited token
        SecureVaultClient limitedClient = SecureVaultClient.builder()
                .address(TestConfig.SERVER_ADDRESS)
                .token(tokenId)
                .build();
        try {
            // Create test secrets
            String allowedSecretPath = TestConfig.TEST_NAMESPACE + "/allowed/test-secret";
            String deniedSecretPath = TestConfig.TEST_NAMESPACE + "/forbidden/test-secret";
            
            Map<String, Object> secretData = new HashMap<>();
            secretData.put("key", "test-value");
            
            // Using root client to set up the secrets
            rootClient.writeSecret("secret/" + allowedSecretPath, secretData);
            rootClient.writeSecret("secret/" + deniedSecretPath, secretData);
            
            // Test with limited client
            
            // Should be able to read from allowed path
            Map<String, Object> allowedSecretData = limitedClient.readSecret("secret/" + allowedSecretPath);
            Secret allowedSecret = Secret.fromMap(allowedSecretData);
            assertEquals("test-value", allowedSecret.getData().get("key"), "Should be able to read from allowed path");
            
            // Try to read from a forbidden path
            assertThrows(SecureVaultForbiddenException.class, () -> {
                limitedClient.readSecret("secret/" + deniedSecretPath);
            }, "Reading from forbidden path should throw exception");
            
            // Try to write to allowed path (should fail because we only gave read access)
            assertThrows(SecureVaultForbiddenException.class, () -> {
                limitedClient.writeSecret("secret/" + allowedSecretPath, secretData);
            }, "Writing to allowed path should throw exception");
            
            // Clean up secrets
            rootClient.deleteSecret("secret/" + allowedSecretPath);
            rootClient.deleteSecret("secret/" + deniedSecretPath);
        } finally {
            try {
                limitedClient.close();
            } catch (IOException e) {
                System.err.println("Error closing limited client: " + e.getMessage());
            }
        }
    }
    @Test
    @Order(9)
    public void testTokenExpiration() throws Exception {
        // Create a token with very short TTL (5 seconds)
        TokenCreateOptions options = TokenCreateOptions.builder()
                .withPolicies(Arrays.asList("default"))
                .withTtl("5s")  // 5 seconds
                .build();
        
        TokenResponse token = rootClient.createToken(options);
        String tokenId = token.getTokenId();
        // Don't add to createdTokens as it will expire anyway
        
        // Create a client with this token
        SecureVaultClient shortLivedClient = SecureVaultClient.builder()
                .address(TestConfig.SERVER_ADDRESS)
                .token(tokenId)
                .build();
        
        try {
            // Initial operation should succeed
            TokenLookupResponse initialLookup = shortLivedClient.lookupSelfToken();
            assertNotNull(initialLookup, "Initial lookup should succeed");
            
            // Wait for token to expire
            System.out.println("Waiting for token to expire...");
            Thread.sleep(6000);  // Wait 6 seconds
            
            // Operation after expiration should fail
            assertThrows(SecureVaultUnauthorizedException.class, () -> {
                shortLivedClient.lookupSelfToken();
            }, "Operation with expired token should throw UnauthorizedException");
        } finally {
            try {
                shortLivedClient.close();
            } catch (IOException e) {
                System.err.println("Error closing short-lived client: " + e.getMessage());
            }
        }
    }
}
