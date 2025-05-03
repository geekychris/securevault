package com.example.securevault;

import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.model.*;
import org.junit.jupiter.api.*;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for policy management in SecureVaultClient.
 * These tests require a running SecureVault server.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PolicyTest {
    private static SecureVaultClient client;
    private static final List<String> createdPolicies = new ArrayList<>();
    
    @BeforeAll
    public static void setUp() {
        client = TestConfig.createRootClient();
        System.out.println("Using test namespace: " + TestConfig.TEST_NAMESPACE);
    }
    
    @AfterAll
    public static void tearDown() throws Exception {
        // Delete all policies created during tests
        for (String policyName : createdPolicies) {
            try {
                client.deletePolicy(policyName);
            } catch (Exception e) {
                System.err.println("Failed to delete policy: " + policyName + ", error: " + e.getMessage());
            }
        }
        client.close();
    }
    
    @Test
    @Order(1)
    public void testCreatePolicy() throws SecureVaultException {
        String policyName = "test-policy-" + UUID.randomUUID().toString().substring(0, 8);
        createdPolicies.add(policyName);
        
        // Create a basic policy for test
        Policy policy = new Policy();
        policy.setName(policyName);
        
        String path = "/secret/" + TestConfig.TEST_NAMESPACE + "/*";
        List<String> capabilities = Arrays.asList("read", "list");
        
        // Add a rule to the policy
        PolicyRule rule = new PolicyRule();
        rule.setPath(path);
        rule.setCapabilities(capabilities);
        policy.setRules(Collections.singletonList(rule));
        
        boolean created = client.createPolicy(policy);
        assertTrue(created, "Policy should be created successfully");
        
        // Verify policy exists
        Policy retrievedPolicy = client.getPolicy(policyName);
        assertNotNull(retrievedPolicy, "Retrieved policy should not be null");
        assertEquals(policyName, retrievedPolicy.getName(), "Policy name should match");
    }
    
    @Test
    @Order(2)
    public void testListPolicies() throws SecureVaultException {
        List<String> policies = client.listPolicies();
        assertNotNull(policies, "Policy list should not be null");
        assertFalse(policies.isEmpty(), "Policy list should not be empty");
        
        // Verify our test policy is in the list
        assertTrue(policies.stream().anyMatch(p -> createdPolicies.contains(p)), 
                "Policy list should contain our test policy");
    }
}
