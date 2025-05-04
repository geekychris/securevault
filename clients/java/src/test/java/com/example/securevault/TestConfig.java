package com.example.securevault;

import java.util.UUID;

/**
 * Configuration for tests.
 */
public class TestConfig {
    // Server address - modify according to your local setup
    public static final String SERVER_ADDRESS = "http://localhost:8200";
    
    // Root token - modify according to your server setup
    public static final String ROOT_TOKEN = "s.root";
    
    // Test namespace to isolate test data
    public static final String TEST_NAMESPACE = "test-" + UUID.randomUUID().toString().substring(0, 8);
    
    /**
     * Generates a unique path for test secrets.
     *
     * @param testName the name of the test
     * @return a unique path
     */
    public static String generateTestPath(String testName) {
        return TEST_NAMESPACE + "/" + testName + "-" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    /**
     * Builds a SecureVaultClient with the root token.
     *
     * @return a configured client
     */
    public static SecureVaultClient createRootClient() {
        return SecureVaultClient.builder()
                .address(SERVER_ADDRESS)
                .token(ROOT_TOKEN)
                .build();
    }
}
