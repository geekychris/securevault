package com.example.securevault.walkthrough;

import com.example.securevault.SecureVaultClient;
import com.example.securevault.model.Policy;
import com.example.securevault.model.TokenCreateOptions;
import com.example.securevault.model.TokenResponse;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Demonstrates the administrator workflow:
 *   1. Connect with a root token
 *   2. Store secrets (service-specific AND shared)
 *   3. Create policies (service-specific, shared, and cross-cutting)
 *   4. Generate tokens with MULTIPLE policies for cross-team access
 */
public class AdminSetup {

    private final SecureVaultClient client;

    public AdminSetup(String vaultAddr, String rootToken) {
        this.client = SecureVaultClient.builder()
                .address(vaultAddr)
                .token(rootToken)
                .requestTimeout(10_000)
                .build();
    }

    /** Stores all application and shared secrets. */
    public void storeSecrets() throws Exception {
        System.out.println("► Storing secrets...");

        // --- Service-specific secrets ---

        Map<String, Object> dbCreds = new HashMap<>();
        dbCreds.put("host", "db.production.internal");
        dbCreds.put("port", 5432);
        dbCreds.put("username", "app_service");
        dbCreds.put("password", "xK9#mP2$vL5nQ8wR");
        dbCreds.put("database", "myapp_production");
        client.writeSecret("app/db/credentials", dbCreds);
        System.out.println("  ✓ app/db/credentials        (backend only)");

        Map<String, Object> stripeKeys = new HashMap<>();
        stripeKeys.put("publishable_key", "pk_live_51ABC123DEF456GHI789");
        stripeKeys.put("secret_key", "sk_live_51ABC123DEF456GHI789");
        stripeKeys.put("webhook_secret", "whsec_ABC123DEF456GHI789JKL");
        client.writeSecret("app/api/stripe", stripeKeys);
        System.out.println("  ✓ app/api/stripe             (payments only)");

        Map<String, Object> redisCreds = new HashMap<>();
        redisCreds.put("host", "redis.production.internal");
        redisCreds.put("port", 6379);
        redisCreds.put("password", "rD7kL3mN9pQ2wX");
        client.writeSecret("app/cache/redis", redisCreds);
        System.out.println("  ✓ app/cache/redis            (backend only)");

        // --- Shared secrets (used by multiple services) ---

        Map<String, Object> datadog = new HashMap<>();
        datadog.put("api_key", "dd_live_abc123def456ghi789");
        datadog.put("app_key", "dd_app_xyz987uvw654rst321");
        datadog.put("site", "datadoghq.com");
        client.writeSecret("shared/logging/datadog", datadog);
        System.out.println("  ✓ shared/logging/datadog     (ALL services)");

        Map<String, Object> rabbitmq = new HashMap<>();
        rabbitmq.put("host", "rabbitmq.production.internal");
        rabbitmq.put("port", 5672);
        rabbitmq.put("username", "app_publisher");
        rabbitmq.put("password", "mQ8$nR4#kW2vP7jL");
        client.writeSecret("shared/messaging/rabbitmq", rabbitmq);
        System.out.println("  ✓ shared/messaging/rabbitmq  (ALL services)");

        Map<String, Object> jwtKeys = new HashMap<>();
        jwtKeys.put("algorithm", "RS256");
        jwtKeys.put("private_key", "-----BEGIN RSA PRIVATE KEY-----\nexample\n-----END RSA PRIVATE KEY-----");
        jwtKeys.put("public_key", "-----BEGIN PUBLIC KEY-----\nexample\n-----END PUBLIC KEY-----");
        jwtKeys.put("issuer", "myapp.example.com");
        client.writeSecret("shared/auth/jwt-signing", jwtKeys);
        System.out.println("  ✓ shared/auth/jwt-signing    (backend + payments)");

        System.out.println();
    }

    /** Creates policies — both service-specific and shared. */
    public void createPolicies() throws Exception {
        System.out.println("► Creating policies...");

        createPolicySafe("backend-service", "Backend: DB and cache access",
                new String[]{"app/db/*", "read,list"}, new String[]{"app/cache/*", "read,list"});
        System.out.println("  ✓ backend-service    → app/db/*, app/cache/*");

        createPolicySafe("payments-service", "Payments: Stripe API keys",
                new String[]{"app/api/*", "read"});
        System.out.println("  ✓ payments-service   → app/api/*");

        createPolicySafe("shared-infra", "Shared: logging + messaging for all services",
                new String[]{"shared/logging/*", "read,list"}, new String[]{"shared/messaging/*", "read,list"});
        System.out.println("  ✓ shared-infra       → shared/logging/*, shared/messaging/*");

        createPolicySafe("auth-signing", "JWT signing keys for token-issuing services",
                new String[]{"shared/auth/*", "read"});
        System.out.println("  ✓ auth-signing       → shared/auth/*");

        createPolicySafe("devops-admin", "DevOps: full shared access, read-only app access",
                new String[]{"shared/**", "read,create,update,delete,list"}, new String[]{"app/**", "read,list"});
        System.out.println("  ✓ devops-admin       → shared/* (full), app/* (read)");

        System.out.println();
    }

    private void createPolicySafe(String name, String description, String[]... rules) {
        try {
            Policy p = Policy.builder().name(name).description(description).build();
            for (String[] rule : rules) {
                p.addRule(rule[0], Arrays.asList(rule[1].split(",")));
            }
            client.createPolicy(p);
        } catch (Exception e) {
            // Policy may already exist from bash walkthrough — that's fine
            if (!e.getMessage().contains("409") && !e.getMessage().toLowerCase().contains("exists")) {
                System.out.println("  Warning creating policy " + name + ": " + e.getMessage());
            }
        }
    }

    /**
     * Generates tokens with MULTIPLE policies.
     * This is how shared access works: attach several policies to one token.
     */
    public Map<String, String> generateTokens() throws Exception {
        System.out.println("► Generating tokens with multiple policies...");
        System.out.println();
        System.out.println("  A token's effective access = UNION of all its policies.");
        System.out.println("  This lets you compose fine-grained building blocks.");
        System.out.println();

        Map<String, String> tokens = new HashMap<>();

        // Backend: own policy + shared infra
        TokenResponse backendResp = client.createToken(
                TokenCreateOptions.builder()
                        .withPolicies(List.of("backend-service", "shared-infra"))
                        .withTtl("8h")
                        .build());
        tokens.put("backend-service", backendResp.getTokenId());
        System.out.println("  ✓ Backend:  [backend-service, shared-infra]");
        System.out.println("    → app/db/*, app/cache/*, shared/logging/*, shared/messaging/*");

        // Payments: own policy + shared infra + auth signing
        TokenResponse paymentsResp = client.createToken(
                TokenCreateOptions.builder()
                        .withPolicies(List.of("payments-service", "shared-infra", "auth-signing"))
                        .withTtl("8h")
                        .build());
        tokens.put("payments-service", paymentsResp.getTokenId());
        System.out.println("  ✓ Payments: [payments-service, shared-infra, auth-signing]");
        System.out.println("    → app/api/*, shared/logging/*, shared/messaging/*, shared/auth/*");

        // DevOps: single broad policy
        TokenResponse devopsResp = client.createToken(
                TokenCreateOptions.builder()
                        .withPolicies(List.of("devops-admin"))
                        .withTtl("4h")
                        .build());
        tokens.put("devops-admin", devopsResp.getTokenId());
        System.out.println("  ✓ DevOps:   [devops-admin]");
        System.out.println("    → shared/* (read+write), app/* (read)");

        System.out.println();
        return tokens;
    }

    public void close() {
        try { client.close(); } catch (Exception e) { /* ignore */ }
    }
}
