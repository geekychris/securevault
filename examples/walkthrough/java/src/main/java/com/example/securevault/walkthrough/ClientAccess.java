package com.example.securevault.walkthrough;

import com.example.securevault.SecureVaultClient;
import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.exception.SecureVaultForbiddenException;
import com.example.securevault.exception.SecureVaultUnauthorizedException;

import java.util.Map;

/**
 * Demonstrates application-side access with multi-policy tokens.
 *
 * Each service connects with a token that has multiple policies attached.
 * The effective access is the union of all policies on the token.
 */
public class ClientAccess {

    private final String serviceName;
    private final SecureVaultClient client;

    public ClientAccess(String vaultAddr, String token, String serviceName) {
        this.serviceName = serviceName;
        this.client = SecureVaultClient.builder()
                .address(vaultAddr)
                .token(token)
                .requestTimeout(5_000)
                .build();
    }

    public void tryReadSecret(String path, boolean expectAllow) {
        try {
            Map<String, Object> secret = client.readSecret(path);
            if (expectAllow) {
                System.out.println("  ✓ READ " + path);
                for (Map.Entry<String, Object> entry : secret.entrySet()) {
                    String value = String.valueOf(entry.getValue());
                    if (value.length() > 40) value = value.substring(0, 37) + "...";
                    System.out.println("      " + entry.getKey() + " = " + value);
                }
            } else {
                System.out.println("  ⚠ READ " + path + " — GRANTED (unexpected!)");
            }
        } catch (SecureVaultForbiddenException e) {
            if (!expectAllow) {
                System.out.println("  ✗ READ " + path + " — DENIED");
            } else {
                System.out.println("  ⚠ READ " + path + " — DENIED (unexpected!)");
            }
        } catch (SecureVaultUnauthorizedException e) {
            System.out.println("  ✗ READ " + path + " — UNAUTHORIZED");
        } catch (SecureVaultException e) {
            System.out.println("  ? READ " + path + " — " + e.getMessage());
        }
    }

    public void tryWriteSecret(String path, boolean expectAllow) {
        try {
            client.writeSecret(path, Map.of("rotated", "true", "timestamp", System.currentTimeMillis()));
            if (expectAllow) {
                System.out.println("  ✓ WRITE " + path + " — SUCCESS");
            } else {
                System.out.println("  ⚠ WRITE " + path + " — GRANTED (unexpected!)");
            }
        } catch (SecureVaultForbiddenException e) {
            if (!expectAllow) {
                System.out.println("  ✗ WRITE " + path + " — DENIED");
            } else {
                System.out.println("  ⚠ WRITE " + path + " — DENIED (unexpected!)");
            }
        } catch (SecureVaultException e) {
            System.out.println("  ✗ WRITE " + path + " — " + e.getMessage());
        }
    }

    public void runDemo() {
        System.out.println("┌───────────────────────────────────────────────────────┐");
        System.out.println("│ " + padRight(serviceName, 54) + "│");
        System.out.println("└───────────────────────────────────────────────────────┘");

        switch (serviceName) {
            case "backend-service" -> runBackendDemo();
            case "payments-service" -> runPaymentsDemo();
            case "devops-admin" -> runDevOpsDemo();
            default -> System.out.println("  Unknown service: " + serviceName);
        }
        System.out.println();
    }

    private void runBackendDemo() {
        System.out.println("  Policies: backend-service + shared-infra");
        System.out.println();

        System.out.println("  ── Service-specific secrets (backend-service policy) ──");
        tryReadSecret("app/db/credentials", true);
        tryReadSecret("app/cache/redis", true);
        System.out.println();

        System.out.println("  ── Shared secrets (shared-infra policy) ──");
        tryReadSecret("shared/logging/datadog", true);
        tryReadSecret("shared/messaging/rabbitmq", true);
        System.out.println();

        System.out.println("  ── Secrets outside this token's policies ──");
        tryReadSecret("app/api/stripe", false);
        tryReadSecret("shared/auth/jwt-signing", false);
    }

    private void runPaymentsDemo() {
        System.out.println("  Policies: payments-service + shared-infra + auth-signing");
        System.out.println();

        System.out.println("  ── Service-specific secrets (payments-service policy) ──");
        tryReadSecret("app/api/stripe", true);
        System.out.println();

        System.out.println("  ── Shared secrets (shared-infra policy) ──");
        tryReadSecret("shared/logging/datadog", true);
        tryReadSecret("shared/messaging/rabbitmq", true);
        System.out.println();

        System.out.println("  ── Auth secrets (auth-signing policy) ──");
        tryReadSecret("shared/auth/jwt-signing", true);
        System.out.println();

        System.out.println("  ── Secrets outside this token's policies ──");
        tryReadSecret("app/db/credentials", false);
        tryReadSecret("app/cache/redis", false);
    }

    private void runDevOpsDemo() {
        System.out.println("  Policy: devops-admin");
        System.out.println("  Can READ everything, can WRITE only shared/*");
        System.out.println();

        System.out.println("  ── Read access (broad) ──");
        tryReadSecret("app/db/credentials", true);
        tryReadSecret("app/api/stripe", true);
        tryReadSecret("shared/logging/datadog", true);
        tryReadSecret("shared/auth/jwt-signing", true);
        System.out.println();

        System.out.println("  ── Write access (shared only) ──");
        tryWriteSecret("shared/logging/datadog", true);
        tryWriteSecret("app/db/credentials", false);
    }

    public void close() {
        try { client.close(); } catch (Exception e) { /* ignore */ }
    }

    private static String padRight(String s, int w) {
        return s.length() >= w ? s : s + " ".repeat(w - s.length());
    }
}
