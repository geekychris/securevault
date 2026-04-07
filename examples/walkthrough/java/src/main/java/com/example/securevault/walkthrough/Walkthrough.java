package com.example.securevault.walkthrough;

import java.util.Map;

/**
 * SecureVault End-to-End Walkthrough — Cross-Team Secret Sharing
 *
 * This demonstrates:
 *   1. Admin stores service-specific AND shared secrets
 *   2. Admin creates composable policies (service-specific + shared)
 *   3. Admin generates tokens with MULTIPLE policies per service
 *   4. Each service accesses its own secrets AND shared ones
 *   5. Access outside the combined policies is still denied
 *
 * Usage:
 *   mvn compile exec:java
 *   mvn compile exec:java -Dexec.args="http://127.0.0.1:8200 s.your-root-token"
 */
public class Walkthrough {

    public static void main(String[] args) {
        String vaultAddr = args.length > 0 ? args[0] : "http://127.0.0.1:8200";
        String rootToken = args.length > 1 ? args[1] : System.getenv("ROOT_TOKEN");

        if (rootToken == null || rootToken.isEmpty()) {
            rootToken = readTokenFromFile();
        }
        if (rootToken == null || rootToken.isEmpty()) {
            System.err.println("ERROR: No root token. Run 01-admin-setup.sh first or pass as argument.");
            System.exit(1);
        }

        System.out.println("============================================");
        System.out.println("  SecureVault Java Walkthrough");
        System.out.println("  Cross-Team Secret Sharing");
        System.out.println("============================================");
        System.out.println();

        try {
            // ── Phase 1: Admin Setup ──
            System.out.println("━━━━ Phase 1: Administrator Setup ━━━━━━━━━━━━━━━━━━━━━");
            System.out.println();

            AdminSetup admin = new AdminSetup(vaultAddr, rootToken);
            admin.storeSecrets();
            admin.createPolicies();
            Map<String, String> tokens = admin.generateTokens();
            admin.close();

            // ── Phase 2: Each service connects with its multi-policy token ──
            System.out.println("━━━━ Phase 2: Service Access ━━━━━━━━━━━━━━━━━━━━━━━━━━");
            System.out.println();
            System.out.println("  Each token below has MULTIPLE policies.");
            System.out.println("  Shared secrets (logging, messaging) are accessible by");
            System.out.println("  both backend and payments because both tokens include");
            System.out.println("  the shared-infra policy.");
            System.out.println();

            ClientAccess backend = new ClientAccess(vaultAddr, tokens.get("backend-service"), "backend-service");
            backend.runDemo();
            backend.close();

            ClientAccess payments = new ClientAccess(vaultAddr, tokens.get("payments-service"), "payments-service");
            payments.runDemo();
            payments.close();

            ClientAccess devops = new ClientAccess(vaultAddr, tokens.get("devops-admin"), "devops-admin");
            devops.runDemo();
            devops.close();

            // ── Phase 3: Invalid token ──
            System.out.println("━━━━ Phase 3: Invalid Token ━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            System.out.println();
            ClientAccess invalid = new ClientAccess(vaultAddr, "s.not-a-real-token", "invalid");
            invalid.tryReadSecret("app/db/credentials", false);
            invalid.close();

            // ── Summary ──
            System.out.println();
            System.out.println("============================================");
            System.out.println("  How Cross-Team Sharing Works");
            System.out.println("============================================");
            System.out.println();
            System.out.println("  1. Secrets are organized by ownership:");
            System.out.println("     app/db/*     → owned by backend team");
            System.out.println("     app/api/*    → owned by payments team");
            System.out.println("     shared/*     → owned by platform/DevOps");
            System.out.println();
            System.out.println("  2. Policies are small, composable building blocks:");
            System.out.println("     backend-service  → app/db/*, app/cache/*");
            System.out.println("     payments-service → app/api/*");
            System.out.println("     shared-infra     → shared/logging/*, shared/messaging/*");
            System.out.println("     auth-signing     → shared/auth/*");
            System.out.println();
            System.out.println("  3. Tokens combine multiple policies:");
            System.out.println("     backend token  = backend-service + shared-infra");
            System.out.println("     payments token = payments-service + shared-infra + auth-signing");
            System.out.println("     devops token   = devops-admin (one broad policy)");
            System.out.println();
            System.out.println("  4. Effective access = UNION of all policies on the token.");
            System.out.println("     shared/logging/datadog is readable by BOTH backend");
            System.out.println("     and payments, because both include shared-infra.");
            System.out.println();

        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static String readTokenFromFile() {
        try {
            var reader = new java.io.BufferedReader(new java.io.FileReader("/tmp/securevault-walkthrough-tokens.env"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("ROOT_TOKEN=")) {
                    reader.close();
                    return line.substring("ROOT_TOKEN=".length()).trim();
                }
            }
            reader.close();
        } catch (Exception e) { /* ok */ }
        return null;
    }
}
