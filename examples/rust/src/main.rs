use securevault_client::{SecureVaultClient, Policy, PathRule, DeleteOptions};
use serde_json::json;
use std::collections::HashMap;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <vault-address> [token]", args[0]);
        eprintln!("Example: {} http://127.0.0.1:8200", args[0]);
        std::process::exit(1);
    }

    let vault_addr = &args[1];
    let mut token = if args.len() >= 3 { args[2].clone() } else { String::new() };

    // --- Initialize and Unseal ---
    if token.is_empty() {
        println!("=== Checking Vault Status ===");
        let client = SecureVaultClient::new(vault_addr, "");
        let status = client.seal_status()?;
        println!("Initialized: {}, Sealed: {}", status.initialized, status.sealed);

        if !status.initialized {
            println!("Initializing vault...");
            let init_resp = client.initialize(3, 2)?;

            println!("Root Token: {}", init_resp.root_token);
            println!("Unseal Keys:");
            for (i, key) in init_resp.keys.iter().enumerate() {
                println!("  Key {}: {}", i + 1, key);
            }
            println!("\n*** SAVE THESE KEYS SECURELY ***\n");

            token = init_resp.root_token;

            // Unseal with threshold keys
            let client = SecureVaultClient::new(vault_addr, &token);
            for key in init_resp.keys.iter().take(2) {
                let seal_status = client.unseal(key)?;
                println!("Unseal progress: {}/{}", seal_status.progress, seal_status.threshold);
                if !seal_status.sealed {
                    println!("Vault is unsealed!");
                }
            }
        } else if status.sealed {
            eprintln!("Vault is sealed. Provide unseal keys.");
            std::process::exit(1);
        }
    }

    let client = SecureVaultClient::new(vault_addr, &token);

    // --- Policy Management ---
    println!("\n=== Policy Management ===");
    let policy = Policy {
        name: "rust-reader".to_string(),
        description: "Read-only access for Rust example".to_string(),
        rules: vec![PathRule {
            path: "app/*".to_string(),
            capabilities: vec!["read".to_string(), "list".to_string()],
        }],
    };
    match client.create_policy(policy) {
        Ok(_) => println!("Created 'rust-reader' policy"),
        Err(e) => println!("Create policy: {}", e),
    }

    // --- Secret Operations ---
    println!("\n=== Secret Operations ===");

    // Write a secret
    let mut data = HashMap::new();
    data.insert("host".to_string(), json!("db.internal.example.com"));
    data.insert("port".to_string(), json!(5432));
    data.insert("username".to_string(), json!("rust_app"));
    data.insert("password".to_string(), json!("rust-secret-password"));

    client.write_secret("app/rust/database", data)?;
    println!("Written secret: app/rust/database");

    // Read the secret
    let secret = client.read_secret("app/rust/database")?;
    println!(
        "Read: host={}, user={} (v{})",
        secret.data["host"], secret.data["username"], secret.metadata.version
    );

    // Update (creates version 2)
    let mut updated_data = HashMap::new();
    updated_data.insert("host".to_string(), json!("db.internal.example.com"));
    updated_data.insert("port".to_string(), json!(5432));
    updated_data.insert("username".to_string(), json!("rust_app"));
    updated_data.insert("password".to_string(), json!("rotated-rust-password"));

    client.write_secret("app/rust/database", updated_data)?;
    println!("Updated secret (new version)");

    // Read specific version
    match client.read_secret_version("app/rust/database", 1) {
        Ok(v1) => println!("Version 1 password: {}", v1.data["password"]),
        Err(e) => println!("Read v1: {}", e),
    }

    // List secrets
    match client.list_secrets("app/rust") {
        Ok(keys) => println!("Secrets under app/rust: {:?}", keys),
        Err(e) => println!("List secrets: {}", e),
    }

    // --- Token Management ---
    println!("\n=== Token Management ===");

    let token_resp = client.create_token(vec!["rust-reader".to_string()], Some("2h".to_string()))?;
    println!("Created restricted token: {}...", &token_resp.client_token[..10]);

    // Use restricted token
    let restricted = SecureVaultClient::new(vault_addr, &token_resp.client_token);

    // Read should work
    match restricted.read_secret("app/rust/database") {
        Ok(s) => println!("Restricted read: host={}", s.data["host"]),
        Err(e) => println!("Restricted read failed: {}", e),
    }

    // Write should fail
    let mut hack_data = HashMap::new();
    hack_data.insert("hacked".to_string(), json!(true));
    match restricted.write_secret("app/rust/database", hack_data) {
        Ok(_) => println!("ERROR: Write should have been denied!"),
        Err(e) => println!("Restricted write correctly denied: {}", e),
    }

    // --- Cleanup ---
    println!("\n=== Cleanup ===");
    client.delete_secret("app/rust/database", DeleteOptions { destroy: true, ..Default::default() })?;
    println!("Destroyed app/rust/database");
    client.delete_policy("rust-reader")?;
    println!("Deleted rust-reader policy");

    // Health
    let health = client.health()?;
    println!("\nVault health: {}", health.status);

    println!("\n=== Example Complete ===");
    Ok(())
}
