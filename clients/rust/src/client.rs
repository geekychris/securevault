use std::collections::HashMap;

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::Value;

use crate::error::{Result, SecureVaultError};
use crate::models::*;

/// A blocking client for the SecureVault REST API.
#[derive(Debug, Clone)]
pub struct SecureVaultClient {
    address: String,
    token: String,
    http: Client,
}

impl SecureVaultClient {
    /// Create a new client pointing at the given SecureVault `address`
    /// (e.g. `"http://127.0.0.1:8200"`) authenticated with `token`.
    pub fn new(address: &str, token: &str) -> Self {
        Self {
            address: address.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: Client::new(),
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.address, path)
    }

    /// Map an HTTP response to the appropriate error variant when the status
    /// code indicates failure.
    fn check_response(
        &self,
        resp: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }

        let body = resp.text().unwrap_or_default();

        match status {
            StatusCode::UNAUTHORIZED => Err(SecureVaultError::Unauthorized(body)),
            StatusCode::FORBIDDEN => Err(SecureVaultError::Forbidden(body)),
            StatusCode::NOT_FOUND => Err(SecureVaultError::NotFound(body)),
            StatusCode::CONFLICT => Err(SecureVaultError::Conflict(body)),
            s if s.is_server_error() => Err(SecureVaultError::ServerError {
                status: s.as_u16(),
                message: body,
            }),
            _ => Err(SecureVaultError::RequestFailed(format!(
                "unexpected status {}: {}",
                status.as_u16(),
                body
            ))),
        }
    }

    // ------------------------------------------------------------------
    // Secrets
    // ------------------------------------------------------------------

    /// Write a secret at the given `path`.
    pub fn write_secret(&self, path: &str, data: HashMap<String, Value>) -> Result<()> {
        let url = self.url(&format!("/v1/secret/{}", path));
        let body = WriteSecretRequest { data };
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    /// Read the latest version of a secret at `path`.
    pub fn read_secret(&self, path: &str) -> Result<Secret> {
        let url = self.url(&format!("/v1/secret/{}", path));
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let secret: Secret = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(secret)
    }

    /// Read a specific `version` of a secret at `path`.
    pub fn read_secret_version(&self, path: &str, version: u32) -> Result<Secret> {
        let url = self.url(&format!("/v1/secret/versions/{}/{}", version, path));
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let secret: Secret = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(secret)
    }

    /// Delete a secret at `path` with the given options.
    pub fn delete_secret(&self, path: &str, options: DeleteOptions) -> Result<()> {
        let mut url = format!("{}/v1/secret/{}", self.address, path);

        let mut query_parts: Vec<String> = Vec::new();
        if let Some(ref versions) = options.versions {
            let v: Vec<String> = versions.iter().map(|v| v.to_string()).collect();
            query_parts.push(format!("versions={}", v.join(",")));
        }
        if options.destroy {
            query_parts.push("destroy=true".to_string());
        }
        if !query_parts.is_empty() {
            url = format!("{}?{}", url, query_parts.join("&"));
        }

        let resp = self
            .http
            .delete(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    /// List secret keys under `path`.
    pub fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        let url = self.url(&format!("/v1/secret/list/{}", path));
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let list: ListSecretsResponse = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(list.keys)
    }

    /// Get metadata for a secret at `path`.
    pub fn get_secret_metadata(&self, path: &str) -> Result<SecretMetadata> {
        let url = self.url(&format!("/v1/secret/metadata/{}", path));
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let metadata: SecretMetadata = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(metadata)
    }

    // ------------------------------------------------------------------
    // Tokens
    // ------------------------------------------------------------------

    /// Create a new token with the given policies and optional TTL.
    pub fn create_token(
        &self,
        policy_ids: Vec<String>,
        ttl: Option<String>,
    ) -> Result<TokenResponse> {
        let url = self.url("/v1/auth/token/create");
        let body = CreateTokenRequest { policy_ids, ttl };
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()?;
        let resp = self.check_response(resp)?;
        let token_resp: TokenResponse = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(token_resp)
    }

    /// Look up information about the current token.
    pub fn lookup_token(&self) -> Result<TokenLookupResponse> {
        let url = self.url("/v1/auth/token/lookup-self");
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let lookup: TokenLookupResponse = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(lookup)
    }

    /// Renew the current token.
    pub fn renew_token(&self) -> Result<()> {
        let url = self.url("/v1/auth/token/renew-self");
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    /// Revoke the current token.
    pub fn revoke_token(&self) -> Result<()> {
        let url = self.url("/v1/auth/token/revoke-self");
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Policies
    // ------------------------------------------------------------------

    /// Create a new policy.
    pub fn create_policy(&self, policy: Policy) -> Result<()> {
        let url = self.url("/v1/policies");
        let body = CreatePolicyRequest { policy };
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    /// Get a policy by name.
    pub fn get_policy(&self, name: &str) -> Result<Policy> {
        let url = self.url(&format!("/v1/policies/{}", name));
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let policy: Policy = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(policy)
    }

    /// Update an existing policy.
    pub fn update_policy(&self, policy: Policy) -> Result<()> {
        let url = self.url(&format!("/v1/policies/{}", policy.name));
        let resp = self
            .http
            .put(&url)
            .header("X-Vault-Token", &self.token)
            .json(&policy)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    /// Delete a policy by name.
    pub fn delete_policy(&self, name: &str) -> Result<()> {
        let url = self.url(&format!("/v1/policies/{}", name));
        let resp = self
            .http
            .delete(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    /// List all policies.
    pub fn list_policies(&self) -> Result<Vec<Policy>> {
        let url = self.url("/v1/policies");
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let list: ListPoliciesResponse = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(list.policies)
    }

    // ------------------------------------------------------------------
    // System
    // ------------------------------------------------------------------

    /// Get the current seal status.
    pub fn seal_status(&self) -> Result<SealStatus> {
        let url = self.url("/v1/sys/seal-status");
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        let resp = self.check_response(resp)?;
        let status: SealStatus = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(status)
    }

    /// Submit an unseal key. Returns the updated seal status.
    pub fn unseal(&self, key: &str) -> Result<SealStatus> {
        let url = self.url("/v1/sys/unseal");
        let body = UnsealRequest {
            key: key.to_string(),
        };
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()?;
        let resp = self.check_response(resp)?;
        let status: SealStatus = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(status)
    }

    /// Seal the vault.
    pub fn seal(&self) -> Result<()> {
        let url = self.url("/v1/sys/seal");
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .send()?;
        self.check_response(resp)?;
        Ok(())
    }

    /// Initialize the vault with the given Shamir secret sharing parameters.
    pub fn initialize(
        &self,
        secret_shares: u32,
        secret_threshold: u32,
    ) -> Result<InitResponse> {
        let url = self.url("/v1/sys/init");
        let body = InitRequest {
            secret_shares,
            secret_threshold,
        };
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()?;
        let resp = self.check_response(resp)?;
        let init: InitResponse = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(init)
    }

    /// Check the health of the vault.
    pub fn health(&self) -> Result<HealthResponse> {
        let url = self.url("/v1/health");
        let resp = self.http.get(&url).send()?;
        let resp = self.check_response(resp)?;
        let health: HealthResponse = resp.json().map_err(|e| {
            SecureVaultError::DeserializationError(e.to_string())
        })?;
        Ok(health)
    }
}
