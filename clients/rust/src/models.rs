use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Secret types
// ---------------------------------------------------------------------------

/// A secret read from SecureVault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub data: HashMap<String, Value>,
    pub metadata: SecretResponseMetadata,
}

/// Metadata returned alongside a secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretResponseMetadata {
    pub created_time: String,
    pub version: u64,
    pub created_by: String,
    pub current_version: u64,
}

/// Full metadata for a secret path (without the secret data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub versions: HashMap<String, VersionMetadata>,
    pub current_version: u64,
    pub created_time: String,
    pub last_modified: String,
}

/// Per-version metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub created_time: String,
    pub created_by: String,
    pub is_destroyed: bool,
}

/// Options for secret deletion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteOptions {
    /// Specific versions to delete. `None` targets the latest version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<u32>>,
    /// If `true`, the data is permanently destroyed rather than soft-deleted.
    pub destroy: bool,
}

impl Default for DeleteOptions {
    fn default() -> Self {
        Self {
            versions: None,
            destroy: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Token types
// ---------------------------------------------------------------------------

/// Response from creating a new token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub client_token: String,
    pub policies: Vec<String>,
    pub ttl: String,
}

/// Response from looking up the current token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLookupResponse {
    pub id: String,
    pub policies: Vec<String>,
    pub expire_time: String,
}

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/// An access-control policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<PathRule>,
}

/// A single path-based rule within a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRule {
    pub path: String,
    pub capabilities: Vec<String>,
}

// ---------------------------------------------------------------------------
// System types
// ---------------------------------------------------------------------------

/// Seal status of the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealStatus {
    pub sealed: bool,
    pub threshold: u32,
    pub num_shares: u32,
    pub progress: u32,
    pub initialized: bool,
}

/// Response from initializing a new vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitResponse {
    pub keys: Vec<String>,
    pub root_token: String,
}

/// Health-check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

// ---------------------------------------------------------------------------
// Internal request / response wrappers
// ---------------------------------------------------------------------------

/// Wrapper used when writing a secret.
#[derive(Debug, Serialize)]
pub(crate) struct WriteSecretRequest {
    pub data: HashMap<String, Value>,
}

/// Wrapper for the list-secrets response.
#[derive(Debug, Deserialize)]
pub(crate) struct ListSecretsResponse {
    pub keys: Vec<String>,
}

/// Wrapper for the list-policies response.
#[derive(Debug, Deserialize)]
pub(crate) struct ListPoliciesResponse {
    pub policies: Vec<Policy>,
}

/// Body sent when creating a token.
#[derive(Debug, Serialize)]
pub(crate) struct CreateTokenRequest {
    pub policy_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

/// Body sent when submitting an unseal key.
#[derive(Debug, Serialize)]
pub(crate) struct UnsealRequest {
    pub key: String,
}

/// Body sent when initializing the vault.
#[derive(Debug, Serialize)]
pub(crate) struct InitRequest {
    pub secret_shares: u32,
    pub secret_threshold: u32,
}

/// Wrapper for creating/updating a policy.
#[derive(Debug, Serialize)]
pub(crate) struct CreatePolicyRequest {
    pub policy: Policy,
}
