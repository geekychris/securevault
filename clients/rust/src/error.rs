use thiserror::Error;

/// Errors returned by the SecureVault client.
#[derive(Debug, Error)]
pub enum SecureVaultError {
    /// The HTTP request failed due to a network or transport error.
    #[error("request failed: {0}")]
    RequestFailed(String),

    /// The server returned 401 Unauthorized.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The server returned 403 Forbidden.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The server returned 404 Not Found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The server returned 409 Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// The server returned a 5xx status code.
    #[error("server error ({status}): {message}")]
    ServerError { status: u16, message: String },

    /// Failed to deserialize the response body.
    #[error("deserialization error: {0}")]
    DeserializationError(String),
}

pub type Result<T> = std::result::Result<T, SecureVaultError>;

impl From<reqwest::Error> for SecureVaultError {
    fn from(err: reqwest::Error) -> Self {
        SecureVaultError::RequestFailed(err.to_string())
    }
}

impl From<serde_json::Error> for SecureVaultError {
    fn from(err: serde_json::Error) -> Self {
        SecureVaultError::DeserializationError(err.to_string())
    }
}
