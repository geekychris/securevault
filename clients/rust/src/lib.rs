//! # securevault-client
//!
//! A blocking Rust client library for the SecureVault REST API.
//!
//! ## Quick start
//!
//! ```no_run
//! use std::collections::HashMap;
//! use serde_json::json;
//! use securevault_client::SecureVaultClient;
//!
//! let client = SecureVaultClient::new("http://127.0.0.1:8200", "my-token");
//!
//! // Write a secret
//! let mut data = HashMap::new();
//! data.insert("password".into(), json!("s3cret"));
//! client.write_secret("app/db", data).unwrap();
//!
//! // Read it back
//! let secret = client.read_secret("app/db").unwrap();
//! println!("{:?}", secret.data);
//! ```

pub mod client;
pub mod error;
pub mod models;

pub use client::SecureVaultClient;
pub use error::{Result, SecureVaultError};
pub use models::*;
