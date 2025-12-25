//! Token payload data model
//!
//! This module defines the TokenPayload struct with standard PASETO claims.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Decoded token payload with standard claims
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenPayload {
    /// Issuer claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Expiration time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    /// Not before time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,

    /// Issued at time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    /// Token ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl TokenPayload {
    /// Create a new empty payload
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the issuer claim
    pub fn with_issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the subject claim
    pub fn with_subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Set the audience claim
    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// Set the expiration claim
    pub fn with_expiration(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Set the not-before claim
    pub fn with_not_before(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    /// Set the issued-at claim
    pub fn with_issued_at(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// Set the token ID claim
    pub fn with_token_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Add a custom claim
    pub fn with_claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.custom.insert(key.into(), value);
        self
    }

    /// Get a custom claim by key
    pub fn get_claim(&self, key: &str) -> Option<&serde_json::Value> {
        self.custom.get(key)
    }
}
