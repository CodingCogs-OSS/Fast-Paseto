//! PASETO error types
//!
//! This module defines all error types used throughout the fast-paseto library.

use thiserror::Error;

/// PASETO error types
#[derive(Error, Debug)]
pub enum PasetoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),

    #[error("Token authentication failed")]
    AuthenticationFailed,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Token integrity check failed")]
    IntegrityError,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Token is not yet valid")]
    TokenNotYetValid,

    #[error("Token issued-at time is in the future")]
    TokenIssuedInFuture,

    #[error("Footer mismatch")]
    FooterMismatch,

    #[error("Implicit assertion mismatch")]
    ImplicitAssertionMismatch,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid PEM format: {0}")]
    InvalidPemFormat(String),

    #[error("Invalid PASERK format: {0}")]
    InvalidPaserkFormat(String),

    #[error("Password decryption failed")]
    PasswordDecryptionFailed,

    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}
