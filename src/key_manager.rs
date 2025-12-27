//! PASERK key management for serialization, wrapping, and identification
//!
//! This module implements the PASERK (Platform-Agnostic Serialized Keys) specification
//! for key serialization, key wrapping, password-based encryption, and key identification.
//!
//! # Overview
//!
//! PASERK provides standardized formats for:
//! - **Key Serialization**: Converting keys to/from portable string formats
//! - **Key Wrapping**: Encrypting keys with other keys for secure storage
//! - **Password Protection**: Encrypting keys with passwords using Argon2id
//! - **Key Identification**: Generating deterministic IDs for keys
//! - **PEM Import**: Loading keys from standard PEM formats
//!
//! # PASERK Formats
//!
//! | Format | Description | Example |
//! |--------|-------------|---------|
//! | `k4.local.{key}` | Symmetric key | `k4.local.AAAA...` |
//! | `k4.secret.{key}` | Ed25519 secret key | `k4.secret.AAAA...` |
//! | `k4.public.{key}` | Ed25519 public key | `k4.public.AAAA...` |
//! | `k4.local-wrap.pie.{data}` | Wrapped symmetric key | `k4.local-wrap.pie.AAAA...` |
//! | `k4.secret-wrap.pie.{data}` | Wrapped secret key | `k4.secret-wrap.pie.AAAA...` |
//! | `k4.local-pw.{data}` | Password-encrypted symmetric key | `k4.local-pw.AAAA...` |
//! | `k4.secret-pw.{data}` | Password-encrypted secret key | `k4.secret-pw.AAAA...` |
//! | `k4.lid.{hash}` | Local key ID | `k4.lid.AAAA...` |
//! | `k4.sid.{hash}` | Secret key ID | `k4.sid.AAAA...` |
//! | `k4.pid.{hash}` | Public key ID | `k4.pid.AAAA...` |
//!
//! # Example
//!
//! ```rust
//! use fast_paseto::{KeyManager, KeyGenerator, PaserkId};
//!
//! // Generate and serialize a symmetric key
//! let key = KeyGenerator::generate_symmetric_key();
//! let paserk = KeyManager::to_paserk_local(&key);
//!
//! // Generate a key ID for identification
//! let key_id = PaserkId::generate_lid(&key);
//!
//! // Wrap a key with another key for secure storage
//! let wrapping_key = KeyGenerator::generate_symmetric_key();
//! let wrapped = KeyManager::local_wrap(&key, &wrapping_key).unwrap();
//! ```

use crate::error::PasetoError;
use crate::token_generator::TokenGenerator;
use crate::token_verifier::TokenVerifier;
use base64::prelude::*;
use blake2::{Blake2b512, Digest};

/// PASERK key types for deserialization
///
/// Represents the different key types that can be parsed from PASERK format strings.
#[derive(Debug, Clone, PartialEq)]
pub enum PaserkKey {
    /// Local (symmetric) key - 32 bytes
    Local([u8; 32]),
    /// Secret (Ed25519 secret) key - 64 bytes
    Secret([u8; 64]),
    /// Public (Ed25519 public) key - 32 bytes
    Public([u8; 32]),
}

/// PASERK key management for serialization and deserialization
pub struct KeyManager;

impl KeyManager {
    /// Wrap a symmetric key using a wrapping key (PASERK local-wrap)
    ///
    /// Encrypts a 32-byte symmetric key using another 32-byte wrapping key,
    /// producing a PASERK wrapped key string. Uses v4.local token encryption
    /// internally to provide authenticated encryption.
    ///
    /// Format: `k4.local-wrap.pie.{base64url_wrapped_token}`
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte symmetric key to wrap
    /// * `wrapping_key` - 32-byte wrapping key
    ///
    /// # Returns
    ///
    /// A PASERK local-wrap key string
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::CryptoError` if encryption fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let key = KeyGenerator::generate_symmetric_key();
    /// let wrapping_key = KeyGenerator::generate_symmetric_key();
    /// let wrapped = KeyManager::local_wrap(&key, &wrapping_key).unwrap();
    /// assert!(wrapped.starts_with("k4.local-wrap.pie."));
    /// ```
    pub fn local_wrap(key: &[u8; 32], wrapping_key: &[u8; 32]) -> Result<String, PasetoError> {
        use crate::token_generator::TokenGenerator;

        // Use v4.local encryption to wrap the key
        // The key bytes become the payload
        let wrapped_token = TokenGenerator::v4_local_encrypt(
            wrapping_key,
            key,
            None, // No footer
            None, // No implicit assertion
        )?;

        // Extract the payload part (everything after "v4.local.")
        // Format: v4.local.{base64url_payload}
        let parts: Vec<&str> = wrapped_token.split('.').collect();
        if parts.len() < 3 {
            return Err(PasetoError::CryptoError(
                "Invalid wrapped token format".to_string(),
            ));
        }

        // Build PASERK local-wrap format: k4.local-wrap.pie.{base64url_payload}
        Ok(format!("k4.local-wrap.pie.{}", parts[2]))
    }

    /// Unwrap a symmetric key using a wrapping key (PASERK local-wrap)
    ///
    /// Decrypts a PASERK wrapped key string using a 32-byte wrapping key,
    /// returning the original 32-byte symmetric key. Uses v4.local token
    /// decryption internally to provide authenticated decryption.
    ///
    /// Format: `k4.local-wrap.pie.{base64url_wrapped_token}`
    ///
    /// # Arguments
    ///
    /// * `wrapped_key` - PASERK local-wrap key string
    /// * `wrapping_key` - 32-byte wrapping key
    ///
    /// # Returns
    ///
    /// The unwrapped 32-byte symmetric key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPaserkFormat` if the format is invalid
    /// Returns `PasetoError::AuthenticationFailed` if decryption fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let key = KeyGenerator::generate_symmetric_key();
    /// let wrapping_key = KeyGenerator::generate_symmetric_key();
    /// let wrapped = KeyManager::local_wrap(&key, &wrapping_key).unwrap();
    /// let unwrapped = KeyManager::local_unwrap(&wrapped, &wrapping_key).unwrap();
    /// assert_eq!(key, unwrapped);
    /// ```
    pub fn local_unwrap(
        wrapped_key: &str,
        wrapping_key: &[u8; 32],
    ) -> Result<[u8; 32], PasetoError> {
        use crate::token_verifier::TokenVerifier;

        // Parse PASERK local-wrap format: k4.local-wrap.pie.{base64url_payload}
        let parts: Vec<&str> = wrapped_key.split('.').collect();

        if parts.len() != 4 {
            return Err(PasetoError::InvalidPaserkFormat(
                "PASERK local-wrap must have exactly 4 parts separated by dots".to_string(),
            ));
        }

        if parts[0] != "k4" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Unsupported PASERK version: {}",
                parts[0]
            )));
        }

        if parts[1] != "local-wrap" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Expected 'local-wrap', got '{}'",
                parts[1]
            )));
        }

        if parts[2] != "pie" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Expected 'pie', got '{}'",
                parts[2]
            )));
        }

        // Reconstruct v4.local token from the payload part
        let token = format!("v4.local.{}", parts[3]);

        // Use v4.local decryption to unwrap the key
        let verifier = TokenVerifier::new(None);
        let key_bytes = verifier.v4_local_decrypt(
            &token,
            wrapping_key,
            None, // No footer
            None, // No implicit assertion
        )?;

        // Validate key length
        if key_bytes.len() != 32 {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Unwrapped key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    /// Wrap an Ed25519 secret key using a wrapping key (PASERK secret-wrap)
    ///
    /// Encrypts a 64-byte Ed25519 secret key using a 32-byte wrapping key,
    /// producing a PASERK wrapped key string. Uses v4.local token encryption
    /// internally to provide authenticated encryption.
    ///
    /// Format: `k4.secret-wrap.pie.{base64url_wrapped_token}`
    ///
    /// # Arguments
    ///
    /// * `secret_key` - 64-byte Ed25519 secret key to wrap
    /// * `wrapping_key` - 32-byte wrapping key
    ///
    /// # Returns
    ///
    /// A PASERK secret-wrap key string
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::CryptoError` if encryption fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let keypair = KeyGenerator::generate_ed25519_keypair();
    /// let wrapping_key = KeyGenerator::generate_symmetric_key();
    /// let wrapped = KeyManager::secret_wrap(&keypair.secret_key, &wrapping_key).unwrap();
    /// assert!(wrapped.starts_with("k4.secret-wrap.pie."));
    /// ```
    pub fn secret_wrap(
        secret_key: &[u8; 64],
        wrapping_key: &[u8; 32],
    ) -> Result<String, PasetoError> {
        // Use v4.local encryption to wrap the secret key
        // The secret key bytes become the payload
        let wrapped_token = TokenGenerator::v4_local_encrypt(
            wrapping_key,
            secret_key,
            None, // No footer
            None, // No implicit assertion
        )?;

        // Extract the payload part (everything after "v4.local.")
        // Format: v4.local.{base64url_payload}
        let parts: Vec<&str> = wrapped_token.split('.').collect();
        if parts.len() < 3 {
            return Err(PasetoError::CryptoError(
                "Invalid wrapped token format".to_string(),
            ));
        }

        // Build PASERK secret-wrap format: k4.secret-wrap.pie.{base64url_payload}
        Ok(format!("k4.secret-wrap.pie.{}", parts[2]))
    }

    /// Unwrap an Ed25519 secret key using a wrapping key (PASERK secret-wrap)
    ///
    /// Decrypts a PASERK wrapped key string using a 32-byte wrapping key,
    /// returning the original 64-byte Ed25519 secret key. Uses v4.local token
    /// decryption internally to provide authenticated decryption.
    ///
    /// Format: `k4.secret-wrap.pie.{base64url_wrapped_token}`
    ///
    /// # Arguments
    ///
    /// * `wrapped_key` - PASERK secret-wrap key string
    /// * `wrapping_key` - 32-byte wrapping key
    ///
    /// # Returns
    ///
    /// The unwrapped 64-byte Ed25519 secret key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPaserkFormat` if the format is invalid
    /// Returns `PasetoError::AuthenticationFailed` if decryption fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let keypair = KeyGenerator::generate_ed25519_keypair();
    /// let wrapping_key = KeyGenerator::generate_symmetric_key();
    /// let wrapped = KeyManager::secret_wrap(&keypair.secret_key, &wrapping_key).unwrap();
    /// let unwrapped = KeyManager::secret_unwrap(&wrapped, &wrapping_key).unwrap();
    /// assert_eq!(keypair.secret_key, unwrapped);
    /// ```
    pub fn secret_unwrap(
        wrapped_key: &str,
        wrapping_key: &[u8; 32],
    ) -> Result<[u8; 64], PasetoError> {
        // Parse PASERK secret-wrap format: k4.secret-wrap.pie.{base64url_payload}
        let parts: Vec<&str> = wrapped_key.split('.').collect();

        if parts.len() != 4 {
            return Err(PasetoError::InvalidPaserkFormat(
                "PASERK secret-wrap must have exactly 4 parts separated by dots".to_string(),
            ));
        }

        if parts[0] != "k4" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Unsupported PASERK version: {}",
                parts[0]
            )));
        }

        if parts[1] != "secret-wrap" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Expected 'secret-wrap', got '{}'",
                parts[1]
            )));
        }

        if parts[2] != "pie" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Expected 'pie', got '{}'",
                parts[2]
            )));
        }

        // Reconstruct v4.local token from the payload part
        let token = format!("v4.local.{}", parts[3]);

        // Use v4.local decryption to unwrap the key
        let verifier = TokenVerifier::new(None);
        let key_bytes = verifier.v4_local_decrypt(
            &token,
            wrapping_key,
            None, // No footer
            None, // No implicit assertion
        )?;

        // Validate key length
        if key_bytes.len() != 64 {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Unwrapped secret key must be 64 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 64];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    /// Encrypt a symmetric key with a password (PASERK local-pw)
    ///
    /// Uses Argon2id for key derivation and v4.local encryption.
    /// Format: `k4.local-pw.{base64url_encrypted_data}`
    ///
    /// The encrypted data contains:
    /// - Salt (16 bytes) for Argon2id
    /// - Encrypted payload from v4.local encryption
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte symmetric key to encrypt
    /// * `password` - Password string
    ///
    /// # Returns
    ///
    /// A PASERK local-pw encrypted key string
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::CryptoError` if encryption fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let key = KeyGenerator::generate_symmetric_key();
    /// let password = "secure-password-123";
    /// let encrypted = KeyManager::local_pw_encrypt(&key, password).unwrap();
    /// assert!(encrypted.starts_with("k4.local-pw."));
    /// ```
    pub fn local_pw_encrypt(key: &[u8; 32], password: &str) -> Result<String, PasetoError> {
        use argon2::{Algorithm, Argon2, Params, Version};
        use rand::Rng;

        // Generate random salt (16 bytes)
        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);

        // Derive encryption key using Argon2id
        // PASERK recommends: m=64MB (65536 KB), t=2 iterations, p=1 parallelism
        let params = Params::new(65536, 2, 1, Some(32))
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 params error: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 error: {}", e)))?;

        // Encrypt the key using v4.local encryption
        let wrapped_token = TokenGenerator::v4_local_encrypt(
            &derived_key,
            key,
            None, // No footer
            None, // No implicit assertion
        )?;

        // Extract payload from token (after "v4.local.")
        let parts: Vec<&str> = wrapped_token.split('.').collect();
        if parts.len() < 3 {
            return Err(PasetoError::CryptoError(
                "Invalid wrapped token format".to_string(),
            ));
        }

        // Combine salt + encrypted payload
        let encrypted_payload = BASE64_URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| PasetoError::CryptoError(format!("Base64 decode error: {}", e)))?;

        let mut combined = Vec::with_capacity(16 + encrypted_payload.len());
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&encrypted_payload);

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&combined);
        Ok(format!("k4.local-pw.{}", encoded))
    }

    /// Decrypt a symmetric key with a password (PASERK local-pw)
    ///
    /// Decrypts a PASERK local-pw encrypted key string using a password,
    /// returning the original 32-byte symmetric key.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - PASERK local-pw encrypted key string
    /// * `password` - Password string
    ///
    /// # Returns
    ///
    /// The decrypted 32-byte symmetric key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPaserkFormat` if the format is invalid
    /// Returns `PasetoError::AuthenticationFailed` if decryption fails (wrong password)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let key = KeyGenerator::generate_symmetric_key();
    /// let password = "secure-password-123";
    /// let encrypted = KeyManager::local_pw_encrypt(&key, password).unwrap();
    /// let decrypted = KeyManager::local_pw_decrypt(&encrypted, password).unwrap();
    /// assert_eq!(key, decrypted);
    /// ```
    pub fn local_pw_decrypt(encrypted: &str, password: &str) -> Result<[u8; 32], PasetoError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        // Parse format: k4.local-pw.{base64url_data}
        let parts: Vec<&str> = encrypted.split('.').collect();

        if parts.len() != 3 {
            return Err(PasetoError::InvalidPaserkFormat(
                "PASERK local-pw must have exactly 3 parts".to_string(),
            ));
        }

        if parts[0] != "k4" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Unsupported PASERK version: {}",
                parts[0]
            )));
        }

        if parts[1] != "local-pw" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Expected 'local-pw', got '{}'",
                parts[1]
            )));
        }

        // Decode combined data
        let combined = BASE64_URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| PasetoError::InvalidPaserkFormat(format!("Invalid base64url: {}", e)))?;

        if combined.len() < 16 {
            return Err(PasetoError::InvalidPaserkFormat(
                "Encrypted data too short".to_string(),
            ));
        }

        // Extract salt and encrypted payload
        let salt = &combined[..16];
        let encrypted_payload = &combined[16..];

        // Derive decryption key using Argon2id
        let params = Params::new(65536, 2, 1, Some(32))
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 params error: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut derived_key)
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 error: {}", e)))?;

        // Reconstruct v4.local token and decrypt
        let token = format!(
            "v4.local.{}",
            BASE64_URL_SAFE_NO_PAD.encode(encrypted_payload)
        );

        let verifier = TokenVerifier::new(None);
        let key_bytes = verifier.v4_local_decrypt(
            &token,
            &derived_key,
            None, // No footer
            None, // No implicit assertion
        )?;

        if key_bytes.len() != 32 {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Decrypted key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    /// Encrypt an Ed25519 secret key with a password (PASERK secret-pw)
    ///
    /// Uses Argon2id for key derivation and v4.local encryption.
    /// Format: `k4.secret-pw.{base64url_encrypted_data}`
    ///
    /// The encrypted data contains:
    /// - Salt (16 bytes) for Argon2id
    /// - Encrypted payload from v4.local encryption
    ///
    /// # Arguments
    ///
    /// * `secret_key` - 64-byte Ed25519 secret key to encrypt
    /// * `password` - Password string
    ///
    /// # Returns
    ///
    /// A PASERK secret-pw encrypted key string
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::CryptoError` if encryption fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let keypair = KeyGenerator::generate_ed25519_keypair();
    /// let password = "secure-password-123";
    /// let encrypted = KeyManager::secret_pw_encrypt(&keypair.secret_key, password).unwrap();
    /// assert!(encrypted.starts_with("k4.secret-pw."));
    /// ```
    pub fn secret_pw_encrypt(secret_key: &[u8; 64], password: &str) -> Result<String, PasetoError> {
        use argon2::{Algorithm, Argon2, Params, Version};
        use rand::Rng;

        // Generate random salt (16 bytes)
        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);

        // Derive encryption key using Argon2id
        // PASERK recommends: m=64MB (65536 KB), t=2 iterations, p=1 parallelism
        let params = Params::new(65536, 2, 1, Some(32))
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 params error: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 error: {}", e)))?;

        // Encrypt the secret key using v4.local encryption
        let wrapped_token = TokenGenerator::v4_local_encrypt(
            &derived_key,
            secret_key,
            None, // No footer
            None, // No implicit assertion
        )?;

        // Extract payload from token (after "v4.local.")
        let parts: Vec<&str> = wrapped_token.split('.').collect();
        if parts.len() < 3 {
            return Err(PasetoError::CryptoError(
                "Invalid wrapped token format".to_string(),
            ));
        }

        // Combine salt + encrypted payload
        let encrypted_payload = BASE64_URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| PasetoError::CryptoError(format!("Base64 decode error: {}", e)))?;

        let mut combined = Vec::with_capacity(16 + encrypted_payload.len());
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&encrypted_payload);

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&combined);
        Ok(format!("k4.secret-pw.{}", encoded))
    }

    /// Decrypt an Ed25519 secret key with a password (PASERK secret-pw)
    ///
    /// Decrypts a PASERK secret-pw encrypted key string using a password,
    /// returning the original 64-byte Ed25519 secret key.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - PASERK secret-pw encrypted key string
    /// * `password` - Password string
    ///
    /// # Returns
    ///
    /// The decrypted 64-byte Ed25519 secret key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPaserkFormat` if the format is invalid
    /// Returns `PasetoError::AuthenticationFailed` if decryption fails (wrong password)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    /// use fast_paseto::KeyGenerator;
    ///
    /// let keypair = KeyGenerator::generate_ed25519_keypair();
    /// let password = "secure-password-123";
    /// let encrypted = KeyManager::secret_pw_encrypt(&keypair.secret_key, password).unwrap();
    /// let decrypted = KeyManager::secret_pw_decrypt(&encrypted, password).unwrap();
    /// assert_eq!(keypair.secret_key, decrypted);
    /// ```
    pub fn secret_pw_decrypt(encrypted: &str, password: &str) -> Result<[u8; 64], PasetoError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        // Parse format: k4.secret-pw.{base64url_data}
        let parts: Vec<&str> = encrypted.split('.').collect();

        if parts.len() != 3 {
            return Err(PasetoError::InvalidPaserkFormat(
                "PASERK secret-pw must have exactly 3 parts".to_string(),
            ));
        }

        if parts[0] != "k4" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Unsupported PASERK version: {}",
                parts[0]
            )));
        }

        if parts[1] != "secret-pw" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Expected 'secret-pw', got '{}'",
                parts[1]
            )));
        }

        // Decode combined data
        let combined = BASE64_URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| PasetoError::InvalidPaserkFormat(format!("Invalid base64url: {}", e)))?;

        if combined.len() < 16 {
            return Err(PasetoError::InvalidPaserkFormat(
                "Encrypted data too short".to_string(),
            ));
        }

        // Extract salt and encrypted payload
        let salt = &combined[..16];
        let encrypted_payload = &combined[16..];

        // Derive decryption key using Argon2id
        let params = Params::new(65536, 2, 1, Some(32))
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 params error: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut derived_key)
            .map_err(|e| PasetoError::CryptoError(format!("Argon2 error: {}", e)))?;

        // Reconstruct v4.local token and decrypt
        let token = format!(
            "v4.local.{}",
            BASE64_URL_SAFE_NO_PAD.encode(encrypted_payload)
        );

        let verifier = TokenVerifier::new(None);
        let key_bytes = verifier.v4_local_decrypt(
            &token,
            &derived_key,
            None, // No footer
            None, // No implicit assertion
        )?;

        if key_bytes.len() != 64 {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Decrypted secret key must be 64 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 64];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    /// Serialize a symmetric key to PASERK local format
    ///
    /// Format: `k4.local.{base64url_key}`
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte symmetric key
    ///
    /// # Returns
    ///
    /// A PASERK local key string
    pub fn to_paserk_local(key: &[u8; 32]) -> String {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(key);
        format!("k4.local.{}", encoded)
    }

    /// Serialize an Ed25519 secret key to PASERK secret format
    ///
    /// Format: `k4.secret.{base64url_key}`
    ///
    /// # Arguments
    ///
    /// * `key` - 64-byte Ed25519 secret key
    ///
    /// # Returns
    ///
    /// A PASERK secret key string
    pub fn to_paserk_secret(key: &[u8; 64]) -> String {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(key);
        format!("k4.secret.{}", encoded)
    }

    /// Serialize an Ed25519 public key to PASERK public format
    ///
    /// Format: `k4.public.{base64url_key}`
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte Ed25519 public key
    ///
    /// # Returns
    ///
    /// A PASERK public key string
    pub fn to_paserk_public(key: &[u8; 32]) -> String {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(key);
        format!("k4.public.{}", encoded)
    }

    /// Deserialize a PASERK string to key bytes
    ///
    /// Supports k4.local, k4.secret, and k4.public formats.
    ///
    /// # Arguments
    ///
    /// * `paserk` - PASERK-formatted string
    ///
    /// # Returns
    ///
    /// A `PaserkKey` enum containing the decoded key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPaserkFormat` if the format is invalid
    pub fn from_paserk(paserk: &str) -> Result<PaserkKey, PasetoError> {
        let parts: Vec<&str> = paserk.split('.').collect();

        if parts.len() != 3 {
            return Err(PasetoError::InvalidPaserkFormat(
                "PASERK must have exactly 3 parts separated by dots".to_string(),
            ));
        }

        if parts[0] != "k4" {
            return Err(PasetoError::InvalidPaserkFormat(format!(
                "Unsupported PASERK version: {}",
                parts[0]
            )));
        }

        let key_bytes = BASE64_URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
            PasetoError::InvalidPaserkFormat(format!("Invalid base64url encoding: {}", e))
        })?;

        match parts[1] {
            "local" => {
                if key_bytes.len() != 32 {
                    return Err(PasetoError::InvalidPaserkFormat(format!(
                        "Local key must be 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                Ok(PaserkKey::Local(key))
            }
            "secret" => {
                if key_bytes.len() != 64 {
                    return Err(PasetoError::InvalidPaserkFormat(format!(
                        "Secret key must be 64 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let mut key = [0u8; 64];
                key.copy_from_slice(&key_bytes);
                Ok(PaserkKey::Secret(key))
            }
            "public" => {
                if key_bytes.len() != 32 {
                    return Err(PasetoError::InvalidPaserkFormat(format!(
                        "Public key must be 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                Ok(PaserkKey::Public(key))
            }
            _ => Err(PasetoError::InvalidPaserkFormat(format!(
                "Unsupported PASERK type: {}",
                parts[1]
            ))),
        }
    }

    /// Load an Ed25519 private key from PEM format (PKCS#8)
    ///
    /// Parses a PEM-encoded Ed25519 private key in PKCS#8 format and returns
    /// the 64-byte secret key suitable for use with v4.public tokens.
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded Ed25519 private key string
    ///
    /// # Returns
    ///
    /// A 64-byte Ed25519 secret key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPemFormat` if:
    /// - The PEM format is invalid
    /// - The key is not an Ed25519 key
    /// - The key data is malformed
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    ///
    /// let pem = r#"-----BEGIN PRIVATE KEY-----
    /// MC4CAQAwBQYDK2VwBCIEIGqPaUKpqt0MJjJgXgXgXgXgXgXgXgXgXgXgXgXgXgXg
    /// -----END PRIVATE KEY-----"#;
    ///
    /// let secret_key = KeyManager::ed25519_from_pem(pem);
    /// ```
    pub fn ed25519_from_pem(pem: &str) -> Result<[u8; 64], PasetoError> {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|e| {
            PasetoError::InvalidPemFormat(format!("Failed to parse Ed25519 private key PEM: {}", e))
        })?;

        // Get the secret key bytes (32 bytes seed + 32 bytes public key = 64 bytes)
        let mut secret_key = [0u8; 64];
        secret_key[..32].copy_from_slice(signing_key.as_bytes());
        secret_key[32..].copy_from_slice(signing_key.verifying_key().as_bytes());

        Ok(secret_key)
    }

    /// Load an Ed25519 public key from PEM format (SPKI)
    ///
    /// Parses a PEM-encoded Ed25519 public key in SPKI (Subject Public Key Info)
    /// format and returns the 32-byte public key suitable for use with v4.public
    /// token verification.
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded Ed25519 public key string
    ///
    /// # Returns
    ///
    /// A 32-byte Ed25519 public key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPemFormat` if:
    /// - The PEM format is invalid
    /// - The key is not an Ed25519 key
    /// - The key data is malformed
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    ///
    /// let pem = r#"-----BEGIN PUBLIC KEY-----
    /// MCowBQYDK2VwAyEAGb9F2CMCwPz0vPz0vPz0vPz0vPz0vPz0vPz0vPz0vPw=
    /// -----END PUBLIC KEY-----"#;
    ///
    /// let public_key = KeyManager::ed25519_public_from_pem(pem);
    /// ```
    pub fn ed25519_public_from_pem(pem: &str) -> Result<[u8; 32], PasetoError> {
        use ed25519_dalek::VerifyingKey;
        use ed25519_dalek::pkcs8::DecodePublicKey;

        let verifying_key = VerifyingKey::from_public_key_pem(pem).map_err(|e| {
            PasetoError::InvalidPemFormat(format!("Failed to parse Ed25519 public key PEM: {}", e))
        })?;

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(verifying_key.as_bytes());

        Ok(public_key)
    }

    /// Load a P-384 private key from PEM format (PKCS#8)
    ///
    /// Parses a PEM-encoded P-384 private key in PKCS#8 format and returns
    /// the 48-byte secret key suitable for use with v3.public tokens.
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded P-384 private key string
    ///
    /// # Returns
    ///
    /// A 48-byte P-384 secret key
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPemFormat` if:
    /// - The PEM format is invalid
    /// - The key is not a P-384 key
    /// - The key data is malformed
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    ///
    /// let pem = r#"-----BEGIN PRIVATE KEY-----
    /// MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBD...
    /// -----END PRIVATE KEY-----"#;
    ///
    /// let secret_key = KeyManager::p384_from_pem(pem);
    /// ```
    pub fn p384_from_pem(pem: &str) -> Result<[u8; 48], PasetoError> {
        use p384::ecdsa::SigningKey;
        use p384::pkcs8::DecodePrivateKey;

        let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|e| {
            PasetoError::InvalidPemFormat(format!("Failed to parse P-384 private key PEM: {}", e))
        })?;

        // Get the secret key bytes (48 bytes for P-384)
        let mut secret_key = [0u8; 48];
        secret_key.copy_from_slice(&signing_key.to_bytes());

        Ok(secret_key)
    }

    /// Load a P-384 public key from PEM format (SPKI)
    ///
    /// Parses a PEM-encoded P-384 public key in SPKI (Subject Public Key Info)
    /// format and returns the 49-byte compressed public key suitable for use
    /// with v3.public token verification.
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded P-384 public key string
    ///
    /// # Returns
    ///
    /// A 49-byte P-384 public key (compressed point format)
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidPemFormat` if:
    /// - The PEM format is invalid
    /// - The key is not a P-384 key
    /// - The key data is malformed
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyManager;
    ///
    /// let pem = r#"-----BEGIN PUBLIC KEY-----
    /// MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE...
    /// -----END PUBLIC KEY-----"#;
    ///
    /// let public_key = KeyManager::p384_public_from_pem(pem);
    /// ```
    pub fn p384_public_from_pem(pem: &str) -> Result<[u8; 49], PasetoError> {
        use p384::ecdsa::VerifyingKey;
        use p384::pkcs8::DecodePublicKey;

        let verifying_key = VerifyingKey::from_public_key_pem(pem).map_err(|e| {
            PasetoError::InvalidPemFormat(format!("Failed to parse P-384 public key PEM: {}", e))
        })?;

        // Get the public key in compressed form (49 bytes)
        let encoded_point = verifying_key.to_encoded_point(true); // compressed
        let public_bytes = encoded_point.as_bytes();

        let mut public_key = [0u8; 49];
        public_key.copy_from_slice(public_bytes);

        Ok(public_key)
    }
}

/// PASERK ID generation for key identification
///
/// PASERK (Platform-Agnostic Serialized Keys) IDs provide a deterministic
/// way to identify keys without exposing the key material itself.
pub struct PaserkId;

impl PaserkId {
    /// Generate a local ID (lid) for symmetric keys
    ///
    /// Creates a PASERK ID for a 32-byte symmetric key used in v4.local tokens.
    /// The ID is deterministic - the same key always produces the same ID.
    ///
    /// Format: `k4.lid.{base64url_hash}`
    /// where hash is BLAKE2b-256 of the key bytes
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte symmetric key
    ///
    /// # Returns
    ///
    /// A PASERK local ID string in the format `k4.lid.{base64url_hash}`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::PaserkId;
    ///
    /// let key = [0u8; 32];
    /// let lid = PaserkId::generate_lid(&key);
    /// assert!(lid.starts_with("k4.lid."));
    /// ```
    pub fn generate_lid(key: &[u8; 32]) -> String {
        let hash = Self::blake2b_256(key);
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash);
        format!("k4.lid.{}", encoded)
    }

    /// Generate a secret ID (sid) for Ed25519 secret keys
    ///
    /// Creates a PASERK ID for a 64-byte Ed25519 secret key used in v4.public tokens.
    /// The ID is deterministic - the same key always produces the same ID.
    ///
    /// Format: `k4.sid.{base64url_hash}`
    /// where hash is BLAKE2b-256 of the key bytes
    ///
    /// # Arguments
    ///
    /// * `key` - 64-byte Ed25519 secret key
    ///
    /// # Returns
    ///
    /// A PASERK secret ID string in the format `k4.sid.{base64url_hash}`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::PaserkId;
    ///
    /// let key = [0u8; 64];
    /// let sid = PaserkId::generate_sid(&key);
    /// assert!(sid.starts_with("k4.sid."));
    /// ```
    pub fn generate_sid(key: &[u8; 64]) -> String {
        let hash = Self::blake2b_256(key);
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash);
        format!("k4.sid.{}", encoded)
    }

    /// Generate a public ID (pid) for Ed25519 public keys
    ///
    /// Creates a PASERK ID for a 32-byte Ed25519 public key used in v4.public tokens.
    /// The ID is deterministic - the same key always produces the same ID.
    ///
    /// Format: `k4.pid.{base64url_hash}`
    /// where hash is BLAKE2b-256 of the key bytes
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte Ed25519 public key
    ///
    /// # Returns
    ///
    /// A PASERK public ID string in the format `k4.pid.{base64url_hash}`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::PaserkId;
    ///
    /// let key = [0u8; 32];
    /// let pid = PaserkId::generate_pid(&key);
    /// assert!(pid.starts_with("k4.pid."));
    /// ```
    pub fn generate_pid(key: &[u8; 32]) -> String {
        let hash = Self::blake2b_256(key);
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash);
        format!("k4.pid.{}", encoded)
    }

    /// Compute BLAKE2b-256 hash of input data
    ///
    /// Internal helper function to compute a 32-byte BLAKE2b hash.
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// 32-byte BLAKE2b-256 hash
    fn blake2b_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        let result = hasher.finalize();

        // Take first 32 bytes for BLAKE2b-256
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result[..32]);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_generator::KeyGenerator;
    use proptest::prelude::*;

    // PASERK Serialization Tests
    #[test]
    fn test_to_paserk_local() {
        let key = [0u8; 32];
        let paserk = KeyManager::to_paserk_local(&key);
        assert!(paserk.starts_with("k4.local."));
        assert_eq!(paserk.split('.').count(), 3);
    }

    #[test]
    fn test_to_paserk_secret() {
        let key = [0u8; 64];
        let paserk = KeyManager::to_paserk_secret(&key);
        assert!(paserk.starts_with("k4.secret."));
        assert_eq!(paserk.split('.').count(), 3);
    }

    #[test]
    fn test_to_paserk_public() {
        let key = [0u8; 32];
        let paserk = KeyManager::to_paserk_public(&key);
        assert!(paserk.starts_with("k4.public."));
        assert_eq!(paserk.split('.').count(), 3);
    }

    #[test]
    fn test_from_paserk_local_roundtrip() {
        let key = KeyGenerator::generate_symmetric_key();
        let paserk = KeyManager::to_paserk_local(&key);
        let parsed = KeyManager::from_paserk(&paserk).unwrap();

        match parsed {
            PaserkKey::Local(k) => assert_eq!(k, key),
            _ => panic!("Expected Local key"),
        }
    }

    #[test]
    fn test_from_paserk_secret_roundtrip() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let paserk = KeyManager::to_paserk_secret(&keypair.secret_key);
        let parsed = KeyManager::from_paserk(&paserk).unwrap();

        match parsed {
            PaserkKey::Secret(k) => assert_eq!(k, keypair.secret_key),
            _ => panic!("Expected Secret key"),
        }
    }

    #[test]
    fn test_from_paserk_public_roundtrip() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let paserk = KeyManager::to_paserk_public(&keypair.public_key);
        let parsed = KeyManager::from_paserk(&paserk).unwrap();

        match parsed {
            PaserkKey::Public(k) => assert_eq!(k, keypair.public_key),
            _ => panic!("Expected Public key"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_format_too_few_parts() {
        let result = KeyManager::from_paserk("k4.local");
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("exactly 3 parts"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_format_too_many_parts() {
        let result = KeyManager::from_paserk("k4.local.data.extra");
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("exactly 3 parts"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_version() {
        let result =
            KeyManager::from_paserk("k3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("Unsupported PASERK version"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_type() {
        let result =
            KeyManager::from_paserk("k4.invalid.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("Unsupported PASERK type"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_base64() {
        let result = KeyManager::from_paserk("k4.local.invalid@base64!");
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("Invalid base64url encoding"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_local_key_length() {
        // Create a base64url-encoded 16-byte key (wrong length for local)
        let short_key = BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 16]);
        let result = KeyManager::from_paserk(&format!("k4.local.{}", short_key));
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("Local key must be 32 bytes"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_secret_key_length() {
        // Create a base64url-encoded 32-byte key (wrong length for secret)
        let short_key = BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 32]);
        let result = KeyManager::from_paserk(&format!("k4.secret.{}", short_key));
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("Secret key must be 64 bytes"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_from_paserk_invalid_public_key_length() {
        // Create a base64url-encoded 16-byte key (wrong length for public)
        let short_key = BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 16]);
        let result = KeyManager::from_paserk(&format!("k4.public.{}", short_key));
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPaserkFormat(msg)) => {
                assert!(msg.contains("Public key must be 32 bytes"));
            }
            _ => panic!("Expected InvalidPaserkFormat error"),
        }
    }

    #[test]
    fn test_paserk_no_padding() {
        // Ensure base64url encoding doesn't include padding
        let key = [0u8; 32];
        let paserk = KeyManager::to_paserk_local(&key);
        assert!(!paserk.contains('='), "PASERK should not contain padding");
    }

    #[test]
    fn test_paserk_uses_url_safe_alphabet() {
        // Generate a key that would produce + or / in standard base64
        let mut key = [0u8; 32];
        key[0] = 0xFE; // This byte produces + or / in standard base64
        key[1] = 0xFF;

        let paserk = KeyManager::to_paserk_local(&key);
        assert!(!paserk.contains('+'), "PASERK should use URL-safe alphabet");
        assert!(!paserk.contains('/'), "PASERK should use URL-safe alphabet");
    }

    #[test]
    fn test_paserk_key_equality() {
        let key = KeyGenerator::generate_symmetric_key();
        let paserk1 = KeyManager::to_paserk_local(&key);
        let paserk2 = KeyManager::to_paserk_local(&key);
        assert_eq!(paserk1, paserk2, "Same key should produce same PASERK");
    }

    #[test]
    fn test_paserk_different_keys_different_paserks() {
        let key1 = KeyGenerator::generate_symmetric_key();
        let key2 = KeyGenerator::generate_symmetric_key();
        let paserk1 = KeyManager::to_paserk_local(&key1);
        let paserk2 = KeyManager::to_paserk_local(&key2);
        assert_ne!(
            paserk1, paserk2,
            "Different keys should produce different PASERKs"
        );
    }

    // PASERK ID Tests

    #[test]
    fn test_generate_lid_format() {
        let key = [0u8; 32];
        let lid = PaserkId::generate_lid(&key);

        // Check format
        assert!(lid.starts_with("k4.lid."));

        // Check that the hash part is valid base64url
        let parts: Vec<&str> = lid.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "k4");
        assert_eq!(parts[1], "lid");

        // Verify base64url decoding works
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), 32); // BLAKE2b-256 produces 32 bytes
    }

    #[test]
    fn test_generate_sid_format() {
        let key = [0u8; 64];
        let sid = PaserkId::generate_sid(&key);

        // Check format
        assert!(sid.starts_with("k4.sid."));

        // Check that the hash part is valid base64url
        let parts: Vec<&str> = sid.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "k4");
        assert_eq!(parts[1], "sid");

        // Verify base64url decoding works
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), 32); // BLAKE2b-256 produces 32 bytes
    }

    #[test]
    fn test_generate_pid_format() {
        let key = [0u8; 32];
        let pid = PaserkId::generate_pid(&key);

        // Check format
        assert!(pid.starts_with("k4.pid."));

        // Check that the hash part is valid base64url
        let parts: Vec<&str> = pid.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "k4");
        assert_eq!(parts[1], "pid");

        // Verify base64url decoding works
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), 32); // BLAKE2b-256 produces 32 bytes
    }

    #[test]
    fn test_lid_determinism() {
        let key = KeyGenerator::generate_symmetric_key();
        let lid1 = PaserkId::generate_lid(&key);
        let lid2 = PaserkId::generate_lid(&key);

        // Same key should produce same ID
        assert_eq!(lid1, lid2);
    }

    #[test]
    fn test_sid_determinism() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let sid1 = PaserkId::generate_sid(&keypair.secret_key);
        let sid2 = PaserkId::generate_sid(&keypair.secret_key);

        // Same key should produce same ID
        assert_eq!(sid1, sid2);
    }

    #[test]
    fn test_pid_determinism() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let pid1 = PaserkId::generate_pid(&keypair.public_key);
        let pid2 = PaserkId::generate_pid(&keypair.public_key);

        // Same key should produce same ID
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn test_different_keys_produce_different_lids() {
        let key1 = KeyGenerator::generate_symmetric_key();
        let key2 = KeyGenerator::generate_symmetric_key();

        let lid1 = PaserkId::generate_lid(&key1);
        let lid2 = PaserkId::generate_lid(&key2);

        // Different keys should produce different IDs
        assert_ne!(lid1, lid2);
    }

    #[test]
    fn test_different_keys_produce_different_sids() {
        let keypair1 = KeyGenerator::generate_ed25519_keypair();
        let keypair2 = KeyGenerator::generate_ed25519_keypair();

        let sid1 = PaserkId::generate_sid(&keypair1.secret_key);
        let sid2 = PaserkId::generate_sid(&keypair2.secret_key);

        // Different keys should produce different IDs
        assert_ne!(sid1, sid2);
    }

    #[test]
    fn test_different_keys_produce_different_pids() {
        let keypair1 = KeyGenerator::generate_ed25519_keypair();
        let keypair2 = KeyGenerator::generate_ed25519_keypair();

        let pid1 = PaserkId::generate_pid(&keypair1.public_key);
        let pid2 = PaserkId::generate_pid(&keypair2.public_key);

        // Different keys should produce different IDs
        assert_ne!(pid1, pid2);
    }

    #[test]
    fn test_lid_no_padding() {
        let key = [0u8; 32];
        let lid = PaserkId::generate_lid(&key);

        // Base64url without padding should not contain '='
        assert!(!lid.contains('='));
    }

    #[test]
    fn test_sid_no_padding() {
        let key = [0u8; 64];
        let sid = PaserkId::generate_sid(&key);

        // Base64url without padding should not contain '='
        assert!(!sid.contains('='));
    }

    #[test]
    fn test_pid_no_padding() {
        let key = [0u8; 32];
        let pid = PaserkId::generate_pid(&key);

        // Base64url without padding should not contain '='
        assert!(!pid.contains('='));
    }

    #[test]
    fn test_blake2b_256_output_length() {
        let data = b"test data";
        let hash = PaserkId::blake2b_256(data);

        // BLAKE2b-256 should produce exactly 32 bytes
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2b_256_determinism() {
        let data = b"test data";
        let hash1 = PaserkId::blake2b_256(data);
        let hash2 = PaserkId::blake2b_256(data);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake2b_256_different_inputs() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        let hash1 = PaserkId::blake2b_256(data1);
        let hash2 = PaserkId::blake2b_256(data2);

        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    // PASERK Key Wrapping Tests

    #[test]
    fn test_local_wrap_format() {
        let key = KeyGenerator::generate_symmetric_key();
        let wrapping_key = KeyGenerator::generate_symmetric_key();
        let wrapped = KeyManager::local_wrap(&key, &wrapping_key).unwrap();

        // Check format
        assert!(wrapped.starts_with("k4.local-wrap.pie."));

        // Should have exactly 4 parts
        let parts: Vec<&str> = wrapped.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "k4");
        assert_eq!(parts[1], "local-wrap");
        assert_eq!(parts[2], "pie");
    }

    #[test]
    fn test_local_wrap_unwrap_roundtrip() {
        let key = KeyGenerator::generate_symmetric_key();
        let wrapping_key = KeyGenerator::generate_symmetric_key();

        // Wrap and unwrap
        let wrapped = KeyManager::local_wrap(&key, &wrapping_key).unwrap();
        let unwrapped = KeyManager::local_unwrap(&wrapped, &wrapping_key).unwrap();

        // Should get back the original key
        assert_eq!(key, unwrapped);
    }

    #[test]
    fn test_local_unwrap_wrong_key() {
        let key = KeyGenerator::generate_symmetric_key();
        let wrapping_key1 = KeyGenerator::generate_symmetric_key();
        let wrapping_key2 = KeyGenerator::generate_symmetric_key();

        // Wrap with key1
        let wrapped = KeyManager::local_wrap(&key, &wrapping_key1).unwrap();

        // Try to unwrap with key2 - should fail
        let result = KeyManager::local_unwrap(&wrapped, &wrapping_key2);
        assert!(result.is_err());
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_local_unwrap_invalid_format() {
        let wrapping_key = KeyGenerator::generate_symmetric_key();

        // Test various invalid formats
        let invalid_formats = vec![
            "k4.local.test",              // Wrong type
            "k4.local-wrap.test",         // Missing part
            "k3.local-wrap.pie.test",     // Wrong version
            "k4.secret-wrap.pie.test",    // Wrong type
            "k4.local-wrap.invalid.test", // Wrong algorithm
        ];

        for invalid in invalid_formats {
            let result = KeyManager::local_unwrap(invalid, &wrapping_key);
            assert!(result.is_err(), "Should fail for: {}", invalid);
        }
    }

    #[test]
    fn test_local_wrap_different_keys_different_output() {
        let key = KeyGenerator::generate_symmetric_key();
        let wrapping_key1 = KeyGenerator::generate_symmetric_key();
        let wrapping_key2 = KeyGenerator::generate_symmetric_key();

        // Wrap with different wrapping keys
        let wrapped1 = KeyManager::local_wrap(&key, &wrapping_key1).unwrap();
        let wrapped2 = KeyManager::local_wrap(&key, &wrapping_key2).unwrap();

        // Should produce different wrapped keys
        assert_ne!(wrapped1, wrapped2);
    }

    #[test]
    fn test_local_wrap_randomness() {
        let key = KeyGenerator::generate_symmetric_key();
        let wrapping_key = KeyGenerator::generate_symmetric_key();

        // Wrap the same key twice
        let wrapped1 = KeyManager::local_wrap(&key, &wrapping_key).unwrap();
        let wrapped2 = KeyManager::local_wrap(&key, &wrapping_key).unwrap();

        // Should produce different wrapped keys due to random nonce
        assert_ne!(wrapped1, wrapped2);

        // But both should unwrap to the same key
        let unwrapped1 = KeyManager::local_unwrap(&wrapped1, &wrapping_key).unwrap();
        let unwrapped2 = KeyManager::local_unwrap(&wrapped2, &wrapping_key).unwrap();
        assert_eq!(unwrapped1, unwrapped2);
        assert_eq!(unwrapped1, key);
    }

    // Property-based tests
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property: PASERK Local Round-Trip
        /// For any 32-byte key, serializing to PASERK local format and deserializing
        /// SHALL return the original key bytes.
        /// **Validates: Requirements 10.1, 10.4**
        #[test]
        fn prop_paserk_local_roundtrip(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            // Feature: paseto-implementation, Property: PASERK Local Round-Trip
            let key: [u8; 32] = key_bytes.try_into().unwrap();
            let paserk = KeyManager::to_paserk_local(&key);
            let parsed = KeyManager::from_paserk(&paserk)
                .expect("Valid PASERK should parse successfully");

            match parsed {
                PaserkKey::Local(k) => prop_assert_eq!(k, key),
                _ => return Err(proptest::test_runner::TestCaseError::fail("Expected Local key")),
            }
        }

        /// Property: PASERK Secret Round-Trip
        /// For any 64-byte key, serializing to PASERK secret format and deserializing
        /// SHALL return the original key bytes.
        /// **Validates: Requirements 10.2, 10.4**
        #[test]
        fn prop_paserk_secret_roundtrip(key_bytes in prop::collection::vec(any::<u8>(), 64..=64)) {
            // Feature: paseto-implementation, Property: PASERK Secret Round-Trip
            let key: [u8; 64] = key_bytes.try_into().unwrap();
            let paserk = KeyManager::to_paserk_secret(&key);
            let parsed = KeyManager::from_paserk(&paserk)
                .expect("Valid PASERK should parse successfully");

            match parsed {
                PaserkKey::Secret(k) => prop_assert_eq!(k, key),
                _ => return Err(proptest::test_runner::TestCaseError::fail("Expected Secret key")),
            }
        }

        /// Property: PASERK Public Round-Trip
        /// For any 32-byte key, serializing to PASERK public format and deserializing
        /// SHALL return the original key bytes.
        /// **Validates: Requirements 10.3, 10.4**
        #[test]
        fn prop_paserk_public_roundtrip(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            // Feature: paseto-implementation, Property: PASERK Public Round-Trip
            let key: [u8; 32] = key_bytes.try_into().unwrap();
            let paserk = KeyManager::to_paserk_public(&key);
            let parsed = KeyManager::from_paserk(&paserk)
                .expect("Valid PASERK should parse successfully");

            match parsed {
                PaserkKey::Public(k) => prop_assert_eq!(k, key),
                _ => return Err(proptest::test_runner::TestCaseError::fail("Expected Public key")),
            }
        }

        /// Property: PASERK Format Validation
        /// All generated PASERK strings SHALL start with "k4." followed by the key type
        /// and SHALL contain exactly 3 dot-separated parts.
        #[test]
        fn prop_paserk_format_validation(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            let key: [u8; 32] = key_bytes.try_into().unwrap();

            let paserk_local = KeyManager::to_paserk_local(&key);
            prop_assert!(paserk_local.starts_with("k4.local."));
            prop_assert_eq!(paserk_local.split('.').count(), 3);

            let paserk_public = KeyManager::to_paserk_public(&key);
            prop_assert!(paserk_public.starts_with("k4.public."));
            prop_assert_eq!(paserk_public.split('.').count(), 3);
        }

        /// Property: PASERK No Padding
        /// All generated PASERK strings SHALL NOT contain base64 padding characters ('=').
        #[test]
        fn prop_paserk_no_padding(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            let key: [u8; 32] = key_bytes.try_into().unwrap();

            let paserk_local = KeyManager::to_paserk_local(&key);
            prop_assert!(!paserk_local.contains('='));

            let paserk_public = KeyManager::to_paserk_public(&key);
            prop_assert!(!paserk_public.contains('='));
        }

        /// Property 18: PASERK ID Determinism
        /// For any key, generating a PASERK ID multiple times SHALL always produce the same ID string.
        /// **Validates: Requirements 10.5**
        #[test]
        fn prop_paserk_id_determinism_lid(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            // Feature: paseto-implementation, Property 18: PASERK ID Determinism (lid)
            let key: [u8; 32] = key_bytes.try_into().unwrap();
            let lid1 = PaserkId::generate_lid(&key);
            let lid2 = PaserkId::generate_lid(&key);
            prop_assert_eq!(lid1, lid2, "Same key must produce same local ID");
        }

        /// Property 18: PASERK ID Determinism
        /// For any key, generating a PASERK ID multiple times SHALL always produce the same ID string.
        /// **Validates: Requirements 10.5**
        #[test]
        fn prop_paserk_id_determinism_sid(key_bytes in prop::collection::vec(any::<u8>(), 64..=64)) {
            // Feature: paseto-implementation, Property 18: PASERK ID Determinism (sid)
            let key: [u8; 64] = key_bytes.try_into().unwrap();
            let sid1 = PaserkId::generate_sid(&key);
            let sid2 = PaserkId::generate_sid(&key);
            prop_assert_eq!(sid1, sid2, "Same key must produce same secret ID");
        }

        /// Property 18: PASERK ID Determinism
        /// For any key, generating a PASERK ID multiple times SHALL always produce the same ID string.
        /// **Validates: Requirements 10.5**
        #[test]
        fn prop_paserk_id_determinism_pid(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            // Feature: paseto-implementation, Property 18: PASERK ID Determinism (pid)
            let key: [u8; 32] = key_bytes.try_into().unwrap();
            let pid1 = PaserkId::generate_pid(&key);
            let pid2 = PaserkId::generate_pid(&key);
            prop_assert_eq!(pid1, pid2, "Same key must produce same public ID");
        }

        /// Property: PASERK ID Format Validity
        /// All generated PASERK IDs must follow the correct format with valid base64url encoding
        #[test]
        fn prop_paserk_id_format_lid(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            let key: [u8; 32] = key_bytes.try_into().unwrap();
            let lid = PaserkId::generate_lid(&key);

            // Check format
            prop_assert!(lid.starts_with("k4.lid."), "LID must start with k4.lid.");

            // Extract and validate base64url part
            let parts: Vec<&str> = lid.split('.').collect();
            prop_assert_eq!(parts.len(), 3, "LID must have exactly 3 parts");

            // Verify base64url decoding works
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(parts[2]);
            prop_assert!(decoded.is_ok(), "LID hash must be valid base64url");
            prop_assert_eq!(decoded.unwrap().len(), 32, "LID hash must be 32 bytes");

            // No padding characters
            prop_assert!(!lid.contains('='), "LID must not contain padding");
        }

        /// Property: PASERK ID Format Validity
        /// All generated PASERK IDs must follow the correct format with valid base64url encoding
        #[test]
        fn prop_paserk_id_format_sid(key_bytes in prop::collection::vec(any::<u8>(), 64..=64)) {
            let key: [u8; 64] = key_bytes.try_into().unwrap();
            let sid = PaserkId::generate_sid(&key);

            // Check format
            prop_assert!(sid.starts_with("k4.sid."), "SID must start with k4.sid.");

            // Extract and validate base64url part
            let parts: Vec<&str> = sid.split('.').collect();
            prop_assert_eq!(parts.len(), 3, "SID must have exactly 3 parts");

            // Verify base64url decoding works
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(parts[2]);
            prop_assert!(decoded.is_ok(), "SID hash must be valid base64url");
            prop_assert_eq!(decoded.unwrap().len(), 32, "SID hash must be 32 bytes");

            // No padding characters
            prop_assert!(!sid.contains('='), "SID must not contain padding");
        }

        /// Property: PASERK ID Format Validity
        /// All generated PASERK IDs must follow the correct format with valid base64url encoding
        #[test]
        fn prop_paserk_id_format_pid(key_bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            let key: [u8; 32] = key_bytes.try_into().unwrap();
            let pid = PaserkId::generate_pid(&key);

            // Check format
            prop_assert!(pid.starts_with("k4.pid."), "PID must start with k4.pid.");

            // Extract and validate base64url part
            let parts: Vec<&str> = pid.split('.').collect();
            prop_assert_eq!(parts.len(), 3, "PID must have exactly 3 parts");

            // Verify base64url decoding works
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(parts[2]);
            prop_assert!(decoded.is_ok(), "PID hash must be valid base64url");
            prop_assert_eq!(decoded.unwrap().len(), 32, "PID hash must be 32 bytes");

            // No padding characters
            prop_assert!(!pid.contains('='), "PID must not contain padding");
        }
    }

    // Password-based encryption tests

    #[test]
    fn test_local_pw_encrypt_format() {
        let key = KeyGenerator::generate_symmetric_key();
        let password = "test-password-123";
        let encrypted = KeyManager::local_pw_encrypt(&key, password).unwrap();

        assert!(encrypted.starts_with("k4.local-pw."));
        assert_eq!(encrypted.split('.').count(), 3);
    }

    #[test]
    fn test_local_pw_roundtrip() {
        let key = KeyGenerator::generate_symmetric_key();
        let password = "secure-password-456";

        let encrypted = KeyManager::local_pw_encrypt(&key, password).unwrap();
        let decrypted = KeyManager::local_pw_decrypt(&encrypted, password).unwrap();

        assert_eq!(key, decrypted);
    }

    #[test]
    fn test_local_pw_wrong_password() {
        let key = KeyGenerator::generate_symmetric_key();
        let password = "correct-password";
        let wrong_password = "wrong-password";

        let encrypted = KeyManager::local_pw_encrypt(&key, password).unwrap();
        let result = KeyManager::local_pw_decrypt(&encrypted, wrong_password);

        assert!(result.is_err());
    }

    #[test]
    fn test_local_pw_invalid_format() {
        let password = "test";

        // Wrong version
        let result = KeyManager::local_pw_decrypt("k3.local-pw.test", password);
        assert!(result.is_err());

        // Wrong type
        let result = KeyManager::local_pw_decrypt("k4.secret-pw.test", password);
        assert!(result.is_err());

        // Too few parts
        let result = KeyManager::local_pw_decrypt("k4.local-pw", password);
        assert!(result.is_err());
    }

    #[test]
    fn test_local_pw_different_encryptions() {
        let key = KeyGenerator::generate_symmetric_key();
        let password = "same-password";

        // Same key encrypted twice should produce different ciphertexts (due to random salt)
        let encrypted1 = KeyManager::local_pw_encrypt(&key, password).unwrap();
        let encrypted2 = KeyManager::local_pw_encrypt(&key, password).unwrap();

        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same key
        let decrypted1 = KeyManager::local_pw_decrypt(&encrypted1, password).unwrap();
        let decrypted2 = KeyManager::local_pw_decrypt(&encrypted2, password).unwrap();

        assert_eq!(decrypted1, decrypted2);
        assert_eq!(decrypted1, key);
    }

    // Secret key password-based encryption tests

    #[test]
    fn test_secret_pw_encrypt_format() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let password = "test-password-123";
        let encrypted = KeyManager::secret_pw_encrypt(&keypair.secret_key, password).unwrap();

        assert!(encrypted.starts_with("k4.secret-pw."));
        assert_eq!(encrypted.split('.').count(), 3);
    }

    #[test]
    fn test_secret_pw_roundtrip() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let password = "secure-password-456";

        let encrypted = KeyManager::secret_pw_encrypt(&keypair.secret_key, password).unwrap();
        let decrypted = KeyManager::secret_pw_decrypt(&encrypted, password).unwrap();

        assert_eq!(keypair.secret_key, decrypted);
    }

    #[test]
    fn test_secret_pw_wrong_password() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let password = "correct-password";
        let wrong_password = "wrong-password";

        let encrypted = KeyManager::secret_pw_encrypt(&keypair.secret_key, password).unwrap();
        let result = KeyManager::secret_pw_decrypt(&encrypted, wrong_password);

        assert!(result.is_err());
    }

    #[test]
    fn test_secret_pw_invalid_format() {
        let password = "test";

        // Wrong version
        let result = KeyManager::secret_pw_decrypt("k3.secret-pw.test", password);
        assert!(result.is_err());

        // Wrong type
        let result = KeyManager::secret_pw_decrypt("k4.local-pw.test", password);
        assert!(result.is_err());

        // Too few parts
        let result = KeyManager::secret_pw_decrypt("k4.secret-pw", password);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_pw_different_encryptions() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let password = "same-password";

        // Same key encrypted twice should produce different ciphertexts (due to random salt)
        let encrypted1 = KeyManager::secret_pw_encrypt(&keypair.secret_key, password).unwrap();
        let encrypted2 = KeyManager::secret_pw_encrypt(&keypair.secret_key, password).unwrap();

        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same key
        let decrypted1 = KeyManager::secret_pw_decrypt(&encrypted1, password).unwrap();
        let decrypted2 = KeyManager::secret_pw_decrypt(&encrypted2, password).unwrap();

        assert_eq!(decrypted1, decrypted2);
        assert_eq!(decrypted1, keypair.secret_key);
    }

    // P-384 PEM tests

    #[test]
    fn test_p384_pem_roundtrip() {
        use p384::ecdsa::SigningKey;
        use p384::pkcs8::EncodePrivateKey;

        // Generate a P-384 key pair
        let keypair = KeyGenerator::generate_p384_keypair();

        // Create a signing key from the secret bytes
        let signing_key =
            SigningKey::from_bytes((&keypair.secret_key).into()).expect("Valid secret key");

        // Export to PEM
        let pem = signing_key
            .to_pkcs8_pem(p384::pkcs8::LineEnding::LF)
            .expect("PEM encoding should succeed");

        // Load back from PEM
        let loaded_secret =
            KeyManager::p384_from_pem(pem.as_str()).expect("PEM loading should succeed");

        assert_eq!(keypair.secret_key, loaded_secret);
    }

    #[test]
    fn test_p384_public_pem_roundtrip() {
        use p384::ecdsa::SigningKey;
        use p384::pkcs8::EncodePublicKey;

        // Generate a P-384 key pair
        let keypair = KeyGenerator::generate_p384_keypair();

        // Create a signing key from the secret bytes
        let signing_key =
            SigningKey::from_bytes((&keypair.secret_key).into()).expect("Valid secret key");
        let verifying_key = signing_key.verifying_key();

        // Export public key to PEM
        let pem = verifying_key
            .to_public_key_pem(p384::pkcs8::LineEnding::LF)
            .expect("PEM encoding should succeed");

        // Load back from PEM
        let loaded_public =
            KeyManager::p384_public_from_pem(&pem).expect("PEM loading should succeed");

        assert_eq!(keypair.public_key, loaded_public);
    }

    #[test]
    fn test_p384_from_pem_invalid() {
        let invalid_pem = "not a valid PEM";
        let result = KeyManager::p384_from_pem(invalid_pem);
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPemFormat(_)) => {}
            _ => panic!("Expected InvalidPemFormat error"),
        }
    }

    #[test]
    fn test_p384_public_from_pem_invalid() {
        let invalid_pem = "not a valid PEM";
        let result = KeyManager::p384_public_from_pem(invalid_pem);
        assert!(result.is_err());
        match result {
            Err(PasetoError::InvalidPemFormat(_)) => {}
            _ => panic!("Expected InvalidPemFormat error"),
        }
    }
}
