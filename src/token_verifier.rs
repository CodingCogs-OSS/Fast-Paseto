//! Token verification and decryption
//!
//! This module implements token verification (decryption/signature verification) for PASETO tokens.

use crate::error::PasetoError;
use crate::pae::Pae;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use blake2::Blake2bMac512;
use blake2::digest::{KeyInit, Mac};
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use subtle::ConstantTimeEq;

// v3.public imports
use p384::ecdsa::{
    Signature as P384Signature, VerifyingKey as P384VerifyingKey, signature::Verifier,
};
use p384::elliptic_curve::sec1::FromEncodedPoint;
use p384::{EncodedPoint, PublicKey as P384PublicKey};

// v3.local imports
use aes::Aes256;
use ctr::Ctr128BE;
use hkdf::Hkdf;
use hmac::Hmac;
use sha2::Sha384;

// v2.local imports
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, Payload},
};

/// Token verification and decryption
#[derive(Debug)]
pub struct TokenVerifier {
    /// Seconds of tolerance for time-based claims
    #[allow(dead_code)]
    leeway: u64,
}

impl TokenVerifier {
    /// Create a new verifier with optional leeway
    ///
    /// # Arguments
    /// * `leeway` - Optional seconds of tolerance for time-based claims (default: 0)
    pub fn new(leeway: Option<u64>) -> Self {
        Self {
            leeway: leeway.unwrap_or(0),
        }
    }

    /// Verify a v2.public token (legacy asymmetric verification)
    ///
    /// Uses Ed25519 signatures for token verification.
    /// This is the legacy version - prefer v4.public for new implementations.
    ///
    /// # Arguments
    /// * `token` - Token string to verify
    /// * `public_key` - 32-byte Ed25519 public key
    /// * `footer` - Optional expected footer data
    ///
    /// # Returns
    /// * `Result<Vec<u8>, PasetoError>` - Verified payload bytes or error
    ///
    /// # Errors
    /// - `InvalidKeyLength` if public key is not 32 bytes
    /// - `InvalidKeyFormat` if public key is not a valid Ed25519 key
    /// - `InvalidTokenFormat` if token format is invalid
    /// - `FooterMismatch` if provided footer doesn't match token footer
    /// - `SignatureVerificationFailed` if signature verification fails
    ///
    /// # Note
    /// v2.public does NOT support implicit assertions (unlike v4.public).
    /// The PAE format is: PAE("v2.public.", payload, footer)
    pub fn v2_public_verify(
        &self,
        token: &str,
        public_key: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<Vec<u8>, PasetoError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Validate key length
        if public_key.len() != 32 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 32,
                actual: public_key.len(),
            });
        }

        // Convert to Ed25519 verifying key
        let key_bytes: [u8; 32] = public_key.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            PasetoError::InvalidKeyFormat(format!("Invalid Ed25519 public key: {}", e))
        })?;

        // Parse token format: v2.public.payload[.footer]
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(PasetoError::InvalidTokenFormat(
                "Token must have 3 or 4 parts separated by '.'".to_string(),
            ));
        }

        // Validate version and purpose
        if parts[0] != "v2" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected version 'v2', got '{}'",
                parts[0]
            )));
        }
        if parts[1] != "public" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected purpose 'public', got '{}'",
                parts[1]
            )));
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
            PasetoError::InvalidTokenFormat(format!("Invalid base64url payload: {}", e))
        })?;

        // Payload must be at least 64 bytes (signature)
        if payload_bytes.len() < 64 {
            return Err(PasetoError::InvalidTokenFormat(
                "Payload too short (minimum 64 bytes for signature)".to_string(),
            ));
        }

        // Extract payload and signature
        let signature_start = payload_bytes.len() - 64;
        let payload = &payload_bytes[..signature_start];
        let signature_bytes: [u8; 64] = payload_bytes[signature_start..].try_into().unwrap();
        let signature = Signature::from_bytes(&signature_bytes);

        // Handle footer
        let token_footer = if parts.len() == 4 {
            Some(URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                PasetoError::InvalidTokenFormat(format!("Invalid base64url footer: {}", e))
            })?)
        } else {
            None
        };

        // Verify footer matches if provided
        let footer_bytes = footer.unwrap_or(b"");
        let token_footer_bytes = token_footer.as_deref().unwrap_or(b"");
        if footer_bytes != token_footer_bytes {
            return Err(PasetoError::FooterMismatch);
        }

        // Build pre-authentication encoding for signature verification
        // PAE(version.purpose, payload, footer) - NO implicit assertion in v2
        let header = b"v2.public.";

        let pae_pieces: Vec<&[u8]> = vec![header, payload, token_footer_bytes];
        let m2 = Pae::encode(&pae_pieces);

        // Verify signature
        verifying_key
            .verify(&m2, &signature)
            .map_err(|_| PasetoError::SignatureVerificationFailed)?;

        Ok(payload.to_vec())
    }

    /// Verify a v3.public token (NIST-compliant asymmetric verification)
    ///
    /// Uses ECDSA P-384 with SHA-384 for token verification.
    /// This provides NIST-compliant cryptography for regulated environments.
    ///
    /// # Arguments
    /// * `token` - Token string to verify
    /// * `public_key` - 49-byte P-384 public key (compressed) or 97-byte (uncompressed)
    /// * `footer` - Optional expected footer data
    /// * `implicit_assertion` - Optional implicit assertion
    ///
    /// # Returns
    /// * `Result<Vec<u8>, PasetoError>` - Verified payload bytes or error
    ///
    /// # Errors
    /// - `InvalidKeyLength` if public key is not 49 bytes (compressed) or 97 bytes (uncompressed)
    /// - `InvalidKeyFormat` if public key is not a valid P-384 key
    /// - `InvalidTokenFormat` if token format is invalid
    /// - `FooterMismatch` if provided footer doesn't match token footer
    /// - `SignatureVerificationFailed` if signature verification fails
    pub fn v3_public_verify(
        &self,
        token: &str,
        public_key: &[u8],
        footer: Option<&[u8]>,
        implicit_assertion: Option<&[u8]>,
    ) -> Result<Vec<u8>, PasetoError> {
        // Validate key length (49 compressed or 97 uncompressed)
        if public_key.len() != 49 && public_key.len() != 97 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 49, // or 97
                actual: public_key.len(),
            });
        }

        // Convert to P-384 verifying key
        let encoded_point = EncodedPoint::from_bytes(public_key).map_err(|e| {
            PasetoError::InvalidKeyFormat(format!("Invalid P-384 public key: {}", e))
        })?;
        let pk = P384PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or_else(|| {
                PasetoError::InvalidKeyFormat("Invalid P-384 public key point".to_string())
            })?;
        let verifying_key = P384VerifyingKey::from(&pk);

        // Parse token format: v3.public.payload[.footer]
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(PasetoError::InvalidTokenFormat(
                "Token must have 3 or 4 parts separated by '.'".to_string(),
            ));
        }

        // Validate version and purpose
        if parts[0] != "v3" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected version 'v3', got '{}'",
                parts[0]
            )));
        }
        if parts[1] != "public" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected purpose 'public', got '{}'",
                parts[1]
            )));
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
            PasetoError::InvalidTokenFormat(format!("Invalid base64url payload: {}", e))
        })?;

        // Payload must be at least 96 bytes (signature)
        if payload_bytes.len() < 96 {
            return Err(PasetoError::InvalidTokenFormat(
                "Payload too short (minimum 96 bytes for signature)".to_string(),
            ));
        }

        // Extract payload and signature
        let signature_start = payload_bytes.len() - 96;
        let message = &payload_bytes[..signature_start];
        let signature_bytes = &payload_bytes[signature_start..];
        let signature = P384Signature::from_slice(signature_bytes)
            .map_err(|e| PasetoError::InvalidTokenFormat(format!("Invalid signature: {}", e)))?;

        // Handle footer
        let token_footer = if parts.len() == 4 {
            Some(URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                PasetoError::InvalidTokenFormat(format!("Invalid base64url footer: {}", e))
            })?)
        } else {
            None
        };

        // Verify footer matches if provided
        let footer_bytes = footer.unwrap_or(b"");
        let token_footer_bytes = token_footer.as_deref().unwrap_or(b"");
        if footer_bytes != token_footer_bytes {
            return Err(PasetoError::FooterMismatch);
        }

        // Build pre-authentication encoding for signature verification
        // PAE(version.purpose, payload, footer, implicit_assertion)
        let header = b"v3.public.";
        let implicit_bytes = implicit_assertion.unwrap_or(b"");

        let pae_pieces: Vec<&[u8]> = vec![header, message, token_footer_bytes, implicit_bytes];
        let m2 = Pae::encode(&pae_pieces);

        // Verify signature
        verifying_key
            .verify(&m2, &signature)
            .map_err(|_| PasetoError::SignatureVerificationFailed)?;

        Ok(message.to_vec())
    }

    /// Verify a v4.public token
    ///
    /// # Arguments
    /// * `token` - Token string to verify
    /// * `public_key` - 32-byte Ed25519 public key
    /// * `footer` - Optional expected footer data
    /// * `implicit_assertion` - Optional implicit assertion
    ///
    /// # Returns
    /// * `Result<Vec<u8>, PasetoError>` - Verified payload bytes or error
    ///
    /// # Errors
    /// - `InvalidKeyLength` if public key is not 32 bytes
    /// - `InvalidKeyFormat` if public key is not a valid Ed25519 key
    /// - `InvalidTokenFormat` if token format is invalid
    /// - `FooterMismatch` if provided footer doesn't match token footer
    /// - `SignatureVerificationFailed` if signature verification fails
    pub fn v4_public_verify(
        &self,
        token: &str,
        public_key: &[u8],
        footer: Option<&[u8]>,
        implicit_assertion: Option<&[u8]>,
    ) -> Result<Vec<u8>, PasetoError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Validate key length
        if public_key.len() != 32 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 32,
                actual: public_key.len(),
            });
        }

        // Convert to Ed25519 verifying key
        let key_bytes: [u8; 32] = public_key.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            PasetoError::InvalidKeyFormat(format!("Invalid Ed25519 public key: {}", e))
        })?;

        // Parse token format: v4.public.payload[.footer]
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(PasetoError::InvalidTokenFormat(
                "Token must have 3 or 4 parts separated by '.'".to_string(),
            ));
        }

        // Validate version and purpose
        if parts[0] != "v4" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected version 'v4', got '{}'",
                parts[0]
            )));
        }
        if parts[1] != "public" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected purpose 'public', got '{}'",
                parts[1]
            )));
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
            PasetoError::InvalidTokenFormat(format!("Invalid base64url payload: {}", e))
        })?;

        // Payload must be at least 64 bytes (signature)
        if payload_bytes.len() < 64 {
            return Err(PasetoError::InvalidTokenFormat(
                "Payload too short (minimum 64 bytes for signature)".to_string(),
            ));
        }

        // Extract payload and signature
        let signature_start = payload_bytes.len() - 64;
        let payload = &payload_bytes[..signature_start];
        let signature_bytes: [u8; 64] = payload_bytes[signature_start..].try_into().unwrap();
        let signature = Signature::from_bytes(&signature_bytes);

        // Handle footer
        let token_footer = if parts.len() == 4 {
            Some(URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                PasetoError::InvalidTokenFormat(format!("Invalid base64url footer: {}", e))
            })?)
        } else {
            None
        };

        // Verify footer matches if provided
        let footer_bytes = footer.unwrap_or(b"");
        let token_footer_bytes = token_footer.as_deref().unwrap_or(b"");
        if footer_bytes != token_footer_bytes {
            return Err(PasetoError::FooterMismatch);
        }

        // Build pre-authentication encoding for signature verification
        // PAE(version.purpose, payload, footer, implicit_assertion)
        let header = b"v4.public.";
        let implicit_bytes = implicit_assertion.unwrap_or(b"");

        let pae_pieces: Vec<&[u8]> = vec![header, payload, token_footer_bytes, implicit_bytes];
        let m2 = Pae::encode(&pae_pieces);

        // Verify signature
        verifying_key
            .verify(&m2, &signature)
            .map_err(|_| PasetoError::SignatureVerificationFailed)?;

        Ok(payload.to_vec())
    }

    /// Verify and decrypt a v4.local token
    ///
    /// # Arguments
    /// * `token` - Token string to verify
    /// * `key` - 32-byte symmetric key
    /// * `footer` - Optional expected footer data
    /// * `implicit_assertion` - Optional implicit assertion for AAD
    ///
    /// # Returns
    /// * `Result<Vec<u8>, PasetoError>` - Decrypted payload bytes or error
    ///
    /// # Errors
    /// - `InvalidKeyLength` if key is not 32 bytes
    /// - `InvalidTokenFormat` if token format is invalid
    /// - `FooterMismatch` if provided footer doesn't match token footer
    /// - `AuthenticationFailed` if MAC verification fails
    pub fn v4_local_decrypt(
        &self,
        token: &str,
        key: &[u8],
        footer: Option<&[u8]>,
        implicit_assertion: Option<&[u8]>,
    ) -> Result<Vec<u8>, PasetoError> {
        // Validate key length
        if key.len() != 32 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        // Convert key to array
        let key_array: [u8; 32] = key.try_into().unwrap();

        // Parse token format: v4.local.payload[.footer]
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(PasetoError::InvalidTokenFormat(
                "Token must have 3 or 4 parts separated by '.'".to_string(),
            ));
        }

        // Validate version and purpose
        if parts[0] != "v4" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected version 'v4', got '{}'",
                parts[0]
            )));
        }
        if parts[1] != "local" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected purpose 'local', got '{}'",
                parts[1]
            )));
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
            PasetoError::InvalidTokenFormat(format!("Invalid base64url payload: {}", e))
        })?;

        // Payload must be at least 32 (nonce) + 32 (tag) = 64 bytes
        if payload_bytes.len() < 64 {
            return Err(PasetoError::InvalidTokenFormat(
                "Payload too short (minimum 64 bytes)".to_string(),
            ));
        }

        // Extract nonce (first 32 bytes)
        let nonce: [u8; 32] = payload_bytes[..32].try_into().unwrap();

        // Extract ciphertext (middle bytes)
        let ciphertext_end = payload_bytes.len() - 32;
        let ciphertext = &payload_bytes[32..ciphertext_end];

        // Extract tag (last 32 bytes)
        let received_tag: [u8; 32] = payload_bytes[ciphertext_end..].try_into().unwrap();

        // Handle footer
        let token_footer = if parts.len() == 4 {
            Some(URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                PasetoError::InvalidTokenFormat(format!("Invalid base64url footer: {}", e))
            })?)
        } else {
            None
        };

        // Verify footer matches if provided
        let footer_bytes = footer.unwrap_or(b"");
        let token_footer_bytes = token_footer.as_deref().unwrap_or(b"");
        if footer_bytes != token_footer_bytes {
            return Err(PasetoError::FooterMismatch);
        }

        // Derive encryption and authentication keys using BLAKE2b
        let mut ek_input = Vec::new();
        ek_input.extend_from_slice(b"paseto-encryption-key");
        ek_input.extend_from_slice(&nonce);
        let mut ek_mac = <Blake2bMac512 as KeyInit>::new_from_slice(&key_array).map_err(|e| {
            PasetoError::CryptoError(format!("EK MAC initialization failed: {}", e))
        })?;
        ek_mac.update(&ek_input);
        let ek_result = ek_mac.finalize();
        let ek: [u8; 32] = ek_result.into_bytes()[..32].try_into().unwrap();

        let mut ak_input = Vec::new();
        ak_input.extend_from_slice(b"paseto-auth-key-for-aead");
        ak_input.extend_from_slice(&nonce);
        let mut ak_mac = <Blake2bMac512 as KeyInit>::new_from_slice(&key_array).map_err(|e| {
            PasetoError::CryptoError(format!("AK MAC initialization failed: {}", e))
        })?;
        ak_mac.update(&ak_input);
        let ak_result = ak_mac.finalize();
        let ak: [u8; 32] = ak_result.into_bytes()[..32].try_into().unwrap();

        // Build pre-authentication encoding
        let header = b"v4.local.";
        let implicit_bytes = implicit_assertion.unwrap_or(b"");

        let pae_pieces: Vec<&[u8]> = vec![
            header,
            &nonce,
            ciphertext,
            token_footer_bytes,
            implicit_bytes,
        ];
        let pae = Pae::encode(&pae_pieces);

        // Compute expected authentication tag using BLAKE2b-MAC
        let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(&ak)
            .map_err(|e| PasetoError::CryptoError(format!("MAC initialization failed: {}", e)))?;
        mac.update(&pae);
        let computed_tag = mac.finalize().into_bytes();

        // Use constant-time comparison for MAC verification
        let computed_tag_32: [u8; 32] = computed_tag[..32].try_into().unwrap();
        if computed_tag_32.ct_eq(&received_tag).into() {
            // MAC verification succeeded, decrypt the ciphertext
            let xchacha_nonce: [u8; 24] = nonce[..24].try_into().unwrap();
            let mut cipher = XChaCha20::new((&ek).into(), &xchacha_nonce.into());
            let mut plaintext = ciphertext.to_vec();
            cipher.apply_keystream(&mut plaintext);

            Ok(plaintext)
        } else {
            Err(PasetoError::AuthenticationFailed)
        }
    }

    /// Verify and decrypt a v3.local token (NIST-compliant symmetric encryption)
    ///
    /// Uses AES-256-CTR decryption with HMAC-SHA384 for authenticated decryption.
    /// This provides NIST-compliant cryptography for regulated environments.
    ///
    /// # Arguments
    /// * `token` - Token string to verify
    /// * `key` - 32-byte symmetric key
    /// * `footer` - Optional expected footer data
    /// * `implicit_assertion` - Optional implicit assertion for AAD
    ///
    /// # Returns
    /// * `Result<Vec<u8>, PasetoError>` - Decrypted payload bytes or error
    ///
    /// # Errors
    /// - `InvalidKeyLength` if key is not 32 bytes
    /// - `InvalidTokenFormat` if token format is invalid
    /// - `FooterMismatch` if provided footer doesn't match token footer
    /// - `AuthenticationFailed` if HMAC verification fails
    pub fn v3_local_decrypt(
        &self,
        token: &str,
        key: &[u8],
        footer: Option<&[u8]>,
        implicit_assertion: Option<&[u8]>,
    ) -> Result<Vec<u8>, PasetoError> {
        // Validate key length
        if key.len() != 32 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        // Parse token format: v3.local.payload[.footer]
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(PasetoError::InvalidTokenFormat(
                "Token must have 3 or 4 parts separated by '.'".to_string(),
            ));
        }

        // Validate version and purpose
        if parts[0] != "v3" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected version 'v3', got '{}'",
                parts[0]
            )));
        }
        if parts[1] != "local" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected purpose 'local', got '{}'",
                parts[1]
            )));
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
            PasetoError::InvalidTokenFormat(format!("Invalid base64url payload: {}", e))
        })?;

        // Payload must be at least 32 (nonce) + 48 (tag) = 80 bytes
        if payload_bytes.len() < 80 {
            return Err(PasetoError::InvalidTokenFormat(
                "Payload too short (minimum 80 bytes for v3.local)".to_string(),
            ));
        }

        // Extract nonce (first 32 bytes)
        let nonce: [u8; 32] = payload_bytes[..32].try_into().unwrap();

        // Extract ciphertext (middle bytes)
        let ciphertext_end = payload_bytes.len() - 48;
        let ciphertext = &payload_bytes[32..ciphertext_end];

        // Extract tag (last 48 bytes - HMAC-SHA384 output)
        let received_tag: [u8; 48] = payload_bytes[ciphertext_end..].try_into().unwrap();

        // Handle footer
        let token_footer = if parts.len() == 4 {
            Some(URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                PasetoError::InvalidTokenFormat(format!("Invalid base64url footer: {}", e))
            })?)
        } else {
            None
        };

        // Verify footer matches if provided
        let footer_bytes = footer.unwrap_or(b"");
        let token_footer_bytes = token_footer.as_deref().unwrap_or(b"");
        if footer_bytes != token_footer_bytes {
            return Err(PasetoError::FooterMismatch);
        }

        // Derive encryption key using HKDF-SHA384
        let hkdf = Hkdf::<Sha384>::new(None, key);
        let mut ek_info = Vec::new();
        ek_info.extend_from_slice(b"paseto-encryption-key");
        ek_info.extend_from_slice(&nonce);
        let mut ek = [0u8; 32];
        hkdf.expand(&ek_info, &mut ek)
            .map_err(|e| PasetoError::CryptoError(format!("HKDF expand failed: {}", e)))?;

        // Derive authentication key using HKDF-SHA384
        let mut ak_info = Vec::new();
        ak_info.extend_from_slice(b"paseto-auth-key-for-aead");
        ak_info.extend_from_slice(&nonce);
        let mut ak = [0u8; 32];
        hkdf.expand(&ak_info, &mut ak)
            .map_err(|e| PasetoError::CryptoError(format!("HKDF expand failed: {}", e)))?;

        // Build pre-authentication encoding
        let header = b"v3.local.";
        let implicit_bytes = implicit_assertion.unwrap_or(b"");

        let pae_pieces: Vec<&[u8]> = vec![
            header,
            &nonce,
            ciphertext,
            token_footer_bytes,
            implicit_bytes,
        ];
        let pae = Pae::encode(&pae_pieces);

        // Compute expected authentication tag using HMAC-SHA384
        let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(&ak)
            .map_err(|e| PasetoError::CryptoError(format!("HMAC init failed: {}", e)))?;
        mac.update(&pae);
        let computed_tag = mac.finalize().into_bytes();

        // Use constant-time comparison for HMAC verification
        let computed_tag_48: [u8; 48] = computed_tag.as_slice().try_into().unwrap();
        if computed_tag_48.ct_eq(&received_tag).into() {
            // HMAC verification succeeded, decrypt the ciphertext
            let iv: [u8; 16] = nonce[..16].try_into().unwrap();
            let mut cipher = Ctr128BE::<Aes256>::new((&ek).into(), (&iv).into());
            let mut plaintext = ciphertext.to_vec();
            cipher.apply_keystream(&mut plaintext);

            Ok(plaintext)
        } else {
            Err(PasetoError::AuthenticationFailed)
        }
    }

    /// Verify and decrypt a v2.local token (legacy symmetric encryption)
    ///
    /// Uses XChaCha20-Poly1305 AEAD for authenticated decryption.
    /// This is a legacy version - prefer v4.local for new applications.
    ///
    /// # Arguments
    /// * `token` - Token string to verify
    /// * `key` - 32-byte symmetric key
    /// * `footer` - Optional expected footer data
    ///
    /// # Returns
    /// * `Result<Vec<u8>, PasetoError>` - Decrypted payload bytes or error
    ///
    /// # Errors
    /// - `InvalidKeyLength` if key is not 32 bytes
    /// - `InvalidTokenFormat` if token format is invalid
    /// - `FooterMismatch` if provided footer doesn't match token footer
    /// - `AuthenticationFailed` if AEAD decryption fails
    ///
    /// # Note
    /// v2 does NOT support implicit assertions (unlike v3/v4)
    pub fn v2_local_decrypt(
        &self,
        token: &str,
        key: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<Vec<u8>, PasetoError> {
        // Validate key length
        if key.len() != 32 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        // Convert key to array
        let key_array: [u8; 32] = key.try_into().unwrap();

        // Parse token format: v2.local.payload[.footer]
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(PasetoError::InvalidTokenFormat(
                "Token must have 3 or 4 parts separated by '.'".to_string(),
            ));
        }

        // Validate version and purpose
        if parts[0] != "v2" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected version 'v2', got '{}'",
                parts[0]
            )));
        }
        if parts[1] != "local" {
            return Err(PasetoError::InvalidTokenFormat(format!(
                "Expected purpose 'local', got '{}'",
                parts[1]
            )));
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| {
            PasetoError::InvalidTokenFormat(format!("Invalid base64url payload: {}", e))
        })?;

        // Payload must be at least 24 (nonce) + 16 (tag) = 40 bytes
        if payload_bytes.len() < 40 {
            return Err(PasetoError::InvalidTokenFormat(
                "Payload too short (minimum 40 bytes for v2.local)".to_string(),
            ));
        }

        // Extract nonce (first 24 bytes)
        let nonce: [u8; 24] = payload_bytes[..24].try_into().unwrap();

        // Extract ciphertext + tag (remaining bytes)
        let ciphertext_with_tag = &payload_bytes[24..];

        // Handle footer
        let token_footer = if parts.len() == 4 {
            Some(URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                PasetoError::InvalidTokenFormat(format!("Invalid base64url footer: {}", e))
            })?)
        } else {
            None
        };

        // Verify footer matches if provided
        let footer_bytes = footer.unwrap_or(b"");
        let token_footer_bytes = token_footer.as_deref().unwrap_or(b"");
        if footer_bytes != token_footer_bytes {
            return Err(PasetoError::FooterMismatch);
        }

        // Build pre-authentication encoding for AAD
        // PAE("v2.local.", nonce, footer)
        let header = b"v2.local.";
        let pae_pieces: Vec<&[u8]> = vec![header, &nonce, token_footer_bytes];
        let pae = Pae::encode(&pae_pieces);

        // Create XChaCha20-Poly1305 cipher
        let cipher = XChaCha20Poly1305::new((&key_array).into());

        // Decrypt with AAD verification
        let plaintext = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext_with_tag,
                    aad: &pae,
                },
            )
            .map_err(|_| PasetoError::AuthenticationFailed)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_generator::TokenGenerator;

    #[test]
    fn test_v4_local_decrypt_basic() {
        let key = [0u8; 32];
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v4_local_encrypt(&key, payload, None, None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key, None, None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v4_local_decrypt_with_footer() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer = b"test footer";

        // Generate token
        let token = TokenGenerator::v4_local_encrypt(&key, payload, Some(footer), None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key, Some(footer), None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v4_local_decrypt_with_implicit_assertion() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let implicit = b"test implicit assertion";

        // Generate token
        let token = TokenGenerator::v4_local_encrypt(&key, payload, None, Some(implicit)).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key, None, Some(implicit));
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v4_local_decrypt_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let token = "v4.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(token, &key, None, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_v4_local_decrypt_invalid_token_format_parts() {
        let key = [0u8; 32];
        let verifier = TokenVerifier::new(None);

        // Too few parts
        let result = verifier.v4_local_decrypt("v4.local", &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));

        // Too many parts
        let result = verifier.v4_local_decrypt("v4.local.a.b.c", &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_local_decrypt_invalid_version() {
        let key = [0u8; 32];
        let token = "v3.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_local_decrypt_invalid_purpose() {
        let key = [0u8; 32];
        let token = "v4.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_local_decrypt_invalid_base64() {
        let key = [0u8; 32];
        let token = "v4.local.invalid@base64!";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_local_decrypt_payload_too_short() {
        let key = [0u8; 32];
        // Create a token with payload shorter than 64 bytes
        let short_payload = URL_SAFE_NO_PAD.encode([0u8; 32]); // Only 32 bytes
        let token = format!("v4.local.{}", short_payload);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_local_decrypt_wrong_key() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let payload = b"test payload";

        // Generate token with key1
        let token = TokenGenerator::v4_local_encrypt(&key1, payload, None, None).unwrap();

        // Try to decrypt with key2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key2, None, None);
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v4_local_decrypt_footer_mismatch() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer1 = b"footer1";
        let footer2 = b"footer2";

        // Generate token with footer1
        let token = TokenGenerator::v4_local_encrypt(&key, payload, Some(footer1), None).unwrap();

        // Try to decrypt with footer2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key, Some(footer2), None);
        assert!(matches!(result, Err(PasetoError::FooterMismatch)));
    }

    #[test]
    fn test_v4_local_decrypt_implicit_assertion_mismatch() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let implicit1 = b"implicit1";
        let implicit2 = b"implicit2";

        // Generate token with implicit1
        let token = TokenGenerator::v4_local_encrypt(&key, payload, None, Some(implicit1)).unwrap();

        // Try to decrypt with implicit2 - should fail authentication
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key, None, Some(implicit2));
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v4_local_decrypt_tampered_payload() {
        let key = [0u8; 32];
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v4_local_encrypt(&key, payload, None, None).unwrap();

        // Tamper with the token by flipping a bit in the payload
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        payload_bytes[40] ^= 0xFF; // Flip bits in the middle
        let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let tampered_token = format!("v4.local.{}", tampered_payload);

        // Try to decrypt tampered token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&tampered_token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v4_local_decrypt_empty_payload() {
        let key = [0u8; 32];
        let payload = b"";

        // Generate token
        let token = TokenGenerator::v4_local_encrypt(&key, payload, None, None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_local_decrypt(&token, &key, None, None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    // v3.local tests
    #[test]
    fn test_v3_local_decrypt_basic() {
        let key = [0u8; 32];
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v3_local_encrypt(&key, payload, None, None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key, None, None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v3_local_decrypt_with_footer() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer = b"test footer";

        // Generate token
        let token = TokenGenerator::v3_local_encrypt(&key, payload, Some(footer), None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key, Some(footer), None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v3_local_decrypt_with_implicit_assertion() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let implicit = b"test implicit assertion";

        // Generate token
        let token = TokenGenerator::v3_local_encrypt(&key, payload, None, Some(implicit)).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key, None, Some(implicit));
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v3_local_decrypt_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let token = "v3.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(token, &key, None, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_v3_local_decrypt_invalid_token_format_parts() {
        let key = [0u8; 32];
        let verifier = TokenVerifier::new(None);

        // Too few parts
        let result = verifier.v3_local_decrypt("v3.local", &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));

        // Too many parts
        let result = verifier.v3_local_decrypt("v3.local.a.b.c", &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_local_decrypt_invalid_version() {
        let key = [0u8; 32];
        let token = "v4.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_local_decrypt_invalid_purpose() {
        let key = [0u8; 32];
        let token = "v3.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_local_decrypt_invalid_base64() {
        let key = [0u8; 32];
        let token = "v3.local.invalid@base64!";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_local_decrypt_payload_too_short() {
        let key = [0u8; 32];
        // Create a token with payload shorter than 80 bytes (32 nonce + 48 tag)
        let short_payload = URL_SAFE_NO_PAD.encode([0u8; 64]); // Only 64 bytes
        let token = format!("v3.local.{}", short_payload);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_local_decrypt_wrong_key() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let payload = b"test payload";

        // Generate token with key1
        let token = TokenGenerator::v3_local_encrypt(&key1, payload, None, None).unwrap();

        // Try to decrypt with key2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key2, None, None);
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v3_local_decrypt_footer_mismatch() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer1 = b"footer1";
        let footer2 = b"footer2";

        // Generate token with footer1
        let token = TokenGenerator::v3_local_encrypt(&key, payload, Some(footer1), None).unwrap();

        // Try to decrypt with footer2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key, Some(footer2), None);
        assert!(matches!(result, Err(PasetoError::FooterMismatch)));
    }

    #[test]
    fn test_v3_local_decrypt_implicit_assertion_mismatch() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let implicit1 = b"implicit1";
        let implicit2 = b"implicit2";

        // Generate token with implicit1
        let token = TokenGenerator::v3_local_encrypt(&key, payload, None, Some(implicit1)).unwrap();

        // Try to decrypt with implicit2 - should fail authentication
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key, None, Some(implicit2));
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v3_local_decrypt_tampered_payload() {
        let key = [0u8; 32];
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v3_local_encrypt(&key, payload, None, None).unwrap();

        // Tamper with the token by flipping a bit in the payload
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        payload_bytes[40] ^= 0xFF; // Flip bits in the middle
        let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let tampered_token = format!("v3.local.{}", tampered_payload);

        // Try to decrypt tampered token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&tampered_token, &key, None, None);
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v3_local_decrypt_empty_payload() {
        let key = [0u8; 32];
        let payload = b"";

        // Generate token
        let token = TokenGenerator::v3_local_encrypt(&key, payload, None, None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_local_decrypt(&token, &key, None, None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    // v4.public tests
    #[test]
    fn test_v4_public_verify_basic() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";

        // Generate token
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair.public_key, None, None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v4_public_verify_with_footer() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let footer = b"test footer";

        // Generate token
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, Some(footer), None)
                .unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair.public_key, Some(footer), None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v4_public_verify_with_implicit_assertion() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let implicit = b"test implicit assertion";

        // Generate token
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, Some(implicit))
                .unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair.public_key, None, Some(implicit));
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v4_public_verify_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let token = "v4.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(token, &key, None, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_v4_public_verify_invalid_key_format() {
        // Note: Not all 32-byte arrays are invalid Ed25519 keys
        // This test verifies that the error path exists, but may not always trigger
        // with all-zeros since that might be a valid (though useless) key format
        let key = [0u8; 32];

        // Create a minimal valid token structure to test key validation
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let minimal_payload = vec![0u8; 64]; // Just a signature
        let encoded = URL_SAFE_NO_PAD.encode(&minimal_payload);
        let token = format!("v4.public.{}", encoded);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &key, None, None);

        // The result should be an error (either InvalidKeyFormat or SignatureVerificationFailed)
        // depending on whether the key is accepted as valid format
        assert!(
            result.is_err(),
            "Invalid or zero key should fail verification"
        );
    }

    #[test]
    fn test_v4_public_verify_invalid_token_format_parts() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let verifier = TokenVerifier::new(None);

        // Too few parts
        let result = verifier.v4_public_verify("v4.public", &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));

        // Too many parts
        let result = verifier.v4_public_verify("v4.public.a.b.c", &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_public_verify_invalid_version() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let token = "v3.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_public_verify_invalid_purpose() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let token = "v4.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_public_verify_invalid_base64() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let token = "v4.public.invalid@base64!";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_public_verify_payload_too_short() {
        use crate::key_generator::KeyGenerator;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let keypair = KeyGenerator::generate_ed25519_keypair();
        // Create a token with payload shorter than 64 bytes
        let short_payload = URL_SAFE_NO_PAD.encode([0u8; 32]); // Only 32 bytes
        let token = format!("v4.public.{}", short_payload);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v4_public_verify_wrong_key() {
        use crate::key_generator::KeyGenerator;

        let keypair1 = KeyGenerator::generate_ed25519_keypair();
        let keypair2 = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";

        // Generate token with keypair1
        let token =
            TokenGenerator::v4_public_sign(&keypair1.secret_key, payload, None, None).unwrap();

        // Try to verify with keypair2's public key
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair2.public_key, None, None);
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v4_public_verify_footer_mismatch() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let footer1 = b"footer1";
        let footer2 = b"footer2";

        // Generate token with footer1
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, Some(footer1), None)
                .unwrap();

        // Try to verify with footer2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair.public_key, Some(footer2), None);
        assert!(matches!(result, Err(PasetoError::FooterMismatch)));
    }

    #[test]
    fn test_v4_public_verify_implicit_assertion_mismatch() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let implicit1 = b"implicit1";
        let implicit2 = b"implicit2";

        // Generate token with implicit1
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, Some(implicit1))
                .unwrap();

        // Try to verify with implicit2 - should fail signature verification
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair.public_key, None, Some(implicit2));
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v4_public_verify_tampered_payload() {
        use crate::key_generator::KeyGenerator;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";

        // Generate token
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        // Tamper with the token by flipping a bit in the payload
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        payload_bytes[5] ^= 0xFF; // Flip bits in the payload (not signature)
        let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let tampered_token = format!("v4.public.{}", tampered_payload);

        // Try to verify tampered token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&tampered_token, &keypair.public_key, None, None);
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v4_public_verify_empty_payload() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"";

        // Generate token
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v4_public_verify(&token, &keypair.public_key, None, None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    // v3.public tests
    #[test]
    fn test_v3_public_verify_basic() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let payload = b"test payload";

        // Generate token
        let token =
            TokenGenerator::v3_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair.public_key, None, None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v3_public_verify_with_footer() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let payload = b"test payload";
        let footer = b"test footer";

        // Generate token
        let token =
            TokenGenerator::v3_public_sign(&keypair.secret_key, payload, Some(footer), None)
                .unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair.public_key, Some(footer), None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v3_public_verify_with_implicit_assertion() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let payload = b"test payload";
        let implicit = b"test implicit assertion";

        // Generate token
        let token =
            TokenGenerator::v3_public_sign(&keypair.secret_key, payload, None, Some(implicit))
                .unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair.public_key, None, Some(implicit));
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v3_public_verify_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let token = "v3.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(token, &key, None, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 49);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_v3_public_verify_invalid_token_format_parts() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let verifier = TokenVerifier::new(None);

        // Too few parts
        let result = verifier.v3_public_verify("v3.public", &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));

        // Too many parts
        let result = verifier.v3_public_verify("v3.public.a.b.c", &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_public_verify_invalid_version() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let token = "v4.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_public_verify_invalid_purpose() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let token = "v3.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_public_verify_invalid_base64() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let token = "v3.public.invalid@base64!";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_public_verify_payload_too_short() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        // Create a token with payload shorter than 96 bytes
        let short_payload = URL_SAFE_NO_PAD.encode([0u8; 48]); // Only 48 bytes
        let token = format!("v3.public.{}", short_payload);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair.public_key, None, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v3_public_verify_wrong_key() {
        use crate::key_generator::KeyGenerator;

        let keypair1 = KeyGenerator::generate_p384_keypair();
        let keypair2 = KeyGenerator::generate_p384_keypair();
        let payload = b"test payload";

        // Generate token with keypair1
        let token =
            TokenGenerator::v3_public_sign(&keypair1.secret_key, payload, None, None).unwrap();

        // Try to verify with keypair2's public key
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair2.public_key, None, None);
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v3_public_verify_footer_mismatch() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let payload = b"test payload";
        let footer1 = b"footer1";
        let footer2 = b"footer2";

        // Generate token with footer1
        let token =
            TokenGenerator::v3_public_sign(&keypair.secret_key, payload, Some(footer1), None)
                .unwrap();

        // Try to verify with footer2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair.public_key, Some(footer2), None);
        assert!(matches!(result, Err(PasetoError::FooterMismatch)));
    }

    #[test]
    fn test_v3_public_verify_implicit_assertion_mismatch() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let payload = b"test payload";
        let implicit1 = b"implicit1";
        let implicit2 = b"implicit2";

        // Generate token with implicit1
        let token =
            TokenGenerator::v3_public_sign(&keypair.secret_key, payload, None, Some(implicit1))
                .unwrap();

        // Try to verify with implicit2 - should fail signature verification
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair.public_key, None, Some(implicit2));
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v3_public_verify_tampered_payload() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let payload = b"test payload";

        // Generate token
        let token =
            TokenGenerator::v3_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        // Tamper with the token by flipping a bit in the payload
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        payload_bytes[5] ^= 0xFF; // Flip bits in the payload (not signature)
        let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let tampered_token = format!("v3.public.{}", tampered_payload);

        // Try to verify tampered token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&tampered_token, &keypair.public_key, None, None);
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v3_public_verify_empty_payload() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_p384_keypair();
        let payload = b"";

        // Generate token
        let token =
            TokenGenerator::v3_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v3_public_verify(&token, &keypair.public_key, None, None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    // v2.public tests
    #[test]
    fn test_v2_public_verify_basic() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v2_public_sign(&keypair.secret_key, payload, None).unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&token, &keypair.public_key, None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v2_public_verify_with_footer() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let footer = b"test footer";

        // Generate token
        let token =
            TokenGenerator::v2_public_sign(&keypair.secret_key, payload, Some(footer)).unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&token, &keypair.public_key, Some(footer));
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_v2_public_verify_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let token = "v2.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(token, &key, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_v2_public_verify_invalid_key_format() {
        // Note: Not all 32-byte arrays are invalid Ed25519 keys
        // This test verifies that the error path exists, but may not always trigger
        // with all-zeros since that might be a valid (though useless) key format
        let key = [0u8; 32];

        // Create a minimal valid token structure to test key validation
        let minimal_payload = vec![0u8; 64]; // Just a signature
        let encoded = URL_SAFE_NO_PAD.encode(&minimal_payload);
        let token = format!("v2.public.{}", encoded);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&token, &key, None);

        // The result should be an error (either InvalidKeyFormat or SignatureVerificationFailed)
        // depending on whether the key is accepted as valid format
        assert!(
            result.is_err(),
            "Invalid or zero key should fail verification"
        );
    }

    #[test]
    fn test_v2_public_verify_invalid_token_format_parts() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let verifier = TokenVerifier::new(None);

        // Too few parts
        let result = verifier.v2_public_verify("v2.public", &keypair.public_key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));

        // Too many parts
        let result = verifier.v2_public_verify("v2.public.a.b.c", &keypair.public_key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_public_verify_invalid_version() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let token = "v4.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(token, &keypair.public_key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_public_verify_invalid_purpose() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let token = "v2.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(token, &keypair.public_key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_public_verify_invalid_base64() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let token = "v2.public.invalid@base64!";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(token, &keypair.public_key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_public_verify_payload_too_short() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        // Create a token with payload shorter than 64 bytes
        let short_payload = URL_SAFE_NO_PAD.encode([0u8; 32]); // Only 32 bytes
        let token = format!("v2.public.{}", short_payload);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&token, &keypair.public_key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_public_verify_wrong_key() {
        use crate::key_generator::KeyGenerator;

        let keypair1 = KeyGenerator::generate_ed25519_keypair();
        let keypair2 = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";

        // Generate token with keypair1
        let token = TokenGenerator::v2_public_sign(&keypair1.secret_key, payload, None).unwrap();

        // Try to verify with keypair2's public key
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&token, &keypair2.public_key, None);
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v2_public_verify_footer_mismatch() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let footer1 = b"footer1";
        let footer2 = b"footer2";

        // Generate token with footer1
        let token =
            TokenGenerator::v2_public_sign(&keypair.secret_key, payload, Some(footer1)).unwrap();

        // Try to verify with footer2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&token, &keypair.public_key, Some(footer2));
        assert!(matches!(result, Err(PasetoError::FooterMismatch)));
    }

    #[test]
    fn test_v2_public_verify_tampered_payload() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v2_public_sign(&keypair.secret_key, payload, None).unwrap();

        // Tamper with the token by flipping a bit in the payload
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        payload_bytes[5] ^= 0xFF; // Flip bits in the payload (not signature)
        let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let tampered_token = format!("v2.public.{}", tampered_payload);

        // Try to verify tampered token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&tampered_token, &keypair.public_key, None);
        assert!(matches!(
            result,
            Err(PasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_v2_public_verify_empty_payload() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"";

        // Generate token
        let token = TokenGenerator::v2_public_sign(&keypair.secret_key, payload, None).unwrap();

        // Verify token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_public_verify(&token, &keypair.public_key, None);
        assert!(result.is_ok());

        let verified = result.unwrap();
        assert_eq!(verified, payload);
    }

    // v2.local tests
    #[test]
    fn test_v2_local_decrypt_basic() {
        let key = [0u8; 32];
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v2_local_encrypt(&key, payload, None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(&token, &key, None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v2_local_decrypt_with_footer() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer = b"test footer";

        // Generate token
        let token = TokenGenerator::v2_local_encrypt(&key, payload, Some(footer)).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(&token, &key, Some(footer));
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_v2_local_decrypt_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let token = "v2.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(token, &key, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_v2_local_decrypt_invalid_token_format_parts() {
        let key = [0u8; 32];
        let verifier = TokenVerifier::new(None);

        // Too few parts
        let result = verifier.v2_local_decrypt("v2.local", &key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));

        // Too many parts
        let result = verifier.v2_local_decrypt("v2.local.a.b.c", &key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_local_decrypt_invalid_version() {
        let key = [0u8; 32];
        let token = "v4.local.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(token, &key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_local_decrypt_invalid_purpose() {
        let key = [0u8; 32];
        let token = "v2.public.test";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(token, &key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_local_decrypt_invalid_base64() {
        let key = [0u8; 32];
        let token = "v2.local.invalid@base64!";

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(token, &key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_local_decrypt_payload_too_short() {
        let key = [0u8; 32];
        // Create a token with payload shorter than 40 bytes (24 nonce + 16 tag)
        let short_payload = URL_SAFE_NO_PAD.encode([0u8; 32]); // Only 32 bytes
        let token = format!("v2.local.{}", short_payload);

        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(&token, &key, None);
        assert!(matches!(result, Err(PasetoError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_v2_local_decrypt_wrong_key() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let payload = b"test payload";

        // Generate token with key1
        let token = TokenGenerator::v2_local_encrypt(&key1, payload, None).unwrap();

        // Try to decrypt with key2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(&token, &key2, None);
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v2_local_decrypt_footer_mismatch() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer1 = b"footer1";
        let footer2 = b"footer2";

        // Generate token with footer1
        let token = TokenGenerator::v2_local_encrypt(&key, payload, Some(footer1)).unwrap();

        // Try to decrypt with footer2
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(&token, &key, Some(footer2));
        assert!(matches!(result, Err(PasetoError::FooterMismatch)));
    }

    #[test]
    fn test_v2_local_decrypt_tampered_payload() {
        let key = [0u8; 32];
        let payload = b"test payload";

        // Generate token
        let token = TokenGenerator::v2_local_encrypt(&key, payload, None).unwrap();

        // Tamper with the token by flipping a bit in the payload
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        payload_bytes[30] ^= 0xFF; // Flip bits in the middle
        let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let tampered_token = format!("v2.local.{}", tampered_payload);

        // Try to decrypt tampered token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(&tampered_token, &key, None);
        assert!(matches!(result, Err(PasetoError::AuthenticationFailed)));
    }

    #[test]
    fn test_v2_local_decrypt_empty_payload() {
        let key = [0u8; 32];
        let payload = b"";

        // Generate token
        let token = TokenGenerator::v2_local_encrypt(&key, payload, None).unwrap();

        // Decrypt token
        let verifier = TokenVerifier::new(None);
        let result = verifier.v2_local_decrypt(&token, &key, None);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert_eq!(decrypted, payload);
    }
}
