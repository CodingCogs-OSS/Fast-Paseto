//! Token generation for all PASETO versions
//!
//! This module implements token generation (encryption/signing) for PASETO tokens.

use crate::error::PasetoError;
use crate::pae::Pae;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use blake2::Blake2bMac512;
use blake2::digest::{KeyInit, Mac};
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, rngs::OsRng};

/// Token generation for all PASETO versions
pub struct TokenGenerator;

impl TokenGenerator {
    /// Generate a v4.public token (asymmetric signing)
    ///
    /// Uses Ed25519 signatures for token authentication.
    ///
    /// # Arguments
    /// * `secret_key` - 64-byte Ed25519 secret key
    /// * `payload` - Token payload as bytes
    /// * `footer` - Optional footer data
    /// * `implicit_assertion` - Optional implicit assertion
    ///
    /// # Returns
    /// * `Result<String, PasetoError>` - Token string or error
    ///
    /// # Errors
    /// Returns `PasetoError::InvalidKeyLength` if secret key is not 64 bytes
    /// Returns `PasetoError::InvalidKeyFormat` if secret key is not a valid Ed25519 key
    ///
    /// # Token Format
    /// `v4.public.base64url(payload || signature)[.base64url(footer)]`
    pub fn v4_public_sign(
        secret_key: &[u8],
        payload: &[u8],
        footer: Option<&[u8]>,
        implicit_assertion: Option<&[u8]>,
    ) -> Result<String, PasetoError> {
        use ed25519_dalek::{Signer, SigningKey};

        // Validate key length
        if secret_key.len() != 64 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 64,
                actual: secret_key.len(),
            });
        }

        // Convert to Ed25519 signing key
        let key_bytes: [u8; 64] = secret_key.try_into().unwrap();
        let signing_key = SigningKey::from_keypair_bytes(&key_bytes)
            .map_err(|e| PasetoError::InvalidKeyFormat(format!("Invalid Ed25519 key: {}", e)))?;

        // Build pre-authentication encoding for signature
        // PAE(version.purpose, payload, footer, implicit_assertion)
        let header = b"v4.public.";
        let footer_bytes = footer.unwrap_or(b"");
        let implicit_bytes = implicit_assertion.unwrap_or(b"");

        let pae_pieces: Vec<&[u8]> = vec![header, payload, footer_bytes, implicit_bytes];
        let m2 = Pae::encode(&pae_pieces);

        // Sign the PAE
        let signature = signing_key.sign(&m2);

        // Concatenate payload || signature
        let mut token_bytes = Vec::with_capacity(payload.len() + 64);
        token_bytes.extend_from_slice(payload);
        token_bytes.extend_from_slice(&signature.to_bytes());

        // Encode as base64url
        let encoded_payload = URL_SAFE_NO_PAD.encode(&token_bytes);

        // Build final token string
        let mut token = format!("v4.public.{}", encoded_payload);
        if let Some(f) = footer {
            if !f.is_empty() {
                let encoded_footer = URL_SAFE_NO_PAD.encode(f);
                token.push('.');
                token.push_str(&encoded_footer);
            }
        }

        Ok(token)
    }

    /// Generate a v4.local token (symmetric encryption)
    ///
    /// Uses XChaCha20 encryption with BLAKE2b-MAC for authenticated encryption.
    ///
    /// # Arguments
    /// * `key` - 32-byte symmetric key
    /// * `payload` - Token payload as bytes
    /// * `footer` - Optional footer data
    /// * `implicit_assertion` - Optional implicit assertion for AAD
    ///
    /// # Returns
    /// * `Result<String, PasetoError>` - Token string or error
    ///
    /// # Errors
    /// Returns `PasetoError::InvalidKeyLength` if key is not 32 bytes
    ///
    /// # Token Format
    /// `v4.local.base64url(encrypted_payload)[.base64url(footer)]`
    pub fn v4_local_encrypt(
        key: &[u8],
        payload: &[u8],
        footer: Option<&[u8]>,
        implicit_assertion: Option<&[u8]>,
    ) -> Result<String, PasetoError> {
        // Validate key length
        if key.len() != 32 {
            return Err(PasetoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        // Convert key to array
        let key_array: [u8; 32] = key.try_into().unwrap();

        // Generate random 32-byte nonce
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        // Derive encryption and authentication keys using BLAKE2b
        // Ek = BLAKE2b(key=key, message="paseto-encryption-key" || nonce, size=32)
        // Ak = BLAKE2b(key=key, message="paseto-auth-key-for-aead" || nonce, size=32)

        // For keyed hashing, we use BLAKE2b-MAC
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

        // Encrypt payload using XChaCha20
        // The nonce for XChaCha20 is the first 24 bytes of our 32-byte nonce
        let xchacha_nonce: [u8; 24] = nonce[..24].try_into().unwrap();
        let mut cipher = XChaCha20::new((&ek).into(), &xchacha_nonce.into());
        let mut ciphertext = payload.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // Build pre-authentication encoding
        // PAE(version.purpose, nonce, ciphertext, footer, implicit_assertion)
        let header = b"v4.local.";
        let footer_bytes = footer.unwrap_or(b"");
        let implicit_bytes = implicit_assertion.unwrap_or(b"");

        let pae_pieces: Vec<&[u8]> =
            vec![header, &nonce, &ciphertext, footer_bytes, implicit_bytes];
        let pae = Pae::encode(&pae_pieces);

        // Compute authentication tag using BLAKE2b-MAC
        let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(&ak)
            .map_err(|e| PasetoError::CryptoError(format!("MAC initialization failed: {}", e)))?;
        mac.update(&pae);
        let tag = mac.finalize().into_bytes();

        // Concatenate nonce || ciphertext || tag[..32]
        let mut token_bytes = Vec::with_capacity(32 + ciphertext.len() + 32);
        token_bytes.extend_from_slice(&nonce);
        token_bytes.extend_from_slice(&ciphertext);
        token_bytes.extend_from_slice(&tag[..32]); // Use first 32 bytes of 64-byte tag

        // Encode as base64url
        let encoded_payload = URL_SAFE_NO_PAD.encode(&token_bytes);

        // Build final token string
        let mut token = format!("v4.local.{}", encoded_payload);
        if let Some(f) = footer {
            if !f.is_empty() {
                let encoded_footer = URL_SAFE_NO_PAD.encode(f);
                token.push('.');
                token.push_str(&encoded_footer);
            }
        }

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_verifier::TokenVerifier;
    use proptest::prelude::*;

    #[test]
    fn test_v4_local_encrypt_basic() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let result = TokenGenerator::v4_local_encrypt(&key, payload, None, None);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.starts_with("v4.local."));
    }

    #[test]
    fn test_v4_local_encrypt_with_footer() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer = b"test footer";
        let result = TokenGenerator::v4_local_encrypt(&key, payload, Some(footer), None);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.starts_with("v4.local."));

        // Token should have 4 parts when footer is present
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_v4_local_encrypt_with_implicit_assertion() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let implicit = b"test implicit assertion";
        let result = TokenGenerator::v4_local_encrypt(&key, payload, None, Some(implicit));
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.starts_with("v4.local."));
    }

    #[test]
    fn test_v4_local_encrypt_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let payload = b"test payload";
        let result = TokenGenerator::v4_local_encrypt(&key, payload, None, None);
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
    fn test_v4_local_encrypt_empty_payload() {
        let key = [0u8; 32];
        let payload = b"";
        let result = TokenGenerator::v4_local_encrypt(&key, payload, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_v4_local_encrypt_empty_footer() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let footer = b"";
        let result = TokenGenerator::v4_local_encrypt(&key, payload, Some(footer), None);
        assert!(result.is_ok());

        let token = result.unwrap();
        // Empty footer should not add a fourth part
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_v4_local_encrypt_randomness() {
        // Generate two tokens with the same key and payload
        // They should be different due to random nonce
        let key = [0u8; 32];
        let payload = b"test payload";

        let token1 = TokenGenerator::v4_local_encrypt(&key, payload, None, None).unwrap();
        let token2 = TokenGenerator::v4_local_encrypt(&key, payload, None, None).unwrap();

        assert_ne!(token1, token2, "Tokens should differ due to random nonce");
    }

    #[test]
    fn test_v4_local_encrypt_token_format() {
        let key = [0u8; 32];
        let payload = b"test payload";
        let token = TokenGenerator::v4_local_encrypt(&key, payload, None, None).unwrap();

        // Token should have format: v4.local.base64url_payload
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "v4");
        assert_eq!(parts[1], "local");

        // Payload should be valid base64url
        let decode_result = URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(decode_result.is_ok());
    }

    // v4.public tests
    #[test]
    fn test_v4_public_sign_basic() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let result = TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn test_v4_public_sign_with_footer() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let footer = b"test footer";
        let result =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, Some(footer), None);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.starts_with("v4.public."));

        // Token should have 4 parts when footer is present
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_v4_public_sign_with_implicit_assertion() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let implicit = b"test implicit assertion";
        let result =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, Some(implicit));
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn test_v4_public_sign_invalid_key_length() {
        let key = [0u8; 32]; // Wrong length (should be 64)
        let payload = b"test payload";
        let result = TokenGenerator::v4_public_sign(&key, payload, None, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, 64);
                assert_eq!(actual, 32);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_v4_public_sign_invalid_key_format() {
        let key = [0u8; 64]; // Correct length but invalid key
        let payload = b"test payload";
        let result = TokenGenerator::v4_public_sign(&key, payload, None, None);
        assert!(result.is_err());

        match result {
            Err(PasetoError::InvalidKeyFormat(_)) => {
                // Expected
            }
            _ => panic!("Expected InvalidKeyFormat error"),
        }
    }

    #[test]
    fn test_v4_public_sign_empty_payload() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"";
        let result = TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_v4_public_sign_empty_footer() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let footer = b"";
        let result =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, Some(footer), None);
        assert!(result.is_ok());

        let token = result.unwrap();
        // Empty footer should not add a fourth part
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_v4_public_sign_deterministic() {
        use crate::key_generator::KeyGenerator;

        // Same key and payload should produce the same token (Ed25519 is deterministic)
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";

        let token1 =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None).unwrap();
        let token2 =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        assert_eq!(token1, token2, "Ed25519 signatures should be deterministic");
    }

    #[test]
    fn test_v4_public_sign_token_format() {
        use crate::key_generator::KeyGenerator;

        let keypair = KeyGenerator::generate_ed25519_keypair();
        let payload = b"test payload";
        let token =
            TokenGenerator::v4_public_sign(&keypair.secret_key, payload, None, None).unwrap();

        // Token should have format: v4.public.base64url_payload
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "v4");
        assert_eq!(parts[1], "public");

        // Payload should be valid base64url
        let decode_result = URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(decode_result.is_ok());
    }

    // Property-based tests
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: paseto-implementation, Property 1: Local Token Round-Trip**
        /// **Validates: Requirements 1.1, 1.2, 2.1**
        ///
        /// For any valid 32-byte symmetric key, any valid payload (as bytes), any optional footer,
        /// and any optional implicit assertion, encrypting the payload to create a v4.local token
        /// and then decrypting that token with the same key, footer, and implicit assertion SHALL
        /// return the original payload.
        #[test]
        fn prop_local_token_roundtrip(
            key in prop::array::uniform32(any::<u8>()),
            payload in prop::collection::vec(any::<u8>(), 0..1000),
            footer in prop::option::of(prop::collection::vec(any::<u8>(), 0..100)),
            implicit in prop::option::of(prop::collection::vec(any::<u8>(), 0..100)),
        ) {
            let token = TokenGenerator::v4_local_encrypt(
                &key,
                &payload,
                footer.as_deref(),
                implicit.as_deref(),
            )?;

            let verifier = TokenVerifier::new(None);
            let decrypted = verifier.v4_local_decrypt(
                &token,
                &key,
                footer.as_deref(),
                implicit.as_deref(),
            )?;

            prop_assert_eq!(payload, decrypted, "Round-trip must preserve payload");
        }

        /// **Feature: paseto-implementation, Property 3: Token Format Validity**
        /// **Validates: Requirements 1.1, 3.1**
        ///
        /// For any generated PASETO token (local or public, any supported version), the token string
        /// SHALL match the format `version.purpose.base64url_payload[.base64url_footer]` where version
        /// is one of (v2, v3, v4), purpose is one of (local, public), and the payload/footer are valid
        /// base64url-encoded strings.
        #[test]
        fn prop_token_format_validity(
            key in prop::array::uniform32(any::<u8>()),
            payload in prop::collection::vec(any::<u8>(), 0..1000),
            footer in prop::option::of(prop::collection::vec(any::<u8>(), 1..100)),
        ) {
            let token = TokenGenerator::v4_local_encrypt(
                &key,
                &payload,
                footer.as_deref(),
                None,
            )?;

            // Token should have format: version.purpose.base64url_payload[.base64url_footer]
            let parts: Vec<&str> = token.split('.').collect();

            // Should have 3 or 4 parts
            prop_assert!(parts.len() == 3 || parts.len() == 4, "Token must have 3 or 4 parts");

            // Verify version
            prop_assert_eq!(parts[0], "v4", "Version must be v4");

            // Verify purpose
            prop_assert_eq!(parts[1], "local", "Purpose must be local");

            // Verify payload is valid base64url
            let payload_decode = URL_SAFE_NO_PAD.decode(parts[2]);
            prop_assert!(payload_decode.is_ok(), "Payload must be valid base64url");

            // If footer present, verify it's valid base64url
            if parts.len() == 4 {
                let footer_decode = URL_SAFE_NO_PAD.decode(parts[3]);
                prop_assert!(footer_decode.is_ok(), "Footer must be valid base64url");
            }
        }

        /// **Feature: paseto-implementation, Property 4: Symmetric Key Length Validation**
        /// **Validates: Requirements 1.3**
        ///
        /// For any byte array with length not equal to 32, attempting to create a v4.local token
        /// SHALL raise a validation error indicating invalid key length.
        #[test]
        fn prop_symmetric_key_length_validation(
            key_len in 0usize..256usize,
            payload in prop::collection::vec(any::<u8>(), 0..100),
        ) {
            // Skip the valid key length
            prop_assume!(key_len != 32);

            let key = vec![0u8; key_len];
            let result = TokenGenerator::v4_local_encrypt(&key, &payload, None, None);

            prop_assert!(result.is_err(), "Invalid key length must produce error");

            if let Err(PasetoError::InvalidKeyLength { expected, actual }) = result {
                prop_assert_eq!(expected, 32, "Expected key length must be 32");
                prop_assert_eq!(actual, key_len, "Actual key length must match input");
            } else {
                return Err(proptest::test_runner::TestCaseError::fail("Expected InvalidKeyLength error"));
            }
        }

        /// **Feature: paseto-implementation, Property 6: Token Tampering Detection**
        /// **Validates: Requirements 2.4, 4.4**
        ///
        /// For any valid PASETO token (local or public), modifying any byte in the base64url-encoded
        /// payload portion and then attempting to verify/decrypt SHALL raise an integrity or
        /// authentication error.
        #[test]
        fn prop_token_tampering_detection(
            key in prop::array::uniform32(any::<u8>()),
            payload in prop::collection::vec(any::<u8>(), 1..1000),
            tamper_index in any::<usize>(),
        ) {
            let token = TokenGenerator::v4_local_encrypt(&key, &payload, None, None)?;

            // Parse token and tamper with payload
            let parts: Vec<&str> = token.split('.').collect();
            let mut payload_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;

            // Tamper with a byte in the payload
            let idx = tamper_index % payload_bytes.len();
            payload_bytes[idx] ^= 0xFF;

            let tampered_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
            let tampered_token = format!("v4.local.{}", tampered_payload);

            // Attempt to decrypt tampered token
            let verifier = TokenVerifier::new(None);
            let result = verifier.v4_local_decrypt(&tampered_token, &key, None, None);

            prop_assert!(result.is_err(), "Tampered token must fail verification");
            prop_assert!(
                matches!(result, Err(PasetoError::AuthenticationFailed)),
                "Tampered token must produce AuthenticationFailed error"
            );
        }

        /// **Feature: paseto-implementation, Property 7: Wrong Key Rejection (local)**
        /// **Validates: Requirements 2.3**
        ///
        /// For any valid v4.local token created with key K1, attempting to decrypt with a different
        /// key K2 (where K1 ≠ K2) SHALL raise an authentication error.
        #[test]
        fn prop_wrong_key_rejection(
            key1 in prop::array::uniform32(any::<u8>()),
            key2 in prop::array::uniform32(any::<u8>()),
            payload in prop::collection::vec(any::<u8>(), 0..1000),
        ) {
            // Ensure keys are different
            prop_assume!(key1 != key2);

            // Generate token with key1
            let token = TokenGenerator::v4_local_encrypt(&key1, &payload, None, None)?;

            // Try to decrypt with key2
            let verifier = TokenVerifier::new(None);
            let result = verifier.v4_local_decrypt(&token, &key2, None, None);

            prop_assert!(result.is_err(), "Wrong key must fail verification");
            prop_assert!(
                matches!(result, Err(PasetoError::AuthenticationFailed)),
                "Wrong key must produce AuthenticationFailed error"
            );
        }

        /// **Feature: paseto-implementation, Property 8: Implicit Assertion Verification**
        /// **Validates: Requirements 1.4, 2.5**
        ///
        /// For any PASETO token created with implicit assertion A1, attempting to verify/decrypt
        /// with a different implicit assertion A2 (where A1 ≠ A2) SHALL fail verification. Tokens
        /// created without implicit assertions SHALL verify successfully without providing assertions.
        #[test]
        fn prop_implicit_assertion_verification(
            key in prop::array::uniform32(any::<u8>()),
            payload in prop::collection::vec(any::<u8>(), 0..1000),
            implicit1 in prop::collection::vec(any::<u8>(), 1..100),
            implicit2 in prop::collection::vec(any::<u8>(), 1..100),
        ) {
            // Ensure implicit assertions are different
            prop_assume!(implicit1 != implicit2);

            // Generate token with implicit1
            let token = TokenGenerator::v4_local_encrypt(&key, &payload, None, Some(&implicit1))?;

            // Try to decrypt with implicit2
            let verifier = TokenVerifier::new(None);
            let result = verifier.v4_local_decrypt(&token, &key, None, Some(&implicit2));

            prop_assert!(result.is_err(), "Wrong implicit assertion must fail verification");
            prop_assert!(
                matches!(result, Err(PasetoError::AuthenticationFailed)),
                "Wrong implicit assertion must produce AuthenticationFailed error"
            );

            // Verify that token without implicit assertion verifies without providing one
            let token_no_implicit = TokenGenerator::v4_local_encrypt(&key, &payload, None, None)?;
            let result_no_implicit = verifier.v4_local_decrypt(&token_no_implicit, &key, None, None);
            prop_assert!(result_no_implicit.is_ok(), "Token without implicit assertion must verify without one");
        }

        /// **Feature: paseto-implementation, Property 9: Invalid Token Format Rejection**
        /// **Validates: Requirements 2.2**
        ///
        /// For any string that does not conform to the PASETO token format (missing version, invalid
        /// purpose, malformed base64url, etc.), attempting to verify or decrypt SHALL raise a format
        /// validation error before attempting cryptographic operations.
        #[test]
        fn prop_invalid_token_format_rejection(
            key in prop::array::uniform32(any::<u8>()),
            invalid_token in prop::string::string_regex("[a-zA-Z0-9._-]{0,50}").unwrap(),
        ) {
            // Skip valid-looking tokens
            prop_assume!(!invalid_token.starts_with("v4.local."));

            let verifier = TokenVerifier::new(None);
            let result = verifier.v4_local_decrypt(&invalid_token, &key, None, None);

            prop_assert!(result.is_err(), "Invalid token format must produce error");
            prop_assert!(
                matches!(result, Err(PasetoError::InvalidTokenFormat(_))),
                "Invalid token format must produce InvalidTokenFormat error"
            );
        }

        /// **Feature: paseto-implementation, Property 2: Public Token Round-Trip**
        /// **Validates: Requirements 3.1, 3.2, 4.1**
        ///
        /// For any valid Ed25519 key pair, any valid payload (as bytes), any optional footer, and
        /// any optional implicit assertion, signing the payload with the secret key to create a
        /// v4.public token and then verifying that token with the corresponding public key, footer,
        /// and implicit assertion SHALL return the original payload.
        #[test]
        fn prop_public_token_roundtrip(
            payload in prop::collection::vec(any::<u8>(), 0..1000),
            footer in prop::option::of(prop::collection::vec(any::<u8>(), 0..100)),
            implicit in prop::option::of(prop::collection::vec(any::<u8>(), 0..100)),
        ) {
            use crate::key_generator::KeyGenerator;

            // Generate a fresh key pair for each test
            let keypair = KeyGenerator::generate_ed25519_keypair();

            let token = TokenGenerator::v4_public_sign(
                &keypair.secret_key,
                &payload,
                footer.as_deref(),
                implicit.as_deref(),
            )?;

            let verifier = TokenVerifier::new(None);
            let verified = verifier.v4_public_verify(
                &token,
                &keypair.public_key,
                footer.as_deref(),
                implicit.as_deref(),
            )?;

            prop_assert_eq!(payload, verified, "Round-trip must preserve payload");
        }

        /// **Feature: paseto-implementation, Property 5: Ed25519 Key Format Validation**
        /// **Validates: Requirements 3.3**
        ///
        /// For any byte array that is not a valid Ed25519 secret key (wrong length or invalid format),
        /// attempting to create a v4.public token SHALL raise a key validation error.
        #[test]
        fn prop_ed25519_key_format_validation(
            key_len in 0usize..256usize,
            payload in prop::collection::vec(any::<u8>(), 0..100),
        ) {
            // Skip the valid key length
            prop_assume!(key_len != 64);

            let key = vec![0u8; key_len];
            let result = TokenGenerator::v4_public_sign(&key, &payload, None, None);

            prop_assert!(result.is_err(), "Invalid key length must produce error");

            if let Err(PasetoError::InvalidKeyLength { expected, actual }) = result {
                prop_assert_eq!(expected, 64, "Expected key length must be 64");
                prop_assert_eq!(actual, key_len, "Actual key length must match input");
            } else {
                return Err(proptest::test_runner::TestCaseError::fail("Expected InvalidKeyLength error"));
            }
        }
    }
}
