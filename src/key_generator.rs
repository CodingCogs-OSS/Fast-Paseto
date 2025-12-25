use crate::error::PasetoError;
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};

/// Ed25519 key pair for v4.public tokens
#[derive(Debug, Clone)]
pub struct Ed25519KeyPair {
    /// Ed25519 secret key (64 bytes)
    pub secret_key: [u8; 64],
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
}

/// Cryptographic key generation
pub struct KeyGenerator;

impl KeyGenerator {
    /// Generate a 32-byte symmetric key for local tokens
    ///
    /// Uses a cryptographically secure random number generator (OsRng)
    /// to generate a 32-byte key suitable for v4.local PASETO tokens.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing cryptographically secure random bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyGenerator;
    ///
    /// let key = KeyGenerator::generate_symmetric_key();
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn generate_symmetric_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Generate an Ed25519 key pair for v4.public tokens
    ///
    /// Uses a cryptographically secure random number generator (OsRng)
    /// to generate a valid Ed25519 key pair suitable for v4.public PASETO tokens.
    ///
    /// # Returns
    ///
    /// An `Ed25519KeyPair` containing:
    /// - `secret_key`: 64-byte Ed25519 secret key
    /// - `public_key`: 32-byte Ed25519 public key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyGenerator;
    ///
    /// let keypair = KeyGenerator::generate_ed25519_keypair();
    /// assert_eq!(keypair.secret_key.len(), 64);
    /// assert_eq!(keypair.public_key.len(), 32);
    /// ```
    pub fn generate_ed25519_keypair() -> Ed25519KeyPair {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Ed25519KeyPair {
            secret_key: signing_key.to_keypair_bytes(),
            public_key: verifying_key.to_bytes(),
        }
    }

    /// Encode key bytes to base64 string
    ///
    /// Converts key bytes to a base64-encoded string for serialization
    /// or storage purposes. Uses standard base64 encoding.
    ///
    /// # Arguments
    ///
    /// * `key` - Key bytes to encode
    ///
    /// # Returns
    ///
    /// A base64-encoded string representation of the key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyGenerator;
    ///
    /// let key = KeyGenerator::generate_symmetric_key();
    /// let encoded = KeyGenerator::key_to_base64(&key);
    /// assert!(!encoded.is_empty());
    /// ```
    pub fn key_to_base64(key: &[u8]) -> String {
        general_purpose::STANDARD.encode(key)
    }

    /// Decode base64 string back to key bytes
    ///
    /// Converts a base64-encoded string back to key bytes. Returns an error
    /// if the input is not valid base64.
    ///
    /// # Arguments
    ///
    /// * `encoded` - Base64-encoded key string
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, PasetoError>` - Decoded key bytes or error
    ///
    /// # Errors
    ///
    /// Returns `PasetoError::InvalidKeyFormat` if the input is not valid base64
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fast_paseto::KeyGenerator;
    ///
    /// let key = KeyGenerator::generate_symmetric_key();
    /// let encoded = KeyGenerator::key_to_base64(&key);
    /// let decoded = KeyGenerator::key_from_base64(&encoded).unwrap();
    /// assert_eq!(key.to_vec(), decoded);
    /// ```
    pub fn key_from_base64(encoded: &str) -> Result<Vec<u8>, PasetoError> {
        general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| PasetoError::InvalidKeyFormat(format!("Invalid base64: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, VerifyingKey};
    use proptest::prelude::*;

    #[test]
    fn test_generate_symmetric_key_length() {
        let key = KeyGenerator::generate_symmetric_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_generate_symmetric_key_randomness() {
        // Generate multiple keys and ensure they're different
        let key1 = KeyGenerator::generate_symmetric_key();
        let key2 = KeyGenerator::generate_symmetric_key();
        let key3 = KeyGenerator::generate_symmetric_key();

        // It's extremely unlikely that three 32-byte random keys would be identical
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_generate_symmetric_key_non_zero() {
        // Ensure the key isn't all zeros (extremely unlikely but good to check)
        let key = KeyGenerator::generate_symmetric_key();
        let all_zeros = [0u8; 32];
        assert_ne!(key, all_zeros);
    }

    #[test]
    fn test_generate_ed25519_keypair_length() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        assert_eq!(keypair.secret_key.len(), 64);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_generate_ed25519_keypair_randomness() {
        // Generate multiple key pairs and ensure they're different
        let keypair1 = KeyGenerator::generate_ed25519_keypair();
        let keypair2 = KeyGenerator::generate_ed25519_keypair();
        let keypair3 = KeyGenerator::generate_ed25519_keypair();

        // It's extremely unlikely that three Ed25519 key pairs would be identical
        assert_ne!(keypair1.secret_key, keypair2.secret_key);
        assert_ne!(keypair2.secret_key, keypair3.secret_key);
        assert_ne!(keypair1.secret_key, keypair3.secret_key);

        assert_ne!(keypair1.public_key, keypair2.public_key);
        assert_ne!(keypair2.public_key, keypair3.public_key);
        assert_ne!(keypair1.public_key, keypair3.public_key);
    }

    #[test]
    fn test_generate_ed25519_keypair_non_zero() {
        // Ensure the keys aren't all zeros (extremely unlikely but good to check)
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let all_zeros_64 = [0u8; 64];
        let all_zeros_32 = [0u8; 32];
        assert_ne!(keypair.secret_key, all_zeros_64);
        assert_ne!(keypair.public_key, all_zeros_32);
    }

    #[test]
    fn test_ed25519_keypair_validity() {
        // Test that the generated key pair can be used for signing and verification
        let keypair = KeyGenerator::generate_ed25519_keypair();

        // Reconstruct the signing key from the secret key bytes
        let signing_key = SigningKey::from_keypair_bytes(&keypair.secret_key)
            .expect("Generated secret key should be valid");

        // Reconstruct the verifying key from the public key bytes
        let verifying_key = VerifyingKey::from_bytes(&keypair.public_key)
            .expect("Generated public key should be valid");

        // Verify that the public key from the signing key matches our stored public key
        assert_eq!(signing_key.verifying_key().to_bytes(), keypair.public_key);

        // Test signing and verification with a simple message
        let message = b"test message for Ed25519 key pair validation";
        let signature = signing_key.sign(message);

        // Verification should succeed
        verifying_key
            .verify_strict(message, &signature)
            .expect("Signature verification should succeed with matching key pair");
    }

    #[test]
    fn test_key_to_base64_symmetric() {
        let key = KeyGenerator::generate_symmetric_key();
        let encoded = KeyGenerator::key_to_base64(&key);

        // Base64 encoded 32-byte key should be 44 characters (32 * 4/3 rounded up)
        assert_eq!(encoded.len(), 44);

        // Should contain only valid base64 characters
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        );
    }

    #[test]
    fn test_key_to_base64_ed25519_secret() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let encoded = KeyGenerator::key_to_base64(&keypair.secret_key);

        // Base64 encoded 64-byte key should be 88 characters
        assert_eq!(encoded.len(), 88);

        // Should contain only valid base64 characters
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        );
    }

    #[test]
    fn test_key_to_base64_ed25519_public() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let encoded = KeyGenerator::key_to_base64(&keypair.public_key);

        // Base64 encoded 32-byte key should be 44 characters
        assert_eq!(encoded.len(), 44);

        // Should contain only valid base64 characters
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        );
    }

    #[test]
    fn test_key_from_base64_symmetric_roundtrip() {
        let original_key = KeyGenerator::generate_symmetric_key();
        let encoded = KeyGenerator::key_to_base64(&original_key);
        let decoded = KeyGenerator::key_from_base64(&encoded)
            .expect("Decoding should succeed for valid base64");

        assert_eq!(original_key.to_vec(), decoded);
    }

    #[test]
    fn test_key_from_base64_ed25519_secret_roundtrip() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let encoded = KeyGenerator::key_to_base64(&keypair.secret_key);
        let decoded = KeyGenerator::key_from_base64(&encoded)
            .expect("Decoding should succeed for valid base64");

        assert_eq!(keypair.secret_key.to_vec(), decoded);
    }

    #[test]
    fn test_key_from_base64_ed25519_public_roundtrip() {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let encoded = KeyGenerator::key_to_base64(&keypair.public_key);
        let decoded = KeyGenerator::key_from_base64(&encoded)
            .expect("Decoding should succeed for valid base64");

        assert_eq!(keypair.public_key.to_vec(), decoded);
    }

    #[test]
    fn test_key_from_base64_invalid_input() {
        // Test with invalid base64 characters
        let result = KeyGenerator::key_from_base64("invalid@base64!");
        assert!(result.is_err());

        if let Err(PasetoError::InvalidKeyFormat(msg)) = result {
            assert!(msg.contains("Invalid base64"));
        } else {
            panic!("Expected InvalidKeyFormat error");
        }
    }

    #[test]
    fn test_key_from_base64_invalid_padding() {
        // Test with incorrect padding
        let result = KeyGenerator::key_from_base64("SGVsbG8gV29ybGQ"); // Missing padding
        assert!(result.is_err());

        if let Err(PasetoError::InvalidKeyFormat(msg)) = result {
            assert!(msg.contains("Invalid base64"));
        } else {
            panic!("Expected InvalidKeyFormat error");
        }
    }

    #[test]
    fn test_key_from_base64_empty_string() {
        let result = KeyGenerator::key_from_base64("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_key_to_base64_empty_key() {
        let empty_key: &[u8] = &[];
        let encoded = KeyGenerator::key_to_base64(empty_key);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_base64_roundtrip_various_sizes() {
        // Test with various key sizes to ensure robustness
        let test_sizes = [1, 16, 32, 64, 128];

        for size in test_sizes {
            let mut key = vec![0u8; size];
            OsRng.fill_bytes(&mut key);

            let encoded = KeyGenerator::key_to_base64(&key);
            let decoded = KeyGenerator::key_from_base64(&encoded)
                .expect(&format!("Decoding should succeed for size {}", size));

            assert_eq!(key, decoded, "Round-trip failed for size {}", size);
        }
    }

    #[test]
    fn test_base64_deterministic() {
        // Test that encoding the same key multiple times produces the same result
        let key = KeyGenerator::generate_symmetric_key();
        let encoded1 = KeyGenerator::key_to_base64(&key);
        let encoded2 = KeyGenerator::key_to_base64(&key);

        assert_eq!(encoded1, encoded2);
    }

    // Property-based tests
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 10: Symmetric Key Generation Size
        /// For any call to generate a symmetric key, the returned key SHALL be exactly 32 bytes in length.
        /// **Validates: Requirements 5.1**
        #[test]
        fn prop_symmetric_key_generation_size(_dummy in 0u8..255u8) {
            // Feature: paseto-implementation, Property 10: Symmetric Key Generation Size
            let key = KeyGenerator::generate_symmetric_key();
            prop_assert_eq!(key.len(), 32, "Generated symmetric key must be exactly 32 bytes");
        }

        /// Property 12: Base64 Key Round-Trip
        /// For any valid key (symmetric or asymmetric component), encoding to base64 and then decoding from base64 SHALL return a byte-identical key.
        /// **Validates: Requirements 5.5, 5.6**
        #[test]
        fn prop_base64_key_round_trip(key_bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            // Feature: paseto-implementation, Property 12: Base64 Key Round-Trip
            let encoded = KeyGenerator::key_to_base64(&key_bytes);
            let decoded = KeyGenerator::key_from_base64(&encoded)
                .expect("Decoding valid base64 should always succeed");
            prop_assert_eq!(key_bytes, decoded, "Round-trip encoding/decoding must preserve key bytes");
        }

        /// **Feature: paseto-implementation, Property 11: Ed25519 Key Pair Validity**
        /// **Validates: Requirements 5.2**
        ///
        /// For any generated Ed25519 key pair, the secret key and public key SHALL be usable to sign
        /// and verify a token respectively, and the round-trip property (Property 2) SHALL hold.
        #[test]
        fn prop_ed25519_keypair_validity(_dummy in 0u8..255u8) {
            use crate::token_generator::TokenGenerator;
            use crate::token_verifier::TokenVerifier;

            // Generate a key pair
            let keypair = KeyGenerator::generate_ed25519_keypair();

            // Create a test payload
            let payload = b"test payload for key pair validity";

            // Sign with the secret key
            let token = TokenGenerator::v4_public_sign(
                &keypair.secret_key,
                payload,
                None,
                None,
            ).expect("Signing with generated key pair should succeed");

            // Verify with the public key
            let verifier = TokenVerifier::new(None);
            let verified = verifier.v4_public_verify(
                &token,
                &keypair.public_key,
                None,
                None,
            ).expect("Verification with generated key pair should succeed");

            prop_assert_eq!(
                payload.to_vec(),
                verified,
                "Generated key pair must be usable for signing and verification"
            );
        }
    }
}
