use crate::error::PasetoError;
use base64::prelude::*;
use blake2::{Blake2b512, Digest};

/// PASERK key types for deserialization
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
}
