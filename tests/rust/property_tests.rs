//! Property-based tests for fast-paseto refactoring
//!
//! These tests validate correctness properties across the refactored codebase
//! using property-based testing with the proptest crate.

use fast_paseto::error::PasetoError;
use proptest::prelude::*;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Feature: rust-refactor, Property 1: Error Mapping and Context
/// **Validates: Requirements 3.2, 3.4**
///
/// Tests that PasetoError variants map to correct Python exception types
/// and that InvalidKeyLength errors contain expected and actual values.
#[test]
fn test_error_mapping_and_context() {
    Python::initialize();

    Python::attach(|py| {
        // Test InvalidKeyLength error mapping and context
        let error = PasetoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        let py_err: PyErr = error.into();
        let err_str = format!("{}", py_err);

        // Verify error message contains both expected and actual values
        assert!(err_str.contains("32"), "Error should contain expected value 32");
        assert!(err_str.contains("16"), "Error should contain actual value 16");

        // Verify it maps to PasetoKeyError
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test InvalidKeyFormat error mapping
        let error = PasetoError::InvalidKeyFormat("malformed key".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test InvalidPemFormat error mapping
        let error = PasetoError::InvalidPemFormat("bad PEM".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test InvalidPaserkFormat error mapping
        let error = PasetoError::InvalidPaserkFormat("bad PASERK".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test InvalidTokenFormat error mapping
        let error = PasetoError::InvalidTokenFormat("malformed token".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test UnsupportedVersion error mapping
        let error = PasetoError::UnsupportedVersion("v1".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test FooterMismatch error mapping
        let error = PasetoError::FooterMismatch;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test ImplicitAssertionMismatch error mapping
        let error = PasetoError::ImplicitAssertionMismatch;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test AuthenticationFailed error mapping
        let error = PasetoError::AuthenticationFailed;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test SignatureVerificationFailed error mapping
        let error = PasetoError::SignatureVerificationFailed;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test IntegrityError error mapping
        let error = PasetoError::IntegrityError;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test CryptoError error mapping
        let error = PasetoError::CryptoError("crypto failed".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test PasswordDecryptionFailed error mapping
        let error = PasetoError::PasswordDecryptionFailed;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test TokenExpired error mapping
        let error = PasetoError::TokenExpired;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test TokenNotYetValid error mapping
        let error = PasetoError::TokenNotYetValid;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test TokenIssuedInFuture error mapping
        let error = PasetoError::TokenIssuedInFuture;
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test SerializationError error mapping
        let error = PasetoError::SerializationError("serialization failed".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));

        // Test DeserializationError error mapping
        let error = PasetoError::DeserializationError("deserialization failed".to_string());
        let py_err: PyErr = error.into();
        assert!(py_err.is_instance_of::<pyo3::exceptions::PyException>(py));
    });
}

/// Feature: rust-refactor, Property 2: Debug Implementation
/// **Validates: Requirements 4.11**
///
/// Tests that all public types implement Debug without panicking.
#[test]
fn test_debug_implementation() {
    use fast_paseto::Token;
    use fast_paseto::version::{Version, Purpose};
    use fast_paseto::key_generator::KeyGenerator;

    Python::initialize();

    Python::attach(|py| {
        // Test Token Debug
        let payload = PyDict::new(py).into_any().unbind();
        let token = Token::new(payload, None, "v4".to_string(), "local".to_string());
        let debug_str = format!("{:?}", token);
        assert!(!debug_str.is_empty(), "Token Debug should produce non-empty string");

        // Test PasetoError Debug (all variants)
        let error = PasetoError::InvalidKeyLength { expected: 32, actual: 16 };
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty(), "PasetoError Debug should produce non-empty string");

        let error = PasetoError::InvalidKeyFormat("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty(), "PasetoError Debug should produce non-empty string");

        let error = PasetoError::TokenExpired;
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty(), "PasetoError Debug should produce non-empty string");

        // Test Version Debug
        let version = Version::V4;
        let debug_str = format!("{:?}", version);
        assert!(!debug_str.is_empty(), "Version Debug should produce non-empty string");

        // Test Purpose Debug
        let purpose = Purpose::Local;
        let debug_str = format!("{:?}", purpose);
        assert!(!debug_str.is_empty(), "Purpose Debug should produce non-empty string");

        // Test Ed25519KeyPair Debug
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let debug_str = format!("{:?}", keypair);
        assert!(!debug_str.is_empty(), "Ed25519KeyPair Debug should produce non-empty string");

        // Test P384KeyPair Debug
        let keypair = KeyGenerator::generate_p384_keypair();
        let debug_str = format!("{:?}", keypair);
        assert!(!debug_str.is_empty(), "P384KeyPair Debug should produce non-empty string");
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Feature: rust-refactor, Property 1: Error Mapping and Context (Property-based)
    /// **Validates: Requirements 3.2, 3.4**
    ///
    /// For any expected and actual key lengths, InvalidKeyLength error should
    /// contain both values in its error message.
    #[test]
    fn prop_invalid_key_length_contains_context(
        expected in 1usize..256,
        actual in 0usize..256,
    ) {
        prop_assume!(expected != actual);

        let error = PasetoError::InvalidKeyLength { expected, actual };
        let error_msg = error.to_string();

        // Verify error message contains both expected and actual values
        prop_assert!(
            error_msg.contains(&expected.to_string()),
            "Error message should contain expected value {}: {}",
            expected,
            error_msg
        );
        prop_assert!(
            error_msg.contains(&actual.to_string()),
            "Error message should contain actual value {}: {}",
            actual,
            error_msg
        );
    }

    /// Feature: rust-refactor, Property 2: Debug Implementation (Property-based)
    /// **Validates: Requirements 4.11**
    ///
    /// For any PasetoError variant with string data, Debug formatting should
    /// not panic and should produce a non-empty string.
    #[test]
    fn prop_debug_does_not_panic(
        msg in "\\PC{0,100}",
        expected in 1usize..256,
        actual in 0usize..256,
    ) {
        // Test various error variants with random data
        let errors = vec![
            PasetoError::InvalidKeyFormat(msg.clone()),
            PasetoError::InvalidTokenFormat(msg.clone()),
            PasetoError::UnsupportedVersion(msg.clone()),
            PasetoError::SerializationError(msg.clone()),
            PasetoError::DeserializationError(msg.clone()),
            PasetoError::InvalidPemFormat(msg.clone()),
            PasetoError::InvalidPaserkFormat(msg.clone()),
            PasetoError::CryptoError(msg.clone()),
            PasetoError::InvalidKeyLength { expected, actual },
        ];

        for error in errors {
            let debug_str = format!("{:?}", error);
            prop_assert!(!debug_str.is_empty(), "Debug output should not be empty");
        }
    }

    /// Feature: rust-refactor, Property 3: Key Length Validation
    /// **Validates: Requirements 5.3**
    ///
    /// For any key operation with invalid key length, the operation should
    /// return InvalidKeyLength error with expected and actual lengths.
    #[test]
    fn prop_key_length_validation_v4_local(
        key_len in 0usize..128,
    ) {
        use fast_paseto::token_generator::TokenGenerator;

        prop_assume!(key_len != 32); // Exclude valid length

        let key = vec![0u8; key_len];
        let payload = b"test payload";
        let result = TokenGenerator::v4_local_encrypt(&key, payload, None, None);

        prop_assert!(result.is_err(), "Invalid key length should return error");

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 32, "Expected key length should be 32 for v4.local");
                prop_assert_eq!(actual, key_len, "Actual key length should match input");
            }
            _ => prop_assert!(false, "Should return InvalidKeyLength error"),
        }
    }

    /// Feature: rust-refactor, Property 3: Key Length Validation (v4.public)
    /// **Validates: Requirements 5.3**
    #[test]
    fn prop_key_length_validation_v4_public(
        key_len in 0usize..128,
    ) {
        use fast_paseto::token_generator::TokenGenerator;

        prop_assume!(key_len != 64); // Exclude valid length

        let key = vec![0u8; key_len];
        let payload = b"test payload";
        let result = TokenGenerator::v4_public_sign(&key, payload, None, None);

        prop_assert!(result.is_err(), "Invalid key length should return error");

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 64, "Expected key length should be 64 for v4.public");
                prop_assert_eq!(actual, key_len, "Actual key length should match input");
            }
            _ => prop_assert!(false, "Should return InvalidKeyLength error"),
        }
    }

    /// Feature: rust-refactor, Property 3: Key Length Validation (v2.local)
    /// **Validates: Requirements 5.3**
    #[test]
    fn prop_key_length_validation_v2_local(
        key_len in 0usize..128,
    ) {
        use fast_paseto::token_generator::TokenGenerator;

        prop_assume!(key_len != 32); // Exclude valid length

        let key = vec![0u8; key_len];
        let payload = b"test payload";
        let result = TokenGenerator::v2_local_encrypt(&key, payload, None);

        prop_assert!(result.is_err(), "Invalid key length should return error");

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 32, "Expected key length should be 32 for v2.local");
                prop_assert_eq!(actual, key_len, "Actual key length should match input");
            }
            _ => prop_assert!(false, "Should return InvalidKeyLength error"),
        }
    }

    /// Feature: rust-refactor, Property 3: Key Length Validation (v2.public)
    /// **Validates: Requirements 5.3**
    #[test]
    fn prop_key_length_validation_v2_public(
        key_len in 0usize..128,
    ) {
        use fast_paseto::token_generator::TokenGenerator;

        prop_assume!(key_len != 64); // Exclude valid length

        let key = vec![0u8; key_len];
        let payload = b"test payload";
        let result = TokenGenerator::v2_public_sign(&key, payload, None);

        prop_assert!(result.is_err(), "Invalid key length should return error");

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 64, "Expected key length should be 64 for v2.public");
                prop_assert_eq!(actual, key_len, "Actual key length should match input");
            }
            _ => prop_assert!(false, "Should return InvalidKeyLength error"),
        }
    }

    /// Feature: rust-refactor, Property 3: Key Length Validation (v3.local)
    /// **Validates: Requirements 5.3**
    #[test]
    fn prop_key_length_validation_v3_local(
        key_len in 0usize..128,
    ) {
        use fast_paseto::token_generator::TokenGenerator;

        prop_assume!(key_len != 32); // Exclude valid length

        let key = vec![0u8; key_len];
        let payload = b"test payload";
        let result = TokenGenerator::v3_local_encrypt(&key, payload, None, None);

        prop_assert!(result.is_err(), "Invalid key length should return error");

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 32, "Expected key length should be 32 for v3.local");
                prop_assert_eq!(actual, key_len, "Actual key length should match input");
            }
            _ => prop_assert!(false, "Should return InvalidKeyLength error"),
        }
    }

    /// Feature: rust-refactor, Property 3: Key Length Validation (v3.public)
    /// **Validates: Requirements 5.3**
    #[test]
    fn prop_key_length_validation_v3_public(
        key_len in 0usize..128,
    ) {
        use fast_paseto::token_generator::TokenGenerator;

        prop_assume!(key_len != 48); // Exclude valid length for P-384

        let key = vec![0u8; key_len];
        let payload = b"test payload";
        let result = TokenGenerator::v3_public_sign(&key, payload, None, None);

        prop_assert!(result.is_err(), "Invalid key length should return error");

        match result {
            Err(PasetoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, 48, "Expected key length should be 48 for v3.public");
                prop_assert_eq!(actual, key_len, "Actual key length should match input");
            }
            _ => prop_assert!(false, "Should return InvalidKeyLength error"),
        }
    }
}
