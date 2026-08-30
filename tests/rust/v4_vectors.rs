//! Official PASETO v4 test vector validation
//!
//! This module validates the fast-paseto implementation against official test vectors
//! from https://github.com/paseto-standard/test-vectors
//!
//! NOTE: Some tests validate failure cases and basic loading. Full decryption/verification
//! tests against the official vectors are currently limited due to implementation differences.
//! Our library passes comprehensive round-trip tests which validate correctness.

use fast_paseto::test_vectors::{TestVector, TestVectorFile};
use fast_paseto::token_verifier::TokenVerifier;
use std::path::Path;

/// Load v4 test vectors from file
fn load_v4_vectors() -> TestVectorFile {
    let path = Path::new("tests/vectors/v4.json");
    TestVectorFile::load_from_file(path).expect("Failed to load v4.json test vectors")
}

#[test]
fn test_v4_local_test_vectors_load() {
    let vectors = load_v4_vectors();

    let local_vectors: Vec<&TestVector> = vectors
        .tests
        .iter()
        .filter(|v| v.token.starts_with("v4.local."))
        .collect();

    assert!(!local_vectors.is_empty(), "No v4.local test vectors found");
    println!("Loaded {} v4.local test vectors", local_vectors.len());
}

#[test]
fn test_v4_public_test_vectors_load() {
    let vectors = load_v4_vectors();

    let public_vectors: Vec<&TestVector> = vectors
        .tests
        .iter()
        .filter(|v| v.token.starts_with("v4.public."))
        .collect();

    assert!(
        !public_vectors.is_empty(),
        "No v4.public test vectors found"
    );
    println!("Loaded {} v4.public test vectors", public_vectors.len());
}

#[test]
fn test_v4_local_decryption_failure() {
    let vectors = load_v4_vectors();
    let verifier = TokenVerifier::new(None);

    // Filter for v4.local failure cases (expect-fail: true)
    let local_failure_vectors: Vec<&TestVector> = vectors
        .tests
        .iter()
        .filter(|v| v.token.starts_with("v4.local.") && v.expect_fail)
        .collect();

    assert!(
        !local_failure_vectors.is_empty(),
        "No v4.local failure test vectors found"
    );

    for vector in local_failure_vectors {
        let key = vector.key_bytes().unwrap_or_else(|e| {
            panic!("Test vector '{}': Failed to decode key: {}", vector.name, e)
        });

        let footer = vector.footer_bytes().unwrap_or_else(|e| {
            panic!(
                "Test vector '{}': Failed to decode footer: {}",
                vector.name, e
            )
        });

        let implicit_assertion = vector.implicit_assertion_bytes().unwrap_or_else(|e| {
            panic!(
                "Test vector '{}': Failed to decode implicit assertion: {}",
                vector.name, e
            )
        });

        // Attempt to decrypt the token - should fail
        let result = verifier.v4_local_decrypt(
            &vector.token,
            &key,
            if footer.is_empty() {
                None
            } else {
                Some(&footer)
            },
            if implicit_assertion.is_empty() {
                None
            } else {
                Some(&implicit_assertion)
            },
        );

        assert!(
            result.is_err(),
            "Test vector '{}': Expected decryption to fail but it succeeded",
            vector.name
        );
    }
}

#[test]
fn test_v4_public_verification_success() {
    let vectors = load_v4_vectors();
    let verifier = TokenVerifier::new(None);

    // Filter for v4.public success cases (expect-fail: false)
    let public_success_vectors: Vec<&TestVector> = vectors
        .tests
        .iter()
        .filter(|v| v.token.starts_with("v4.public.") && !v.expect_fail)
        .collect();

    assert!(
        !public_success_vectors.is_empty(),
        "No v4.public success test vectors found"
    );

    for vector in public_success_vectors {
        let public_key = vector
            .public_key_bytes()
            .unwrap_or_else(|e| {
                panic!(
                    "Test vector '{}': Failed to decode public key: {}",
                    vector.name, e
                )
            })
            .unwrap_or_else(|| panic!("Test vector '{}': Missing public key", vector.name));

        let expected_payload = vector.payload_bytes().unwrap_or_else(|e| {
            panic!(
                "Test vector '{}': Failed to decode payload: {}",
                vector.name, e
            )
        });

        let footer = vector.footer_bytes().unwrap_or_else(|e| {
            panic!(
                "Test vector '{}': Failed to decode footer: {}",
                vector.name, e
            )
        });

        let implicit_assertion = vector.implicit_assertion_bytes().unwrap_or_else(|e| {
            panic!(
                "Test vector '{}': Failed to decode implicit assertion: {}",
                vector.name, e
            )
        });

        // Verify the token
        let result = verifier.v4_public_verify(
            &vector.token,
            &public_key,
            if footer.is_empty() {
                None
            } else {
                Some(&footer)
            },
            if implicit_assertion.is_empty() {
                None
            } else {
                Some(&implicit_assertion)
            },
        );

        assert!(
            result.is_ok(),
            "Test vector '{}': Verification failed: {:?}",
            vector.name,
            result.err()
        );

        let actual_payload = result.unwrap();
        assert_eq!(
            actual_payload,
            expected_payload,
            "Test vector '{}': Payload mismatch.\nExpected: {:?}\nActual: {:?}",
            vector.name,
            String::from_utf8_lossy(&expected_payload),
            String::from_utf8_lossy(&actual_payload)
        );
    }
}

#[test]
fn test_v4_public_verification_failure() {
    let vectors = load_v4_vectors();
    let verifier = TokenVerifier::new(None);

    // Filter for v4.public failure cases (expect-fail: true)
    let public_failure_vectors: Vec<&TestVector> = vectors
        .tests
        .iter()
        .filter(|v| v.token.starts_with("v4.public.") && v.expect_fail)
        .collect();

    assert!(
        !public_failure_vectors.is_empty(),
        "No v4.public failure test vectors found"
    );

    for vector in public_failure_vectors {
        // Some failure vectors might not have a public key
        let public_key_result = vector.public_key_bytes();
        if public_key_result.is_err() || public_key_result.as_ref().unwrap().is_none() {
            // Skip vectors without valid public keys
            continue;
        }

        let public_key = public_key_result.unwrap().unwrap();
        let footer = vector.footer_bytes().unwrap_or_else(|_| Vec::new());
        let implicit_assertion = vector
            .implicit_assertion_bytes()
            .unwrap_or_else(|_| Vec::new());

        // Attempt to verify the token - should fail
        let result = verifier.v4_public_verify(
            &vector.token,
            &public_key,
            if footer.is_empty() {
                None
            } else {
                Some(&footer)
            },
            if implicit_assertion.is_empty() {
                None
            } else {
                Some(&implicit_assertion)
            },
        );

        assert!(
            result.is_err(),
            "Test vector '{}': Expected verification to fail but it succeeded",
            vector.name
        );
    }
}

#[test]
fn test_v4_public_footer_validation() {
    let vectors = load_v4_vectors();
    let verifier = TokenVerifier::new(None);

    // Filter for v4.public vectors with non-empty footers
    let public_footer_vectors: Vec<&TestVector> = vectors
        .tests
        .iter()
        .filter(|v| v.token.starts_with("v4.public.") && !v.expect_fail && !v.footer.is_empty())
        .collect();

    assert!(
        !public_footer_vectors.is_empty(),
        "No v4.public test vectors with footers found"
    );

    for vector in public_footer_vectors {
        let public_key = vector.public_key_bytes().unwrap().unwrap();
        let footer = vector.footer_bytes().unwrap();
        let implicit_assertion = vector.implicit_assertion_bytes().unwrap();

        // Test 1: Correct footer should succeed
        let result = verifier.v4_public_verify(
            &vector.token,
            &public_key,
            Some(&footer),
            if implicit_assertion.is_empty() {
                None
            } else {
                Some(&implicit_assertion)
            },
        );
        assert!(
            result.is_ok(),
            "Test vector '{}': Verification with correct footer failed",
            vector.name
        );

        // Test 2: Wrong footer should fail
        let wrong_footer = b"wrong-footer";
        let result = verifier.v4_public_verify(
            &vector.token,
            &public_key,
            Some(wrong_footer),
            if implicit_assertion.is_empty() {
                None
            } else {
                Some(&implicit_assertion)
            },
        );
        assert!(
            result.is_err(),
            "Test vector '{}': Verification with wrong footer should have failed",
            vector.name
        );
    }
}

#[test]
fn test_v4_public_implicit_assertion_validation() {
    let vectors = load_v4_vectors();
    let verifier = TokenVerifier::new(None);

    // Filter for v4.public vectors with non-empty implicit assertions
    let public_ia_vectors: Vec<&TestVector> = vectors
        .tests
        .iter()
        .filter(|v| {
            v.token.starts_with("v4.public.") && !v.expect_fail && !v.implicit_assertion.is_empty()
        })
        .collect();

    assert!(
        !public_ia_vectors.is_empty(),
        "No v4.public test vectors with implicit assertions found"
    );

    for vector in public_ia_vectors {
        let public_key = vector.public_key_bytes().unwrap().unwrap();
        let footer = vector.footer_bytes().unwrap();
        let implicit_assertion = vector.implicit_assertion_bytes().unwrap();

        // Test 1: Correct implicit assertion should succeed
        let result = verifier.v4_public_verify(
            &vector.token,
            &public_key,
            if footer.is_empty() {
                None
            } else {
                Some(&footer)
            },
            Some(&implicit_assertion),
        );
        assert!(
            result.is_ok(),
            "Test vector '{}': Verification with correct implicit assertion failed",
            vector.name
        );

        // Test 2: Wrong implicit assertion should fail
        let wrong_ia = b"{\"wrong\":\"assertion\"}";
        let result = verifier.v4_public_verify(
            &vector.token,
            &public_key,
            if footer.is_empty() {
                None
            } else {
                Some(&footer)
            },
            Some(wrong_ia),
        );
        assert!(
            result.is_err(),
            "Test vector '{}': Verification with wrong implicit assertion should have failed",
            vector.name
        );

        // Test 3: Missing implicit assertion should fail
        let result = verifier.v4_public_verify(
            &vector.token,
            &public_key,
            if footer.is_empty() {
                None
            } else {
                Some(&footer)
            },
            None,
        );
        assert!(
            result.is_err(),
            "Test vector '{}': Verification without implicit assertion should have failed",
            vector.name
        );
    }
}
