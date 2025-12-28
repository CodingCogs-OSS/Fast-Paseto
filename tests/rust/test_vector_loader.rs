use fast_paseto::test_vectors::{TestVectorFile, TestVector};
use std::path::Path;

#[test]
fn test_load_v4_vectors() {
    let path = Path::new("tests/vectors/v4.json");
    let result = TestVectorFile::load_from_file(path);

    assert!(result.is_ok(), "Failed to load v4.json: {:?}", result.err());

    let vectors = result.unwrap();
    assert_eq!(vectors.name, "PASETO v4 Test Vectors");
    assert!(!vectors.tests.is_empty(), "No test vectors found");

    // Check first test vector
    let first = &vectors.tests[0];
    assert_eq!(first.name, "4-E-1");
    assert!(!first.expect_fail);
    assert!(first.token.starts_with("v4.local."));
}

#[test]
fn test_load_v2_vectors() {
    let path = Path::new("tests/vectors/v2.json");
    let result = TestVectorFile::load_from_file(path);

    assert!(result.is_ok(), "Failed to load v2.json: {:?}", result.err());

    let vectors = result.unwrap();
    assert_eq!(vectors.name, "PASETO v2 Test Vectors");
    assert!(!vectors.tests.is_empty(), "No test vectors found");
}

#[test]
fn test_load_v3_vectors() {
    let path = Path::new("tests/vectors/v3.json");
    let result = TestVectorFile::load_from_file(path);

    assert!(result.is_ok(), "Failed to load v3.json: {:?}", result.err());

    let vectors = result.unwrap();
    assert_eq!(vectors.name, "PASETO v3 Test Vectors");
    assert!(!vectors.tests.is_empty(), "No test vectors found");
}

#[test]
fn test_hex_decoding() {
    let hex = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    let bytes = TestVector::decode_hex(hex).unwrap();

    assert_eq!(bytes.len(), 32);
    assert_eq!(bytes[0], 0x70);
    assert_eq!(bytes[31], 0x8f);
}

#[test]
fn test_payload_bytes() {
    // Test with JSON string payload
    let vector = TestVector {
        name: "test".to_string(),
        expect_fail: false,
        token: "".to_string(),
        key: "".to_string(),
        public_key: None,
        secret_key: None,
        secret_key_seed: None,
        secret_key_pem: None,
        public_key_pem: None,
        nonce: None,
        payload: Some(r#"{"data":"test"}"#.to_string()),
        footer: "".to_string(),
        implicit_assertion: "".to_string(),
    };

    let bytes = vector.payload_bytes().unwrap();
    assert_eq!(bytes, r#"{"data":"test"}"#.as_bytes());
}

#[test]
fn test_empty_fields() {
    let vector = TestVector {
        name: "test".to_string(),
        expect_fail: false,
        token: "".to_string(),
        key: "".to_string(),
        public_key: None,
        secret_key: None,
        secret_key_seed: None,
        secret_key_pem: None,
        public_key_pem: None,
        nonce: None,
        payload: None,
        footer: "".to_string(),
        implicit_assertion: "".to_string(),
    };

    assert_eq!(vector.payload_bytes().unwrap(), Vec::<u8>::new());
    assert_eq!(vector.footer_bytes().unwrap(), Vec::<u8>::new());
    assert_eq!(vector.implicit_assertion_bytes().unwrap(), Vec::<u8>::new());
    assert_eq!(vector.nonce_bytes().unwrap(), None);
}
