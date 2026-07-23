use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Error types for test vector operations
#[derive(Debug, thiserror::Error)]
pub enum TestVectorError {
    #[error("Failed to parse JSON: {0}")]
    JsonParseError(String),

    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    #[error("Invalid PEM format: {0}")]
    InvalidPem(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// A single test vector from the official test suite
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestVector {
    /// Human-readable test name (e.g., "4-E-1")
    pub name: String,

    /// Whether this test is expected to fail
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,

    /// The expected token string
    pub token: String,

    /// Secret key (hex-encoded in JSON)
    #[serde(default)]
    pub key: String,

    /// Public key for public tokens (hex-encoded or PEM in JSON)
    #[serde(rename = "public-key", default)]
    pub public_key: Option<String>,

    /// Secret key for public tokens (hex-encoded or PEM in JSON)
    #[serde(rename = "secret-key", default)]
    pub secret_key: Option<String>,

    /// Secret key seed for public tokens (hex-encoded in JSON)
    #[serde(rename = "secret-key-seed", default)]
    pub secret_key_seed: Option<String>,

    /// Secret key in PEM format
    #[serde(rename = "secret-key-pem", default)]
    pub secret_key_pem: Option<String>,

    /// Public key in PEM format
    #[serde(rename = "public-key-pem", default)]
    pub public_key_pem: Option<String>,

    /// Nonce for deterministic encryption (hex-encoded in JSON)
    #[serde(default)]
    pub nonce: Option<String>,

    /// Payload string or hex-encoded bytes (can be null for expect-fail tests)
    #[serde(default)]
    pub payload: Option<String>,

    /// Footer string or hex-encoded bytes
    #[serde(default)]
    pub footer: String,

    /// Implicit assertion (hex-encoded in JSON)
    #[serde(rename = "implicit-assertion", default)]
    pub implicit_assertion: String,
}

/// Collection of test vectors for a specific version
#[derive(Debug, Deserialize, Serialize)]
pub struct TestVectorFile {
    /// PASETO version (v2, v3, v4)
    pub name: String,

    /// List of test vectors
    pub tests: Vec<TestVector>,
}

impl TestVectorFile {
    /// Load test vectors from a JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, TestVectorError> {
        let content = fs::read_to_string(path)?;
        Self::load_from_str(&content)
    }

    /// Load test vectors from JSON string
    pub fn load_from_str(json: &str) -> Result<Self, TestVectorError> {
        serde_json::from_str(json).map_err(|e| TestVectorError::JsonParseError(e.to_string()))
    }
}

impl TestVector {
    /// Decode hex string to bytes
    pub fn decode_hex(hex: &str) -> Result<Vec<u8>, TestVectorError> {
        if hex.is_empty() {
            return Ok(Vec::new());
        }

        hex::decode(hex).map_err(|e| TestVectorError::InvalidHex(format!("{}: {}", hex, e)))
    }

    /// Get the key as raw bytes (hex-decoded)
    pub fn key_bytes(&self) -> Result<Vec<u8>, TestVectorError> {
        Self::decode_hex(&self.key)
    }

    /// Get the public key as raw bytes (hex-decoded or PEM-decoded)
    pub fn public_key_bytes(&self) -> Result<Option<Vec<u8>>, TestVectorError> {
        match &self.public_key {
            Some(key) => {
                // Try PEM first, then hex
                if key.contains("-----BEGIN") {
                    Self::load_pem_key(key).map(Some)
                } else {
                    Self::decode_hex(key).map(Some)
                }
            }
            None => Ok(None),
        }
    }

    /// Get the secret key as raw bytes (hex-decoded or PEM-decoded)
    pub fn secret_key_bytes(&self) -> Result<Option<Vec<u8>>, TestVectorError> {
        match &self.secret_key {
            Some(key) => {
                // Try PEM first, then hex
                if key.contains("-----BEGIN") {
                    Self::load_pem_key(key).map(Some)
                } else {
                    Self::decode_hex(key).map(Some)
                }
            }
            None => Ok(None),
        }
    }

    /// Get the nonce as raw bytes (hex-decoded)
    pub fn nonce_bytes(&self) -> Result<Option<Vec<u8>>, TestVectorError> {
        match &self.nonce {
            Some(nonce) => Self::decode_hex(nonce).map(Some),
            None => Ok(None),
        }
    }

    /// Get the payload as raw bytes
    /// If it's valid hex, decode it; otherwise treat as UTF-8 string
    pub fn payload_bytes(&self) -> Result<Vec<u8>, TestVectorError> {
        match &self.payload {
            Some(payload) if !payload.is_empty() => {
                // Try hex decoding first
                match Self::decode_hex(payload) {
                    Ok(bytes) => Ok(bytes),
                    Err(_) => {
                        // Not hex, treat as UTF-8 string
                        Ok(payload.as_bytes().to_vec())
                    }
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Get the footer as raw bytes
    /// If it's valid hex, decode it; otherwise treat as UTF-8 string
    pub fn footer_bytes(&self) -> Result<Vec<u8>, TestVectorError> {
        if self.footer.is_empty() {
            return Ok(Vec::new());
        }

        // Try hex decoding first
        match Self::decode_hex(&self.footer) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                // Not hex, treat as UTF-8 string
                Ok(self.footer.as_bytes().to_vec())
            }
        }
    }

    /// Get the implicit assertion as raw bytes (hex-decoded)
    pub fn implicit_assertion_bytes(&self) -> Result<Vec<u8>, TestVectorError> {
        if self.implicit_assertion.is_empty() {
            return Ok(Vec::new());
        }

        // Try hex decoding first
        match Self::decode_hex(&self.implicit_assertion) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                // Not hex, treat as UTF-8 string (JSON)
                Ok(self.implicit_assertion.as_bytes().to_vec())
            }
        }
    }

    /// Load PEM-encoded key
    fn load_pem_key(pem: &str) -> Result<Vec<u8>, TestVectorError> {
        // Parse PEM format
        let pem_data = pem::parse(pem).map_err(|e| TestVectorError::InvalidPem(e.to_string()))?;

        Ok(pem_data.contents().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() {
        let hex = "707172737475767778797a7b7c7d7e7f";
        let bytes = TestVector::decode_hex(hex).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x70);
        assert_eq!(bytes[15], 0x7f);
    }

    #[test]
    fn test_decode_empty_hex() {
        let hex = "";
        let bytes = TestVector::decode_hex(hex).unwrap();
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_decode_invalid_hex() {
        let hex = "not-hex";
        let result = TestVector::decode_hex(hex);
        assert!(result.is_err());
    }
}
