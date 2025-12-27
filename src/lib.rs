use pyo3::prelude::*;

pub mod claims_manager;
pub mod error;
pub mod exceptions;
pub mod key_generator;
pub mod key_manager;
pub mod pae;
pub mod paseto;
pub mod payload;
pub mod token;
pub mod token_generator;
pub mod token_verifier;
pub mod version;

pub use claims_manager::ClaimsManager;
pub use error::PasetoError;
pub use exceptions::{
    PasetoCryptoError, PasetoErrorPy, PasetoExpiredError, PasetoKeyError, PasetoNotYetValidError,
    PasetoValidationError,
};
pub use key_generator::{Ed25519KeyPair, KeyGenerator, P384KeyPair};
pub use key_manager::{KeyManager, PaserkId, PaserkKey};
pub use pae::Pae;
pub use paseto::Paseto;
pub use payload::TokenPayload;
pub use token::Token;
pub use token_generator::TokenGenerator;
pub use token_verifier::TokenVerifier;
pub use version::{Purpose, Version};

/// A Python module implemented in Rust.
#[pymodule]
fn fast_paseto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    use crate::key_generator::KeyGenerator;
    use crate::key_manager::{KeyManager, PaserkKey};
    use pyo3::types::PyBytes;

    // Register Paseto class
    m.add_class::<Paseto>()?;

    // Register Token class
    m.add_class::<Token>()?;

    // Register exception classes
    m.add("PasetoError", m.py().get_type::<PasetoErrorPy>())?;
    m.add(
        "PasetoValidationError",
        m.py().get_type::<PasetoValidationError>(),
    )?;
    m.add("PasetoKeyError", m.py().get_type::<PasetoKeyError>())?;
    m.add("PasetoCryptoError", m.py().get_type::<PasetoCryptoError>())?;
    m.add(
        "PasetoExpiredError",
        m.py().get_type::<PasetoExpiredError>(),
    )?;
    m.add(
        "PasetoNotYetValidError",
        m.py().get_type::<PasetoNotYetValidError>(),
    )?;

    /// Generate a symmetric key for local tokens
    ///
    /// Generates a cryptographically secure 32-byte symmetric key suitable for
    /// v4.local PASETO tokens using XChaCha20 encryption with BLAKE2b-MAC.
    ///
    /// Returns:
    ///     bytes: A 32-byte symmetric key
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> len(key)
    ///     32
    #[pyfunction]
    fn generate_symmetric_key(py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let key = KeyGenerator::generate_symmetric_key();
        Ok(PyBytes::new(py, &key).into())
    }

    /// Generate an Ed25519 key pair for public tokens
    ///
    /// Generates a cryptographically secure Ed25519 key pair suitable for
    /// v4.public PASETO tokens using Ed25519 signatures.
    ///
    /// Returns:
    ///     tuple[bytes, bytes]: A tuple of (secret_key, public_key) where:
    ///         - secret_key is 64 bytes (used for signing)
    ///         - public_key is 32 bytes (used for verification)
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> secret_key, public_key = fast_paseto.generate_keypair()
    ///     >>> len(secret_key)
    ///     64
    ///     >>> len(public_key)
    ///     32
    #[pyfunction]
    fn generate_keypair(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let keypair = KeyGenerator::generate_ed25519_keypair();
        let secret_bytes = PyBytes::new(py, &keypair.secret_key).into();
        let public_bytes = PyBytes::new(py, &keypair.public_key).into();
        Ok((secret_bytes, public_bytes))
    }

    /// Encode a PASETO token
    ///
    /// Creates a PASETO token from a payload dict using the specified key,
    /// purpose, and version.
    ///
    /// Args:
    ///     key: The cryptographic key (bytes or str). For local tokens, must be
    ///          32 bytes. For public tokens, must be 64 bytes (Ed25519 secret key).
    ///     payload: The payload data as a Python dict, bytes, or str
    ///     purpose: Token purpose - "local" (symmetric) or "public" (asymmetric).
    ///              Default: "local"
    ///     version: PASETO version - "v2", "v3", or "v4". Default: "v4"
    ///     footer: Optional footer data (bytes, str, or dict). Default: None
    ///     implicit_assertion: Optional implicit assertion (bytes). Default: None
    ///     serializer: Optional object with dumps() method for custom serialization.
    ///                 If provided, will be used to serialize dict payloads and footers.
    ///                 Default: None (uses JSON)
    ///
    /// Returns:
    ///     str: The encoded PASETO token string
    ///
    /// Raises:
    ///     PasetoKeyError: If the key format or length is invalid
    ///     PasetoValidationError: If the payload cannot be serialized
    ///     PasetoCryptoError: If encryption/signing fails
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> payload = {"sub": "user123", "exp": 1234567890}
    ///     >>> token = fast_paseto.encode(key, payload, purpose="local")
    ///     >>> token.startswith("v4.local.")
    ///     True
    ///     >>> # With custom serializer:
    ///     >>> import json
    ///     >>> token = fast_paseto.encode(key, payload, serializer=json)
    #[pyfunction]
    #[pyo3(signature = (key, payload, purpose="local", version="v4", footer=None, implicit_assertion=None, serializer=None))]
    fn encode(
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        payload: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
        serializer: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<String> {
        use pyo3::types::{PyBytes, PyDict, PyString};

        // Parse version and purpose
        let version_enum = Version::from_str(version)?;
        let purpose_enum = Purpose::from_str(purpose)?;

        // Convert key to bytes
        let key_bytes = if let Ok(bytes) = key.cast::<PyBytes>() {
            bytes.as_bytes().to_vec()
        } else if let Ok(string) = key.cast::<PyString>() {
            string.to_str()?.as_bytes().to_vec()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Key must be bytes or str",
            ));
        };

        // Get the serializer's dumps method or fall back to JSON
        let json_module = py.import("json")?;
        let dumps = if let Some(ser) = serializer {
            ser.getattr("dumps")?
        } else {
            json_module.getattr("dumps")?
        };

        // Serialize payload based on type
        let payload_bytes = if let Ok(dict) = payload.cast::<PyDict>() {
            // Serialize using the serializer
            let serialized = dumps.call1((dict,))?;

            // Handle both bytes and str return types from serializer
            if let Ok(bytes) = serialized.cast::<PyBytes>() {
                bytes.as_bytes().to_vec()
            } else if let Ok(string) = serialized.cast::<PyString>() {
                string.to_str()?.as_bytes().to_vec()
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "Serializer dumps() must return bytes or str",
                ));
            }
        } else if let Ok(bytes) = payload.cast::<PyBytes>() {
            // Accept raw bytes payload when no serializer needed
            bytes.as_bytes().to_vec()
        } else if let Ok(string) = payload.cast::<PyString>() {
            // Accept raw string payload when no serializer needed
            string.to_str()?.as_bytes().to_vec()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Payload must be a dict, bytes, or str",
            ));
        };

        // Convert footer to bytes if provided
        let footer_bytes = if let Some(f) = footer {
            if let Ok(bytes) = f.cast::<PyBytes>() {
                Some(bytes.as_bytes().to_vec())
            } else if let Ok(string) = f.cast::<PyString>() {
                Some(string.to_str()?.as_bytes().to_vec())
            } else if let Ok(dict) = f.cast::<PyDict>() {
                // Serialize dict footer using the serializer
                let serialized = dumps.call1((dict,))?;
                if let Ok(bytes) = serialized.cast::<PyBytes>() {
                    Some(bytes.as_bytes().to_vec())
                } else if let Ok(string) = serialized.cast::<PyString>() {
                    Some(string.to_str()?.as_bytes().to_vec())
                } else {
                    return Err(pyo3::exceptions::PyTypeError::new_err(
                        "Serializer dumps() must return bytes or str",
                    ));
                }
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "Footer must be bytes, str, or dict",
                ));
            }
        } else {
            None
        };

        // Generate token based on version and purpose
        let token = match (version_enum, purpose_enum) {
            (Version::V4, Purpose::Local) => {
                // v4.local requires 32-byte key
                if key_bytes.len() != 32 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v4.local: expected 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                TokenGenerator::v4_local_encrypt(
                    &key_array,
                    &payload_bytes,
                    footer_bytes.as_deref(),
                    implicit_assertion,
                )?
            }
            (Version::V4, Purpose::Public) => {
                // v4.public requires 64-byte secret key
                if key_bytes.len() != 64 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v4.public: expected 64 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 64] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                TokenGenerator::v4_public_sign(
                    &key_array,
                    &payload_bytes,
                    footer_bytes.as_deref(),
                    implicit_assertion,
                )?
            }
            (Version::V2, Purpose::Local) => {
                // v2.local requires 32-byte key
                if key_bytes.len() != 32 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v2.local: expected 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                // v2 does not support implicit assertions
                TokenGenerator::v2_local_encrypt(
                    &key_array,
                    &payload_bytes,
                    footer_bytes.as_deref(),
                )?
            }
            (Version::V2, Purpose::Public) => {
                // v2.public requires 64-byte secret key
                if key_bytes.len() != 64 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v2.public: expected 64 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 64] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                // v2 does not support implicit assertions
                TokenGenerator::v2_public_sign(
                    &key_array,
                    &payload_bytes,
                    footer_bytes.as_deref(),
                )?
            }
            _ => {
                return Err(PasetoValidationError::new_err(format!(
                    "Unsupported version/purpose combination: {}/{}",
                    version, purpose
                )));
            }
        };

        Ok(token)
    }

    /// Decode a PASETO token
    ///
    /// Verifies and decrypts a PASETO token, returning a Token object with
    /// the decoded payload and metadata.
    ///
    /// Args:
    ///     token: The PASETO token string to decode
    ///     key: The cryptographic key (bytes or str). For local tokens, must be
    ///          32 bytes. For public tokens, must be 32 bytes (Ed25519 public key).
    ///     purpose: Token purpose - "local" (symmetric) or "public" (asymmetric).
    ///              Default: "local"
    ///     version: PASETO version - "v2", "v3", or "v4". Default: "v4"
    ///     footer: Optional expected footer data (bytes, str, or dict). Default: None
    ///     implicit_assertion: Optional implicit assertion (bytes). Default: None
    ///     deserializer: Optional object with loads() method for custom deserialization.
    ///                   If provided, will be used to deserialize payload and footer.
    ///                   Default: None (uses JSON)
    ///     leeway: Time tolerance in seconds for time-based claims. Default: 0
    ///
    /// Returns:
    ///     Token: A Token object with payload, footer, version, and purpose
    ///
    /// Raises:
    ///     PasetoKeyError: If the key format or length is invalid
    ///     PasetoValidationError: If the token format is invalid
    ///     PasetoCryptoError: If decryption/verification fails
    ///     PasetoExpiredError: If the token has expired
    ///     PasetoNotYetValidError: If the token is not yet valid
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> payload = {"sub": "user123"}
    ///     >>> token_str = fast_paseto.encode(key, payload)
    ///     >>> token = fast_paseto.decode(token_str, key)
    ///     >>> token.payload["sub"]
    ///     'user123'
    ///     >>> token.version
    ///     'v4'
    ///     >>> # With custom deserializer:
    ///     >>> import json
    ///     >>> token = fast_paseto.decode(token_str, key, deserializer=json)
    #[pyfunction]
    #[pyo3(signature = (token, key, purpose="local", version="v4", footer=None, implicit_assertion=None, deserializer=None, leeway=0))]
    fn decode(
        py: Python<'_>,
        token: &str,
        key: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
        deserializer: Option<&Bound<'_, PyAny>>,
        leeway: u64,
    ) -> PyResult<Token> {
        use base64::prelude::*;
        use pyo3::types::{PyBytes, PyDict, PyString};

        // Parse version and purpose
        let version_enum = Version::from_str(version)?;
        let purpose_enum = Purpose::from_str(purpose)?;

        // Convert key to bytes
        let key_bytes = if let Ok(bytes) = key.cast::<PyBytes>() {
            bytes.as_bytes().to_vec()
        } else if let Ok(string) = key.cast::<PyString>() {
            string.to_str()?.as_bytes().to_vec()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Key must be bytes or str",
            ));
        };

        // Get the deserializer's loads method or fall back to JSON
        let json_module = py.import("json")?;
        let loads = if let Some(deser) = deserializer {
            deser.getattr("loads")?
        } else {
            json_module.getattr("loads")?
        };

        // Get the serializer's dumps method for footer comparison
        let dumps = if let Some(deser) = deserializer {
            // Try to get dumps from the deserializer (it might be a module like json)
            match deser.getattr("dumps") {
                Ok(d) => d,
                Err(_) => json_module.getattr("dumps")?,
            }
        } else {
            json_module.getattr("dumps")?
        };

        // Convert footer to bytes if provided
        let footer_bytes = if let Some(f) = footer {
            if let Ok(bytes) = f.cast::<PyBytes>() {
                Some(bytes.as_bytes().to_vec())
            } else if let Ok(string) = f.cast::<PyString>() {
                Some(string.to_str()?.as_bytes().to_vec())
            } else if let Ok(dict) = f.cast::<PyDict>() {
                // Serialize dict footer using the serializer
                let serialized = dumps.call1((dict,))?;
                if let Ok(bytes) = serialized.cast::<PyBytes>() {
                    Some(bytes.as_bytes().to_vec())
                } else if let Ok(string) = serialized.cast::<PyString>() {
                    Some(string.to_str()?.as_bytes().to_vec())
                } else {
                    return Err(pyo3::exceptions::PyTypeError::new_err(
                        "Serializer dumps() must return bytes or str",
                    ));
                }
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "Footer must be bytes, str, or dict",
                ));
            }
        } else {
            None
        };

        // Extract footer from token string for return value
        let parts: Vec<&str> = token.split('.').collect();
        let token_footer_bytes = if parts.len() == 4 {
            Some(BASE64_URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                PasetoValidationError::new_err(format!("Invalid base64url footer: {}", e))
            })?)
        } else {
            None
        };

        // Create verifier with leeway
        let verifier = TokenVerifier::new(Some(leeway));

        // Decode token based on version and purpose
        let payload_bytes = match (version_enum, purpose_enum) {
            (Version::V4, Purpose::Local) => {
                // v4.local requires 32-byte key
                if key_bytes.len() != 32 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v4.local: expected 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                verifier.v4_local_decrypt(
                    token,
                    &key_array,
                    footer_bytes.as_deref(),
                    implicit_assertion,
                )?
            }
            (Version::V4, Purpose::Public) => {
                // v4.public requires 32-byte public key
                if key_bytes.len() != 32 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v4.public: expected 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                verifier.v4_public_verify(
                    token,
                    &key_array,
                    footer_bytes.as_deref(),
                    implicit_assertion,
                )?
            }
            (Version::V2, Purpose::Local) => {
                // v2.local requires 32-byte key
                if key_bytes.len() != 32 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v2.local: expected 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                // v2 does not support implicit assertions
                verifier.v2_local_decrypt(
                    token,
                    &key_array,
                    footer_bytes.as_deref(),
                )?
            }
            (Version::V2, Purpose::Public) => {
                // v2.public requires 32-byte public key
                if key_bytes.len() != 32 {
                    return Err(PasetoKeyError::new_err(format!(
                        "Invalid key length for v2.public: expected 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                let key_array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
                // v2 does not support implicit assertions
                verifier.v2_public_verify(
                    token,
                    &key_array,
                    footer_bytes.as_deref(),
                )?
            }
            _ => {
                return Err(PasetoValidationError::new_err(format!(
                    "Unsupported version/purpose combination: {}/{}",
                    version, purpose
                )));
            }
        };

        // Deserialize payload using the deserializer
        // First convert bytes to appropriate input for loads
        let payload_input = if deserializer.is_some() {
            // Custom deserializer might expect bytes
            PyBytes::new(py, &payload_bytes).into_any()
        } else {
            // JSON loads expects str
            let payload_str = std::str::from_utf8(&payload_bytes).map_err(|e| {
                PasetoValidationError::new_err(format!("Invalid UTF-8 in payload: {}", e))
            })?;
            PyString::new(py, payload_str).into_any()
        };

        let payload_obj = match loads.call1((payload_input,)) {
            Ok(obj) => obj,
            Err(_) => {
                // If bytes didn't work, try with string
                let payload_str = std::str::from_utf8(&payload_bytes).map_err(|e| {
                    PasetoValidationError::new_err(format!("Invalid UTF-8 in payload: {}", e))
                })?;
                loads.call1((payload_str,))?
            }
        };

        // Deserialize footer if present
        let footer_obj = if let Some(footer_data) = token_footer_bytes {
            // Try to deserialize using the deserializer
            let footer_input = if deserializer.is_some() {
                // Custom deserializer might expect bytes
                PyBytes::new(py, &footer_data).into_any()
            } else {
                // JSON loads expects str
                let footer_str = std::str::from_utf8(&footer_data).map_err(|e| {
                    PasetoValidationError::new_err(format!("Invalid UTF-8 in footer: {}", e))
                })?;
                PyString::new(py, footer_str).into_any()
            };

            match loads.call1((footer_input,)) {
                Ok(obj) => Some(obj.unbind()),
                Err(_) => {
                    // If bytes didn't work, try with string
                    let footer_str = std::str::from_utf8(&footer_data).map_err(|e| {
                        PasetoValidationError::new_err(format!("Invalid UTF-8 in footer: {}", e))
                    })?;
                    match loads.call1((footer_str,)) {
                        Ok(obj) => Some(obj.unbind()),
                        Err(_) => {
                            // If deserialization fails, return as string
                            Some(PyString::new(py, footer_str).into())
                        }
                    }
                }
            }
        } else {
            None
        };

        // Create Token object
        Ok(Token {
            payload: payload_obj.unbind(),
            footer: footer_obj,
            version: version.to_string(),
            purpose: purpose.to_string(),
        })
    }

    /// Serialize a symmetric key to PASERK local format
    ///
    /// Converts a 32-byte symmetric key to the PASERK format: k4.local.{base64url_key}
    ///
    /// Args:
    ///     key: A 32-byte symmetric key (bytes)
    ///
    /// Returns:
    ///     str: A PASERK-formatted string (e.g., "k4.local.AAAA...")
    ///
    /// Raises:
    ///     PasetoKeyError: If the key is not exactly 32 bytes
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> paserk = fast_paseto.to_paserk_local(key)
    ///     >>> paserk.startswith("k4.local.")
    ///     True
    #[pyfunction]
    fn to_paserk_local(key: &[u8]) -> PyResult<String> {
        if key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length for local key: expected 32 bytes, got {}",
                key.len()
            )));
        }
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        Ok(KeyManager::to_paserk_local(&key_array))
    }

    /// Serialize an Ed25519 secret key to PASERK secret format
    ///
    /// Converts a 64-byte Ed25519 secret key to the PASERK format: k4.secret.{base64url_key}
    ///
    /// Args:
    ///     key: A 64-byte Ed25519 secret key (bytes)
    ///
    /// Returns:
    ///     str: A PASERK-formatted string (e.g., "k4.secret.AAAA...")
    ///
    /// Raises:
    ///     PasetoKeyError: If the key is not exactly 64 bytes
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> secret_key, public_key = fast_paseto.generate_keypair()
    ///     >>> paserk = fast_paseto.to_paserk_secret(secret_key)
    ///     >>> paserk.startswith("k4.secret.")
    ///     True
    #[pyfunction]
    fn to_paserk_secret(key: &[u8]) -> PyResult<String> {
        if key.len() != 64 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length for secret key: expected 64 bytes, got {}",
                key.len()
            )));
        }
        let key_array: [u8; 64] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        Ok(KeyManager::to_paserk_secret(&key_array))
    }

    /// Serialize an Ed25519 public key to PASERK public format
    ///
    /// Converts a 32-byte Ed25519 public key to the PASERK format: k4.public.{base64url_key}
    ///
    /// Args:
    ///     key: A 32-byte Ed25519 public key (bytes)
    ///
    /// Returns:
    ///     str: A PASERK-formatted string (e.g., "k4.public.AAAA...")
    ///
    /// Raises:
    ///     PasetoKeyError: If the key is not exactly 32 bytes
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> secret_key, public_key = fast_paseto.generate_keypair()
    ///     >>> paserk = fast_paseto.to_paserk_public(public_key)
    ///     >>> paserk.startswith("k4.public.")
    ///     True
    #[pyfunction]
    fn to_paserk_public(key: &[u8]) -> PyResult<String> {
        if key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length for public key: expected 32 bytes, got {}",
                key.len()
            )));
        }
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        Ok(KeyManager::to_paserk_public(&key_array))
    }

    /// Deserialize a PASERK string back to key bytes
    ///
    /// Parses a PASERK-formatted string and returns the key bytes.
    /// Supports k4.local, k4.secret, and k4.public formats.
    ///
    /// Args:
    ///     paserk: A PASERK-formatted string (e.g., "k4.local.AAAA...")
    ///
    /// Returns:
    ///     tuple[str, bytes]: A tuple of (key_type, key_bytes) where:
    ///         - key_type is "local", "secret", or "public"
    ///         - key_bytes is the decoded key (32 bytes for local/public, 64 bytes for secret)
    ///
    /// Raises:
    ///     PasetoKeyError: If the PASERK format is invalid or unsupported
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> paserk = fast_paseto.to_paserk_local(key)
    ///     >>> key_type, decoded_key = fast_paseto.from_paserk(paserk)
    ///     >>> key_type
    ///     'local'
    ///     >>> decoded_key == key
    ///     True
    #[pyfunction]
    fn from_paserk(py: Python<'_>, paserk: &str) -> PyResult<(String, Py<PyBytes>)> {
        let parsed = KeyManager::from_paserk(paserk)?;

        match parsed {
            PaserkKey::Local(key) => Ok(("local".to_string(), PyBytes::new(py, &key).into())),
            PaserkKey::Secret(key) => Ok(("secret".to_string(), PyBytes::new(py, &key).into())),
            PaserkKey::Public(key) => Ok(("public".to_string(), PyBytes::new(py, &key).into())),
        }
    }

    /// Generate a local ID (lid) for symmetric keys
    ///
    /// Creates a PASERK ID for a 32-byte symmetric key used in v4.local tokens.
    /// The ID is deterministic - the same key always produces the same ID.
    ///
    /// Args:
    ///     key: A 32-byte symmetric key (bytes)
    ///
    /// Returns:
    ///     str: A PASERK local ID string in the format k4.lid.{base64url_hash}
    ///
    /// Raises:
    ///     PasetoKeyError: If the key is not exactly 32 bytes
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> lid = fast_paseto.generate_lid(key)
    ///     >>> lid.startswith("k4.lid.")
    ///     True
    ///     >>> # Same key always produces same ID
    ///     >>> lid2 = fast_paseto.generate_lid(key)
    ///     >>> lid == lid2
    ///     True
    #[pyfunction]
    fn generate_lid(key: &[u8]) -> PyResult<String> {
        if key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length for local key: expected 32 bytes, got {}",
                key.len()
            )));
        }
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        Ok(PaserkId::generate_lid(&key_array))
    }

    /// Generate a secret ID (sid) for Ed25519 secret keys
    ///
    /// Creates a PASERK ID for a 64-byte Ed25519 secret key used in v4.public tokens.
    /// The ID is deterministic - the same key always produces the same ID.
    ///
    /// Args:
    ///     key: A 64-byte Ed25519 secret key (bytes)
    ///
    /// Returns:
    ///     str: A PASERK secret ID string in the format k4.sid.{base64url_hash}
    ///
    /// Raises:
    ///     PasetoKeyError: If the key is not exactly 64 bytes
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> secret_key, public_key = fast_paseto.generate_keypair()
    ///     >>> sid = fast_paseto.generate_sid(secret_key)
    ///     >>> sid.startswith("k4.sid.")
    ///     True
    ///     >>> # Same key always produces same ID
    ///     >>> sid2 = fast_paseto.generate_sid(secret_key)
    ///     >>> sid == sid2
    ///     True
    #[pyfunction]
    fn generate_sid(key: &[u8]) -> PyResult<String> {
        if key.len() != 64 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length for secret key: expected 64 bytes, got {}",
                key.len()
            )));
        }
        let key_array: [u8; 64] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        Ok(PaserkId::generate_sid(&key_array))
    }

    /// Generate a public ID (pid) for Ed25519 public keys
    ///
    /// Creates a PASERK ID for a 32-byte Ed25519 public key used in v4.public tokens.
    /// The ID is deterministic - the same key always produces the same ID.
    ///
    /// Args:
    ///     key: A 32-byte Ed25519 public key (bytes)
    ///
    /// Returns:
    ///     str: A PASERK public ID string in the format k4.pid.{base64url_hash}
    ///
    /// Raises:
    ///     PasetoKeyError: If the key is not exactly 32 bytes
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> secret_key, public_key = fast_paseto.generate_keypair()
    ///     >>> pid = fast_paseto.generate_pid(public_key)
    ///     >>> pid.startswith("k4.pid.")
    ///     True
    ///     >>> # Same key always produces same ID
    ///     >>> pid2 = fast_paseto.generate_pid(public_key)
    ///     >>> pid == pid2
    ///     True
    #[pyfunction]
    fn generate_pid(key: &[u8]) -> PyResult<String> {
        if key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length for public key: expected 32 bytes, got {}",
                key.len()
            )));
        }
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        Ok(PaserkId::generate_pid(&key_array))
    }

    /// Wrap a symmetric key using a wrapping key (PASERK local-wrap)
    ///
    /// Encrypts a 32-byte symmetric key using another 32-byte wrapping key,
    /// producing a PASERK wrapped key string. Uses v4.local token encryption
    /// internally to provide authenticated encryption.
    ///
    /// Args:
    ///     key: A 32-byte symmetric key to wrap (bytes)
    ///     wrapping_key: A 32-byte wrapping key (bytes)
    ///
    /// Returns:
    ///     str: A PASERK local-wrap key string (e.g., "k4.local-wrap.pie.AAAA...")
    ///
    /// Raises:
    ///     PasetoKeyError: If either key is not exactly 32 bytes
    ///     PasetoCryptoError: If encryption fails
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> wrapping_key = fast_paseto.generate_symmetric_key()
    ///     >>> wrapped = fast_paseto.local_wrap(key, wrapping_key)
    ///     >>> wrapped.startswith("k4.local-wrap.pie.")
    ///     True
    #[pyfunction]
    fn local_wrap(key: &[u8], wrapping_key: &[u8]) -> PyResult<String> {
        if key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length: expected 32 bytes, got {}",
                key.len()
            )));
        }
        if wrapping_key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid wrapping key length: expected 32 bytes, got {}",
                wrapping_key.len()
            )));
        }
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        let wrapping_key_array: [u8; 32] = wrapping_key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert wrapping key to array"))?;
        Ok(KeyManager::local_wrap(&key_array, &wrapping_key_array)?)
    }

    /// Unwrap a symmetric key using a wrapping key (PASERK local-wrap)
    ///
    /// Decrypts a PASERK wrapped key string using a 32-byte wrapping key,
    /// returning the original 32-byte symmetric key. Uses v4.local token
    /// decryption internally to provide authenticated decryption.
    ///
    /// Args:
    ///     wrapped_key: A PASERK local-wrap key string (str)
    ///     wrapping_key: A 32-byte wrapping key (bytes)
    ///
    /// Returns:
    ///     bytes: The unwrapped 32-byte symmetric key
    ///
    /// Raises:
    ///     PasetoKeyError: If the wrapping key is not exactly 32 bytes or format is invalid
    ///     PasetoCryptoError: If decryption fails (wrong key or tampered data)
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> wrapping_key = fast_paseto.generate_symmetric_key()
    ///     >>> wrapped = fast_paseto.local_wrap(key, wrapping_key)
    ///     >>> unwrapped = fast_paseto.local_unwrap(wrapped, wrapping_key)
    ///     >>> unwrapped == key
    ///     True
    #[pyfunction]
    fn local_unwrap(
        py: Python<'_>,
        wrapped_key: &str,
        wrapping_key: &[u8],
    ) -> PyResult<Py<PyBytes>> {
        if wrapping_key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid wrapping key length: expected 32 bytes, got {}",
                wrapping_key.len()
            )));
        }
        let wrapping_key_array: [u8; 32] = wrapping_key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert wrapping key to array"))?;
        let unwrapped = KeyManager::local_unwrap(wrapped_key, &wrapping_key_array)?;
        Ok(PyBytes::new(py, &unwrapped).into())
    }

    /// Wrap an Ed25519 secret key with a wrapping key (PASERK secret-wrap).
    ///
    /// Encrypts a 64-byte Ed25519 secret key using a 32-byte wrapping key,
    /// producing a PASERK wrapped key string. Uses v4.local token encryption
    /// internally to provide authenticated encryption.
    ///
    /// Args:
    ///     secret_key: 64-byte Ed25519 secret key to wrap
    ///     wrapping_key: 32-byte wrapping key
    ///
    /// Returns:
    ///     PASERK secret-wrap key string (format: k4.secret-wrap.pie.{wrapped_token})
    ///
    /// Raises:
    ///     PasetoKeyError: If key lengths are invalid
    ///     PasetoCryptoError: If encryption fails
    ///
    /// Example:
    ///     >>> keypair = fast_paseto.generate_keypair()
    ///     >>> wrapping_key = fast_paseto.generate_symmetric_key()
    ///     >>> wrapped = fast_paseto.secret_wrap(keypair['secret_key'], wrapping_key)
    ///     >>> wrapped.startswith("k4.secret-wrap.pie.")
    ///     True
    #[pyfunction]
    fn secret_wrap(secret_key: &[u8], wrapping_key: &[u8]) -> PyResult<String> {
        if secret_key.len() != 64 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid secret key length: expected 64 bytes, got {}",
                secret_key.len()
            )));
        }
        if wrapping_key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid wrapping key length: expected 32 bytes, got {}",
                wrapping_key.len()
            )));
        }
        let secret_key_array: [u8; 64] = secret_key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert secret key to array"))?;
        let wrapping_key_array: [u8; 32] = wrapping_key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert wrapping key to array"))?;
        Ok(KeyManager::secret_wrap(
            &secret_key_array,
            &wrapping_key_array,
        )?)
    }

    /// Unwrap an Ed25519 secret key with a wrapping key (PASERK secret-wrap).
    ///
    /// Decrypts a PASERK wrapped key string using a 32-byte wrapping key,
    /// returning the original 64-byte Ed25519 secret key. Uses v4.local token
    /// decryption internally to provide authenticated decryption.
    ///
    /// Args:
    ///     wrapped_key: PASERK secret-wrap key string
    ///     wrapping_key: 32-byte wrapping key
    ///
    /// Returns:
    ///     Unwrapped 64-byte Ed25519 secret key
    ///
    /// Raises:
    ///     PasetoKeyError: If wrapping key length is invalid
    ///     PasetoFormatError: If wrapped key format is invalid
    ///     PasetoAuthenticationError: If decryption fails
    ///
    /// Example:
    ///     >>> keypair = fast_paseto.generate_keypair()
    ///     >>> wrapping_key = fast_paseto.generate_symmetric_key()
    ///     >>> wrapped = fast_paseto.secret_wrap(keypair['secret_key'], wrapping_key)
    ///     >>> unwrapped = fast_paseto.secret_unwrap(wrapped, wrapping_key)
    ///     >>> unwrapped == keypair['secret_key']
    ///     True
    #[pyfunction]
    fn secret_unwrap(
        py: Python<'_>,
        wrapped_key: &str,
        wrapping_key: &[u8],
    ) -> PyResult<Py<PyBytes>> {
        if wrapping_key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid wrapping key length: expected 32 bytes, got {}",
                wrapping_key.len()
            )));
        }
        let wrapping_key_array: [u8; 32] = wrapping_key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert wrapping key to array"))?;
        let unwrapped = KeyManager::secret_unwrap(wrapped_key, &wrapping_key_array)?;
        Ok(PyBytes::new(py, &unwrapped).into())
    }

    /// Encrypt a symmetric key with a password (PASERK local-pw)
    ///
    /// Uses Argon2id for key derivation and v4.local encryption.
    /// Format: `k4.local-pw.{base64url_encrypted_data}`
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
    /// # Raises
    ///
    /// * `PasetoKeyError` - If key length is not 32 bytes
    /// * `PasetoCryptoError` - If encryption fails
    ///
    /// # Examples
    ///
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> encrypted = fast_paseto.local_pw_encrypt(key, "my-password")
    ///     >>> encrypted.startswith("k4.local-pw.")
    ///     True
    #[pyfunction]
    fn local_pw_encrypt(key: &[u8], password: &str) -> PyResult<String> {
        if key.len() != 32 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid key length: expected 32 bytes, got {}",
                key.len()
            )));
        }
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert key to array"))?;
        let encrypted = KeyManager::local_pw_encrypt(&key_array, password)?;
        Ok(encrypted)
    }

    /// Decrypt a symmetric key with a password (PASERK local-pw)
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
    /// # Raises
    ///
    /// * `PasetoValidationError` - If format is invalid
    /// * `PasetoCryptoError` - If decryption fails (wrong password)
    ///
    /// # Examples
    ///
    ///     >>> import fast_paseto
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> encrypted = fast_paseto.local_pw_encrypt(key, "my-password")
    ///     >>> decrypted = fast_paseto.local_pw_decrypt(encrypted, "my-password")
    ///     >>> decrypted == key
    ///     True
    #[pyfunction]
    fn local_pw_decrypt(py: Python<'_>, encrypted: &str, password: &str) -> PyResult<Py<PyBytes>> {
        let decrypted = KeyManager::local_pw_decrypt(encrypted, password)?;
        Ok(PyBytes::new(py, &decrypted).into())
    }

    /// Encrypt an Ed25519 secret key with a password (PASERK secret-pw)
    ///
    /// Uses Argon2id for key derivation and v4.local encryption.
    /// Format: `k4.secret-pw.{base64url_encrypted_data}`
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
    /// # Raises
    ///
    /// * `PasetoKeyError` - If key length is not 64 bytes
    /// * `PasetoCryptoError` - If encryption fails
    ///
    /// # Examples
    ///
    ///     >>> import fast_paseto
    ///     >>> secret_key, public_key = fast_paseto.generate_keypair()
    ///     >>> encrypted = fast_paseto.secret_pw_encrypt(secret_key, "my-password")
    ///     >>> encrypted.startswith("k4.secret-pw.")
    ///     True
    #[pyfunction]
    fn secret_pw_encrypt(secret_key: &[u8], password: &str) -> PyResult<String> {
        if secret_key.len() != 64 {
            return Err(PasetoKeyError::new_err(format!(
                "Invalid secret key length: expected 64 bytes, got {}",
                secret_key.len()
            )));
        }
        let key_array: [u8; 64] = secret_key
            .try_into()
            .map_err(|_| PasetoKeyError::new_err("Failed to convert secret key to array"))?;
        let encrypted = KeyManager::secret_pw_encrypt(&key_array, password)?;
        Ok(encrypted)
    }

    /// Decrypt an Ed25519 secret key with a password (PASERK secret-pw)
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
    /// # Raises
    ///
    /// * `PasetoValidationError` - If format is invalid
    /// * `PasetoCryptoError` - If decryption fails (wrong password)
    ///
    /// # Examples
    ///
    ///     >>> import fast_paseto
    ///     >>> secret_key, public_key = fast_paseto.generate_keypair()
    ///     >>> encrypted = fast_paseto.secret_pw_encrypt(secret_key, "my-password")
    ///     >>> decrypted = fast_paseto.secret_pw_decrypt(encrypted, "my-password")
    ///     >>> decrypted == secret_key
    ///     True
    #[pyfunction]
    fn secret_pw_decrypt(py: Python<'_>, encrypted: &str, password: &str) -> PyResult<Py<PyBytes>> {
        let decrypted = KeyManager::secret_pw_decrypt(encrypted, password)?;
        Ok(PyBytes::new(py, &decrypted).into())
    }

    /// Load an Ed25519 private key from PEM format (PKCS#8)
    ///
    /// Parses a PEM-encoded Ed25519 private key in PKCS#8 format and returns
    /// the 64-byte secret key suitable for use with v4.public tokens.
    ///
    /// Args:
    ///     pem: PEM-encoded Ed25519 private key string
    ///
    /// Returns:
    ///     bytes: A 64-byte Ed25519 secret key
    ///
    /// Raises:
    ///     PasetoKeyError: If the PEM format is invalid or the key is not Ed25519
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> pem = '''-----BEGIN PRIVATE KEY-----
    ///     ... MC4CAQAwBQYDK2VwBCIEIGqPaUKpqt0MJjJgXgXgXgXgXgXgXgXgXgXgXgXgXgXg
    ///     ... -----END PRIVATE KEY-----'''
    ///     >>> secret_key = fast_paseto.ed25519_from_pem(pem)
    ///     >>> len(secret_key)
    ///     64
    #[pyfunction]
    fn ed25519_from_pem(py: Python<'_>, pem: &str) -> PyResult<Py<PyBytes>> {
        let secret_key = KeyManager::ed25519_from_pem(pem)?;
        Ok(PyBytes::new(py, &secret_key).into())
    }

    /// Load an Ed25519 public key from PEM format (SPKI)
    ///
    /// Parses a PEM-encoded Ed25519 public key in SPKI (Subject Public Key Info)
    /// format and returns the 32-byte public key suitable for use with v4.public
    /// token verification.
    ///
    /// Args:
    ///     pem: PEM-encoded Ed25519 public key string
    ///
    /// Returns:
    ///     bytes: A 32-byte Ed25519 public key
    ///
    /// Raises:
    ///     PasetoKeyError: If the PEM format is invalid or the key is not Ed25519
    ///
    /// Example:
    ///     >>> import fast_paseto
    ///     >>> pem = '''-----BEGIN PUBLIC KEY-----
    ///     ... MCowBQYDK2VwAyEAGb9F2CMCwPz0vPz0vPz0vPz0vPz0vPz0vPz0vPz0vPw=
    ///     ... -----END PUBLIC KEY-----'''
    ///     >>> public_key = fast_paseto.ed25519_public_from_pem(pem)
    ///     >>> len(public_key)
    ///     32
    #[pyfunction]
    fn ed25519_public_from_pem(py: Python<'_>, pem: &str) -> PyResult<Py<PyBytes>> {
        let public_key = KeyManager::ed25519_public_from_pem(pem)?;
        Ok(PyBytes::new(py, &public_key).into())
    }

    m.add_function(wrap_pyfunction!(generate_symmetric_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(to_paserk_local, m)?)?;
    m.add_function(wrap_pyfunction!(to_paserk_secret, m)?)?;
    m.add_function(wrap_pyfunction!(to_paserk_public, m)?)?;
    m.add_function(wrap_pyfunction!(from_paserk, m)?)?;
    m.add_function(wrap_pyfunction!(generate_lid, m)?)?;
    m.add_function(wrap_pyfunction!(generate_sid, m)?)?;
    m.add_function(wrap_pyfunction!(generate_pid, m)?)?;
    m.add_function(wrap_pyfunction!(local_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(local_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(secret_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(secret_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(local_pw_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(local_pw_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(secret_pw_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(secret_pw_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_from_pem, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_public_from_pem, m)?)?;

    Ok(())
}
