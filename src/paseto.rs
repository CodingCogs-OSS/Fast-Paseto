//! Configurable Paseto instance with preset defaults
//!
//! This module provides the `Paseto` class for configuring default behavior
//! for token operations including expiration, issued-at timestamps, and leeway
//! for time-based claim validation.
//!
//! # Example
//!
//! ```python
//! import fast_paseto
//!
//! # Create instance with 1 hour expiration and 60 second leeway
//! paseto = fast_paseto.Paseto(default_exp=3600, include_iat=True, leeway=60)
//! key = fast_paseto.generate_symmetric_key()
//! payload = {"sub": "user123"}
//!
//! # Encode will automatically add exp and iat claims
//! token = paseto.encode(key, payload)
//!
//! # Decode will use 60 second leeway for time validation
//! decoded = paseto.decode(token, key)
//! ```

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyString};

use crate::claims_manager::ClaimsManager;
use crate::exceptions::{PasetoKeyError, PasetoValidationError};
use crate::token::Token;
use crate::token_generator::TokenGenerator;
use crate::token_verifier::TokenVerifier;
use crate::version::{Purpose, Version};

/// Configurable Paseto instance with preset defaults
///
/// A Paseto instance allows you to configure default behavior for token
/// operations, such as automatic expiration times, issued-at timestamps,
/// and time-based claim validation leeway.
///
/// Attributes:
///     default_exp: Default expiration time in seconds (added to current time)
///     include_iat: Whether to automatically include issued-at (iat) claim
///     leeway: Time tolerance in seconds for time-based claim validation
///
/// Example:
///     >>> import fast_paseto
///     >>> # Create instance with 1 hour expiration and 60 second leeway
///     >>> paseto = fast_paseto.Paseto(default_exp=3600, include_iat=True, leeway=60)
///     >>> key = fast_paseto.generate_symmetric_key()
///     >>> payload = {"sub": "user123"}
///     >>> # Encode will automatically add exp and iat claims
///     >>> token = paseto.encode(key, payload)
///     >>> # Decode will use 60 second leeway for time validation
///     >>> decoded = paseto.decode(token, key)
#[pyclass]
#[derive(Debug)]
pub struct Paseto {
    /// Default expiration time in seconds (added to current time)
    #[pyo3(get)]
    default_exp: Option<u64>,

    /// Whether to automatically include issued-at (iat) claim
    #[pyo3(get)]
    include_iat: bool,

    /// Time tolerance in seconds for time-based claim validation
    #[pyo3(get)]
    leeway: u64,
}

#[pymethods]
impl Paseto {
    /// Create a new Paseto instance with configuration
    ///
    /// Args:
    ///     default_exp: Default expiration time in seconds (added to current time).
    ///                  If set, tokens will automatically get an exp claim. Default: None
    ///     include_iat: Whether to automatically include issued-at (iat) claim.
    ///                  Default: True
    ///     leeway: Time tolerance in seconds for time-based claim validation.
    ///             Default: 0
    ///
    /// Returns:
    ///     Paseto: A configured Paseto instance
    ///
    /// Example:
    ///     >>> paseto = fast_paseto.Paseto(default_exp=3600, include_iat=True, leeway=60)
    #[new]
    #[pyo3(signature = (default_exp=None, include_iat=true, leeway=0))]
    fn new(default_exp: Option<u64>, include_iat: bool, leeway: u64) -> Self {
        Self {
            default_exp,
            include_iat,
            leeway,
        }
    }

    /// Encode a PASETO token with configured defaults
    ///
    /// Creates a PASETO token from a payload dict, automatically applying
    /// configured defaults (exp, iat) if not already present in the payload.
    ///
    /// Args:
    ///     key: The cryptographic key (bytes or str)
    ///     payload: The payload data as a Python dict, bytes, or str
    ///     purpose: Token purpose - "local" or "public". Default: "local"
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
    /// Example:
    ///     >>> paseto = fast_paseto.Paseto(default_exp=3600, include_iat=True)
    ///     >>> key = fast_paseto.generate_symmetric_key()
    ///     >>> payload = {"sub": "user123"}
    ///     >>> token = paseto.encode(key, payload)
    ///     >>> # Token will have exp and iat claims automatically added
    ///     >>> # With custom serializer:
    ///     >>> import json
    ///     >>> token = paseto.encode(key, payload, serializer=json)
    #[pyo3(signature = (key, payload, purpose="local", version="v4", footer=None, implicit_assertion=None, serializer=None))]
    #[allow(clippy::too_many_arguments)]
    fn encode(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        payload: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
        serializer: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<String> {
        // Parse version and purpose
        let version_enum: Version = version.parse()?;
        let purpose_enum: Purpose = purpose.parse()?;

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
            // Create a copy of the dict to avoid modifying the original
            let new_dict = dict.copy()?;

            // Apply default_exp if configured and not already present
            if let Some(exp_seconds) = self.default_exp
                && !new_dict.contains("exp")?
            {
                let now = ClaimsManager::now();
                let exp = now + exp_seconds;
                new_dict.set_item("exp", exp)?;
            }

            // Apply include_iat if configured and not already present
            if self.include_iat && !new_dict.contains("iat")? {
                let now = ClaimsManager::now();
                new_dict.set_item("iat", now)?;
            }

            // Serialize using the serializer
            let serialized = dumps.call1((new_dict,))?;

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
                TokenGenerator::v2_public_sign(&key_array, &payload_bytes, footer_bytes.as_deref())?
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

    /// Decode a PASETO token with configured leeway
    ///
    /// Verifies and decrypts a PASETO token, applying the configured leeway
    /// for time-based claim validation.
    ///
    /// Args:
    ///     token: The PASETO token string to decode
    ///     key: The cryptographic key (bytes or str)
    ///     purpose: Token purpose - "local" or "public". Default: "local"
    ///     version: PASETO version - "v2", "v3", or "v4". Default: "v4"
    ///     footer: Optional expected footer data (bytes, str, or dict). Default: None
    ///     implicit_assertion: Optional implicit assertion (bytes). Default: None
    ///     deserializer: Optional object with loads() method for custom deserialization.
    ///                   If provided, will be used to deserialize payload and footer.
    ///                   Default: None (uses JSON)
    ///
    /// Returns:
    ///     Token: A Token object with payload, footer, version, and purpose
    ///
    /// Example:
    ///     >>> paseto = fast_paseto.Paseto(leeway=60)
    ///     >>> token_str = "v4.local...."
    ///     >>> key = b"..."
    ///     >>> decoded = paseto.decode(token_str, key)
    ///     >>> # Time-based claims will be validated with 60 second tolerance
    ///     >>> # With custom deserializer:
    ///     >>> import json
    ///     >>> decoded = paseto.decode(token_str, key, deserializer=json)
    #[pyo3(signature = (token, key, purpose="local", version="v4", footer=None, implicit_assertion=None, deserializer=None))]
    #[allow(clippy::too_many_arguments)]
    fn decode(
        &self,
        py: Python<'_>,
        token: &str,
        key: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
        deserializer: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Token> {
        use base64::prelude::*;

        // Parse version and purpose
        let version_enum: Version = version.parse()?;
        let purpose_enum: Purpose = purpose.parse()?;

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

        // Get the serializer's dumps method for footer comparison (use JSON for footer serialization)
        let dumps = if let Some(deser) = deserializer {
            // Try to get dumps from the deserializer (it might be a module like json)
            match deser.getattr("dumps") {
                Ok(d) => d,
                Err(_) => json_module.getattr("dumps")?,
            }
        } else {
            json_module.getattr("dumps")?
        };

        // Convert footer to bytes if provided (for comparison)
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

        // Create verifier with configured leeway
        let verifier = TokenVerifier::new(Some(self.leeway));

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
                verifier.v2_local_decrypt(token, &key_array, footer_bytes.as_deref())?
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
                verifier.v2_public_verify(token, &key_array, footer_bytes.as_deref())?
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

    /// String representation of the Paseto instance
    fn __repr__(&self) -> String {
        format!(
            "Paseto(default_exp={:?}, include_iat={}, leeway={})",
            self.default_exp, self.include_iat, self.leeway
        )
    }
}
