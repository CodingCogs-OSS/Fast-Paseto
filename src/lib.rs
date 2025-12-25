use pyo3::exceptions::PyException;
use pyo3::prelude::*;

pub mod claims_manager;
pub mod error;
pub mod key_generator;
pub mod pae;
pub mod payload;
pub mod token_generator;
pub mod token_verifier;
pub mod version;

pub use claims_manager::ClaimsManager;
pub use error::PasetoError;
pub use key_generator::{Ed25519KeyPair, KeyGenerator};
pub use pae::Pae;
pub use payload::TokenPayload;
pub use token_generator::TokenGenerator;
pub use token_verifier::TokenVerifier;
pub use version::{Purpose, Version};

/// Token object returned from decode operations
///
/// Provides convenient access to token data including payload, footer,
/// version, and purpose. Supports dict-like access to payload fields.
///
/// Attributes:
///     payload: The decoded payload as a Python object (typically a dict)
///     footer: The decoded footer (if present) as a Python object
///     version: The token version (v2, v3, or v4)
///     purpose: The token purpose (local or public)
///
/// Example:
///     >>> token = fast_paseto.decode(token_string, key, purpose="local")
///     >>> token.version
///     'v4'
///     >>> token.purpose
///     'local'
///     >>> token.payload
///     {'sub': 'user123', 'exp': 1234567890}
///     >>> token["sub"]  # Dict-like access
///     'user123'
///     >>> "sub" in token  # Dict-like membership test
///     True
///     >>> token.to_dict()
///     {'payload': {...}, 'footer': None, 'version': 'v4', 'purpose': 'local'}
#[pyclass]
pub struct Token {
    /// The decoded payload as a Python object (typically a dict)
    #[pyo3(get)]
    pub payload: Py<pyo3::types::PyAny>,

    /// The decoded footer (if present) as a Python object
    #[pyo3(get)]
    pub footer: Option<Py<pyo3::types::PyAny>>,

    /// The token version (v2, v3, or v4)
    #[pyo3(get)]
    pub version: String,

    /// The token purpose (local or public)
    #[pyo3(get)]
    pub purpose: String,
}

#[pymethods]
impl Token {
    /// Create a new Token instance
    #[new]
    pub fn new(
        payload: Py<pyo3::types::PyAny>,
        footer: Option<Py<pyo3::types::PyAny>>,
        version: String,
        purpose: String,
    ) -> Self {
        Self {
            payload,
            footer,
            version,
            purpose,
        }
    }

    /// Dict-like access to payload fields
    ///
    /// Allows accessing payload fields using token["key"] syntax.
    ///
    /// Args:
    ///     key: The key to look up in the payload
    ///
    /// Returns:
    ///     The value associated with the key in the payload
    ///
    /// Raises:
    ///     KeyError: If the key is not found in the payload
    ///     TypeError: If the payload is not a dict
    fn __getitem__(&self, py: Python<'_>, key: &str) -> PyResult<Py<pyo3::types::PyAny>> {
        use pyo3::types::PyDict;

        // Get the payload as a dict
        let payload_dict = self.payload.bind(py).cast::<PyDict>()?;

        // Get the item from the dict
        payload_dict
            .get_item(key)?
            .ok_or_else(|| {
                pyo3::exceptions::PyKeyError::new_err(format!("Key '{}' not found in payload", key))
            })
            .map(|item| item.unbind())
    }

    /// Dict-like key check
    ///
    /// Allows checking if a key exists using "key" in token syntax.
    ///
    /// Args:
    ///     key: The key to check for in the payload
    ///
    /// Returns:
    ///     True if the key exists in the payload, False otherwise
    fn __contains__(&self, py: Python<'_>, key: &str) -> PyResult<bool> {
        use pyo3::types::PyDict;

        // Get the payload as a dict
        let payload_dict = self.payload.bind(py).cast::<PyDict>()?;

        // Check if the key exists
        Ok(payload_dict.contains(key)?)
    }

    /// Convert token to a dictionary representation
    ///
    /// Returns a dict with payload, footer, version, and purpose fields.
    ///
    /// Returns:
    ///     dict: A dictionary containing all token fields
    ///
    /// Example:
    ///     >>> token.to_dict()
    ///     {'payload': {'sub': 'user123'}, 'footer': None, 'version': 'v4', 'purpose': 'local'}
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<pyo3::types::PyAny>> {
        use pyo3::types::PyDict;

        let dict = PyDict::new(py);
        dict.set_item("payload", &self.payload)?;
        dict.set_item("footer", &self.footer)?;
        dict.set_item("version", &self.version)?;
        dict.set_item("purpose", &self.purpose)?;
        Ok(dict.into())
    }

    /// String representation of the token
    fn __repr__(&self) -> String {
        format!(
            "Token(version='{}', purpose='{}', payload=..., footer={})",
            self.version,
            self.purpose,
            if self.footer.is_some() { "..." } else { "None" }
        )
    }
}

// Python exception hierarchy
pyo3::create_exception!(
    fast_paseto,
    PasetoErrorPy,
    PyException,
    "Base exception for all PASETO errors"
);
pyo3::create_exception!(
    fast_paseto,
    PasetoValidationError,
    PasetoErrorPy,
    "Input validation errors"
);
pyo3::create_exception!(
    fast_paseto,
    PasetoKeyError,
    PasetoValidationError,
    "Key-related validation errors"
);
pyo3::create_exception!(
    fast_paseto,
    PasetoCryptoError,
    PasetoErrorPy,
    "Cryptographic operation errors"
);
pyo3::create_exception!(
    fast_paseto,
    PasetoExpiredError,
    PasetoErrorPy,
    "Token has expired"
);
pyo3::create_exception!(
    fast_paseto,
    PasetoNotYetValidError,
    PasetoErrorPy,
    "Token is not yet valid (nbf in future)"
);

/// Convert Rust PasetoError to Python exceptions
impl From<PasetoError> for PyErr {
    fn from(err: PasetoError) -> PyErr {
        match err {
            // Key validation errors -> PasetoKeyError
            PasetoError::InvalidKeyLength { .. } => PasetoKeyError::new_err(err.to_string()),
            PasetoError::InvalidKeyFormat(_) => PasetoKeyError::new_err(err.to_string()),
            PasetoError::InvalidPemFormat(_) => PasetoKeyError::new_err(err.to_string()),
            PasetoError::InvalidPaserkFormat(_) => PasetoKeyError::new_err(err.to_string()),

            // Token format validation errors -> PasetoValidationError
            PasetoError::InvalidTokenFormat(_) => PasetoValidationError::new_err(err.to_string()),
            PasetoError::UnsupportedVersion(_) => PasetoValidationError::new_err(err.to_string()),
            PasetoError::FooterMismatch => PasetoValidationError::new_err(err.to_string()),
            PasetoError::ImplicitAssertionMismatch => {
                PasetoValidationError::new_err(err.to_string())
            }

            // Cryptographic errors -> PasetoCryptoError
            PasetoError::AuthenticationFailed => PasetoCryptoError::new_err(err.to_string()),
            PasetoError::SignatureVerificationFailed => PasetoCryptoError::new_err(err.to_string()),
            PasetoError::IntegrityError => PasetoCryptoError::new_err(err.to_string()),
            PasetoError::CryptoError(_) => PasetoCryptoError::new_err(err.to_string()),
            PasetoError::PasswordDecryptionFailed => PasetoCryptoError::new_err(err.to_string()),

            // Time-based claim validation errors -> Specific exceptions
            PasetoError::TokenExpired => PasetoExpiredError::new_err(err.to_string()),
            PasetoError::TokenNotYetValid => PasetoNotYetValidError::new_err(err.to_string()),
            PasetoError::TokenIssuedInFuture => PasetoValidationError::new_err(err.to_string()),

            // Serialization errors -> PasetoValidationError
            PasetoError::SerializationError(_) => PasetoValidationError::new_err(err.to_string()),
            PasetoError::DeserializationError(_) => PasetoValidationError::new_err(err.to_string()),
        }
    }
}

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
    ///     payload: The payload data as a Python dict
    ///     purpose: Token purpose - "local" or "public". Default: "local"
    ///     version: PASETO version - "v2", "v3", or "v4". Default: "v4"
    ///     footer: Optional footer data (bytes, str, or dict). Default: None
    ///     implicit_assertion: Optional implicit assertion (bytes). Default: None
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
    #[pyo3(signature = (key, payload, purpose="local", version="v4", footer=None, implicit_assertion=None))]
    fn encode(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        payload: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
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

        // Get payload as dict and apply defaults
        let payload_dict = if let Ok(dict) = payload.cast::<PyDict>() {
            // Create a copy of the dict to avoid modifying the original
            let new_dict = dict.copy()?;

            // Apply default_exp if configured and not already present
            if let Some(exp_seconds) = self.default_exp {
                if !new_dict.contains("exp")? {
                    let now = ClaimsManager::now();
                    let exp = now + exp_seconds;
                    new_dict.set_item("exp", exp)?;
                }
            }

            // Apply include_iat if configured and not already present
            if self.include_iat && !new_dict.contains("iat")? {
                let now = ClaimsManager::now();
                new_dict.set_item("iat", now)?;
            }

            new_dict
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Payload must be a dict",
            ));
        };

        // Serialize payload to JSON
        let json_module = py.import("json")?;
        let dumps = json_module.getattr("dumps")?;
        let json_bound = dumps.call1((payload_dict,))?;
        let json_str = json_bound.cast::<PyString>()?;
        let payload_json = json_str.to_str()?.as_bytes().to_vec();

        // Convert footer to bytes if provided
        let footer_bytes = if let Some(f) = footer {
            if let Ok(bytes) = f.cast::<PyBytes>() {
                Some(bytes.as_bytes().to_vec())
            } else if let Ok(string) = f.cast::<PyString>() {
                Some(string.to_str()?.as_bytes().to_vec())
            } else if let Ok(dict) = f.cast::<PyDict>() {
                // Convert dict to JSON string
                let json_bound = dumps.call1((dict,))?;
                let json_str = json_bound.cast::<PyString>()?;
                Some(json_str.to_str()?.as_bytes().to_vec())
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
                    &payload_json,
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
                    &payload_json,
                    footer_bytes.as_deref(),
                    implicit_assertion,
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
    #[pyo3(signature = (token, key, purpose="local", version="v4", footer=None, implicit_assertion=None))]
    fn decode(
        &self,
        py: Python<'_>,
        token: &str,
        key: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
    ) -> PyResult<Token> {
        use pyo3::types::{PyBytes, PyDict, PyString};
        use base64::prelude::*;

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

        // Convert footer to bytes if provided
        let footer_bytes = if let Some(f) = footer {
            if let Ok(bytes) = f.cast::<PyBytes>() {
                Some(bytes.as_bytes().to_vec())
            } else if let Ok(string) = f.cast::<PyString>() {
                Some(string.to_str()?.as_bytes().to_vec())
            } else if let Ok(dict) = f.cast::<PyDict>() {
                // Convert dict to JSON string
                let json_module = py.import("json")?;
                let dumps = json_module.getattr("dumps")?;
                let json_bound = dumps.call1((dict,))?;
                let json_str = json_bound.cast::<PyString>()?;
                Some(json_str.to_str()?.as_bytes().to_vec())
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
                verifier.v4_local_decrypt(token, &key_array, footer_bytes.as_deref(), implicit_assertion)?
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
                verifier.v4_public_verify(token, &key_array, footer_bytes.as_deref(), implicit_assertion)?
            }
            _ => {
                return Err(PasetoValidationError::new_err(format!(
                    "Unsupported version/purpose combination: {}/{}",
                    version, purpose
                )));
            }
        };

        // Parse payload JSON to Python dict
        let json_module = py.import("json")?;
        let loads = json_module.getattr("loads")?;
        let payload_str = std::str::from_utf8(&payload_bytes)
            .map_err(|e| PasetoValidationError::new_err(format!("Invalid UTF-8 in payload: {}", e)))?;
        let payload_dict = loads.call1((payload_str,))?;

        // Parse footer JSON to Python dict if present
        let footer_dict = if let Some(footer_data) = token_footer_bytes {
            let footer_str = std::str::from_utf8(&footer_data)
                .map_err(|e| PasetoValidationError::new_err(format!("Invalid UTF-8 in footer: {}", e)))?;
            // Try to parse as JSON, if it fails, just return as string
            match loads.call1((footer_str,)) {
                Ok(obj) => Some(obj.unbind()),
                Err(_) => {
                    // If JSON parsing fails, return as string
                    Some(PyString::new(py, footer_str).into())
                }
            }
        } else {
            None
        };

        // Create Token object
        Ok(Token {
            payload: payload_dict.unbind(),
            footer: footer_dict,
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

/// A Python module implemented in Rust.
#[pymodule]
fn fast_paseto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    use crate::key_generator::KeyGenerator;
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
    ///     payload: The payload data as a Python dict
    ///     purpose: Token purpose - "local" (symmetric) or "public" (asymmetric).
    ///              Default: "local"
    ///     version: PASETO version - "v2", "v3", or "v4". Default: "v4"
    ///     footer: Optional footer data (bytes, str, or dict). Default: None
    ///     implicit_assertion: Optional implicit assertion (bytes). Default: None
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
    #[pyfunction]
    #[pyo3(signature = (key, payload, purpose="local", version="v4", footer=None, implicit_assertion=None))]
    fn encode(
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        payload: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
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

        // Serialize payload to JSON
        let payload_json = if let Ok(dict) = payload.cast::<PyDict>() {
            // Convert dict to JSON string
            let json_module = py.import("json")?;
            let dumps = json_module.getattr("dumps")?;
            let json_bound = dumps.call1((dict,))?;
            let json_str = json_bound.cast::<PyString>()?;
            json_str.to_str()?.as_bytes().to_vec()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Payload must be a dict",
            ));
        };

        // Convert footer to bytes if provided
        let footer_bytes = if let Some(f) = footer {
            if let Ok(bytes) = f.cast::<PyBytes>() {
                Some(bytes.as_bytes().to_vec())
            } else if let Ok(string) = f.cast::<PyString>() {
                Some(string.to_str()?.as_bytes().to_vec())
            } else if let Ok(dict) = f.cast::<PyDict>() {
                // Convert dict to JSON string
                let json_module = py.import("json")?;
                let dumps = json_module.getattr("dumps")?;
                let json_bound = dumps.call1((dict,))?;
                let json_str = json_bound.cast::<PyString>()?;
                Some(json_str.to_str()?.as_bytes().to_vec())
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
                    &payload_json,
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
                    &payload_json,
                    footer_bytes.as_deref(),
                    implicit_assertion,
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
    #[pyfunction]
    #[pyo3(signature = (token, key, purpose="local", version="v4", footer=None, implicit_assertion=None, leeway=0))]
    fn decode(
        py: Python<'_>,
        token: &str,
        key: &Bound<'_, PyAny>,
        purpose: &str,
        version: &str,
        footer: Option<&Bound<'_, PyAny>>,
        implicit_assertion: Option<&[u8]>,
        leeway: u64,
    ) -> PyResult<Token> {
        use pyo3::types::{PyBytes, PyDict, PyString};
        use base64::prelude::*;

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

        // Convert footer to bytes if provided
        let footer_bytes = if let Some(f) = footer {
            if let Ok(bytes) = f.cast::<PyBytes>() {
                Some(bytes.as_bytes().to_vec())
            } else if let Ok(string) = f.cast::<PyString>() {
                Some(string.to_str()?.as_bytes().to_vec())
            } else if let Ok(dict) = f.cast::<PyDict>() {
                // Convert dict to JSON string
                let json_module = py.import("json")?;
                let dumps = json_module.getattr("dumps")?;
                let json_bound = dumps.call1((dict,))?;
                let json_str = json_bound.cast::<PyString>()?;
                Some(json_str.to_str()?.as_bytes().to_vec())
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
                verifier.v4_local_decrypt(token, &key_array, footer_bytes.as_deref(), implicit_assertion)?
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
                verifier.v4_public_verify(token, &key_array, footer_bytes.as_deref(), implicit_assertion)?
            }
            _ => {
                return Err(PasetoValidationError::new_err(format!(
                    "Unsupported version/purpose combination: {}/{}",
                    version, purpose
                )));
            }
        };

        // Parse payload JSON to Python dict
        let json_module = py.import("json")?;
        let loads = json_module.getattr("loads")?;
        let payload_str = std::str::from_utf8(&payload_bytes)
            .map_err(|e| PasetoValidationError::new_err(format!("Invalid UTF-8 in payload: {}", e)))?;
        let payload_dict = loads.call1((payload_str,))?;

        // Parse footer JSON to Python dict if present
        let footer_dict = if let Some(footer_data) = token_footer_bytes {
            let footer_str = std::str::from_utf8(&footer_data)
                .map_err(|e| PasetoValidationError::new_err(format!("Invalid UTF-8 in footer: {}", e)))?;
            // Try to parse as JSON, if it fails, just return as string
            match loads.call1((footer_str,)) {
                Ok(obj) => Some(obj.unbind()),
                Err(_) => {
                    // If JSON parsing fails, return as string
                    Some(PyString::new(py, footer_str).into())
                }
            }
        } else {
            None
        };

        // Create Token object
        Ok(Token {
            payload: payload_dict.unbind(),
            footer: footer_dict,
            version: version.to_string(),
            purpose: purpose.to_string(),
        })
    }

    m.add_function(wrap_pyfunction!(generate_symmetric_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;

    Ok(())
}
