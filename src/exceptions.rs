//! Python exception hierarchy for PASETO errors
//!
//! This module defines the Python exception types that map to Rust `PasetoError` variants.
//! The exception hierarchy provides specific error types for different failure modes:
//!
//! - `PasetoErrorPy`: Base exception for all PASETO errors
//!   - `PasetoValidationError`: Input validation errors (token format, serialization)
//!     - `PasetoKeyError`: Key-related validation errors (length, format)
//!   - `PasetoCryptoError`: Cryptographic operation errors (auth failed, signature invalid)
//!   - `PasetoExpiredError`: Token has expired (exp claim in past)
//!   - `PasetoNotYetValidError`: Token is not yet valid (nbf claim in future)
//!
//! # Example
//!
//! ```python
//! import fast_paseto
//!
//! try:
//!     token = fast_paseto.decode(token_str, wrong_key)
//! except fast_paseto.PasetoCryptoError:
//!     print("Decryption failed - wrong key?")
//! except fast_paseto.PasetoExpiredError:
//!     print("Token has expired")
//! except fast_paseto.PasetoError:
//!     print("Some other PASETO error")
//! ```

use pyo3::exceptions::PyException;
use pyo3::prelude::*;

use crate::error::PasetoError;

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
///
/// Maps each `PasetoError` variant to the appropriate Python exception type,
/// preserving error context in the exception message.
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
