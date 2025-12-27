//! Token representation for decoded PASETO tokens
//!
//! This module provides the `Token` struct that represents a decoded PASETO token
//! with convenient access to payload, footer, version, and purpose. The Token
//! supports dict-like access to payload fields for ergonomic Python usage.
//!
//! # Example
//!
//! ```python
//! import fast_paseto
//!
//! token = fast_paseto.decode(token_string, key, purpose="local")
//! token.version  # 'v4'
//! token.purpose  # 'local'
//! token["sub"]   # Dict-like access to payload fields
//! "sub" in token # Membership test
//! token.to_dict() # Convert to dictionary
//! ```

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

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
#[derive(Debug)]
pub struct Token {
    /// The decoded payload as a Python object (typically a dict)
    #[pyo3(get)]
    pub payload: Py<PyAny>,

    /// The decoded footer (if present) as a Python object
    #[pyo3(get)]
    pub footer: Option<Py<PyAny>>,

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
    ///
    /// Args:
    ///     payload: The decoded payload as a Python object
    ///     footer: The decoded footer (if present) as a Python object
    ///     version: The token version string (v2, v3, or v4)
    ///     purpose: The token purpose string (local or public)
    ///
    /// Returns:
    ///     Token: A new Token instance
    #[new]
    pub fn new(
        payload: Py<PyAny>,
        footer: Option<Py<PyAny>>,
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
    fn __getitem__(&self, py: Python<'_>, key: &str) -> PyResult<Py<PyAny>> {
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
        // Get the payload as a dict
        let payload_dict = self.payload.bind(py).cast::<PyDict>()?;

        // Check if the key exists
        payload_dict.contains(key)
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
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
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
