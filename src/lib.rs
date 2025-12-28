//! fast-paseto: High-performance PASETO tokens for Python
//!
//! This library provides secure token generation and verification using the
//! PASETO (Platform-Agnostic Security Tokens) specification. All cryptographic
//! operations are implemented in Rust for performance and security, with a
//! Python-friendly API via PyO3 bindings.
//!
//! # Features
//!
//! - **v4.local**: XChaCha20-Poly1305 encryption for confidential data
//! - **v4.public**: Ed25519 signatures for verifiable, non-confidential data
//! - **PASERK**: Key serialization and wrapping (local, secret, public, wrap, pw)
//! - **Automatic claim management**: Optional exp (expiration) and iat (issued-at) injection
//! - **Custom serialization**: JSON by default, custom serializers supported
//!
//! # Quick Start
//!
//! ## Local tokens (symmetric encryption)
//!
//! ```python
//! import fast_paseto
//!
//! # Generate a symmetric key
//! key = fast_paseto.generate_symmetric_key()
//!
//! # Create a token
//! payload = {"user_id": "123", "role": "admin"}
//! token = fast_paseto.encode(key, payload, purpose="local")
//!
//! # Verify and decode
//! decoded = fast_paseto.decode(token, key, purpose="local")
//! print(decoded.payload["user_id"])  # "123"
//! ```
//!
//! ## Public tokens (asymmetric signatures)
//!
//! ```python
//! import fast_paseto
//!
//! # Generate a keypair
//! secret_key, public_key = fast_paseto.generate_keypair()
//!
//! # Sign a token
//! payload = {"user_id": "123", "role": "admin"}
//! token = fast_paseto.encode(secret_key, payload, purpose="public")
//!
//! # Verify with public key
//! decoded = fast_paseto.decode(token, public_key, purpose="public")
//! print(decoded.payload["user_id"])  # "123"
//! ```
//!
//! ## Using the Paseto class for defaults
//!
//! ```python
//! import fast_paseto
//!
//! # Configure defaults
//! paseto = fast_paseto.Paseto(
//!     default_exp=3600,  # 1 hour expiration
//!     include_iat=True,  # Include issued-at timestamp
//!     leeway=60          # 60 second clock skew tolerance
//! )
//!
//! key = fast_paseto.generate_symmetric_key()
//! token = paseto.encode(key, {"user_id": "123"})
//! decoded = paseto.decode(token, key)
//! ```

use pyo3::prelude::*;

pub mod bindings;
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

    // Register key generation functions
    m.add_function(wrap_pyfunction!(bindings::generate_symmetric_key, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::generate_keypair, m)?)?;

    // Register token encoding/decoding functions
    m.add_function(wrap_pyfunction!(bindings::encode, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::decode, m)?)?;

    // Register PASERK serialization functions
    m.add_function(wrap_pyfunction!(bindings::to_paserk_local, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::to_paserk_secret, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::to_paserk_public, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::from_paserk, m)?)?;

    // Register PASERK ID generation functions
    m.add_function(wrap_pyfunction!(bindings::generate_lid, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::generate_sid, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::generate_pid, m)?)?;

    // Register PASERK wrapping functions
    m.add_function(wrap_pyfunction!(bindings::local_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::local_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::secret_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::secret_unwrap, m)?)?;

    // Register PASERK password encryption functions
    m.add_function(wrap_pyfunction!(bindings::local_pw_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::local_pw_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::secret_pw_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::secret_pw_decrypt, m)?)?;

    // Register PEM key loading functions
    m.add_function(wrap_pyfunction!(bindings::ed25519_from_pem, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::ed25519_public_from_pem, m)?)?;

    Ok(())
}
