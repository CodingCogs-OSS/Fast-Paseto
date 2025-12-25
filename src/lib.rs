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

/// A Python module implemented in Rust.
#[pymodule]
mod fast_paseto {
    use pyo3::prelude::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
        Ok((a + b).to_string())
    }
}
