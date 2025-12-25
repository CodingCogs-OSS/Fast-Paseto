use pyo3::prelude::*;

pub mod error;
pub mod key_generator;
pub mod pae;
pub mod payload;
pub mod version;

pub use error::PasetoError;
pub use key_generator::{Ed25519KeyPair, KeyGenerator};
pub use pae::Pae;
pub use payload::TokenPayload;
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
