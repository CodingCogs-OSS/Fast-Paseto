# Project Structure & Architecture

## Architecture Pattern

A **Rust-Python hybrid library**:
- Rust (`src/`) implements ALL cryptographic operations and core logic.
- PyO3 exposes the API to Python; the compiled module is `fast_paseto`.
- `fast_paseto.pyi` is the Python-facing type surface and MUST stay in sync with the Rust bindings.

## Rust Core (`src/`)

| Module | Responsibility |
|--------|----------------|
| `lib.rs` | `#[pymodule]` entry point; registers classes/functions; `pub use` re-exports |
| `bindings.rs` | All `#[pyfunction]` implementations (`encode`, `decode`, `generate_*`, PASERK, PEM) |
| `paseto.rs` | Stateful `Paseto` `#[pyclass]` with defaults (`default_exp`, `include_iat`, `leeway`) |
| `token.rs` | Immutable `Token` class returned from decode |
| `token_generator.rs` | Token creation logic |
| `token_verifier.rs` | Token verification logic |
| `claims_manager.rs` | Claim handling (exp, iat, leeway) |
| `key_generator.rs` | Key/keypair generation (`Ed25519KeyPair`, `P384KeyPair`) |
| `key_manager.rs` | PASERK key serialization, IDs, wrapping (`PaserkKey`, `PaserkId`) |
| `payload.rs` | `TokenPayload` data structures |
| `version.rs` | `Version` (v2/v3/v4) and `Purpose` (local/public) |
| `pae.rs` | Pre-Authentication Encoding (`Pae`) |
| `error.rs` | `PasetoError` enum (`thiserror`) |
| `exceptions.rs` | `From<PasetoError> for PyErr`; Python exception classes |
| `test_vectors.rs` | Official test-vector loading (feature `test-vectors`) |

## Python Interface & Config

- `fast_paseto.pyi` — type stubs (source of truth for the Python API signatures).
- `main.py` — example usage only, not part of the library.
- `profiling/benchmark.py` — benchmarks vs. other libraries.
- `Cargo.toml` — Rust deps, build config, feature-gated test targets.
- `pyproject.toml` — maturin build config, Python dev tooling, pytest config.

## Tests

- `tests/python/` — pytest integration tests against the Python API (require `maturin develop`).
- `tests/rust/` — Rust integration, property, and test-vector suites (vector suites need `--features test-vectors`).
- `tests/vectors/` — official PASETO test vectors (`v2.json`, `v3.json`, `v4.json`).

## Adding Functionality

### New Python Function
1. Implement in `src/bindings.rs` with `#[pyfunction]`.
2. Register in `src/lib.rs` via `wrap_pyfunction!`.
3. Add the signature to `fast_paseto.pyi`.
4. `maturin develop` to rebuild.
5. Add tests in `tests/python/`; verify with `cargo test && pytest`.

### New Python Class
1. Create a focused module in `src/` (e.g., `src/my_class.rs`).
2. `#[pyclass]` on the struct, `#[pymethods]` on the impl.
3. `pub use` from `lib.rs` and register with `.add_class::<MyClass>()`.
4. Add stubs to `fast_paseto.pyi`; `maturin develop`; add tests.

### Modifying Existing API
1. Update the Rust implementation.
2. Update `fast_paseto.pyi` to match.
3. `maturin develop`; update affected tests.
4. `uvx ty check`, then `cargo test && pytest`.

## Hard Constraints

1. All crypto in Rust — never in Python.
2. Rebuild with `maturin develop` after every `src/` change.
3. Keep `fast_paseto.pyi` exactly in sync with the Python-facing API.
4. Keep Python runtime dependencies minimal (pure Rust extension).
5. Python 3.11+, Rust 2024 edition only.
6. One responsibility per module; put unit tests in a `#[cfg(test)]` block at the file bottom.
