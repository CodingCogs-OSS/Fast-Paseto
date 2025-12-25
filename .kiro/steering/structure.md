---
inclusion: always
---

# Project Structure

## Directory Layout

```
fast-paseto/
├── src/                    # Rust source code
│   ├── lib.rs             # PyO3 module definition and Python bindings
│   ├── claims_manager.rs  # JWT-like claims handling
│   ├── error.rs           # Error types and conversions
│   ├── key_generator.rs   # Cryptographic key generation
│   ├── pae.rs             # Pre-Authentication Encoding
│   ├── payload.rs         # Token payload structures
│   ├── token_generator.rs # Token creation logic
│   ├── token_verifier.rs  # Token verification logic
│   └── version.rs         # PASETO version handling
├── tests/                 # Python test suite (pytest)
├── Cargo.toml             # Rust package manifest (cdylib)
├── pyproject.toml         # Python package config (maturin backend)
├── fast_paseto.pyi        # Python type stubs
└── main.py                # Example usage / manual testing
```

## Architecture Patterns

### Rust-Python Bridge
- Rust implements core cryptographic operations for performance and safety
- PyO3 exposes Rust functions/classes to Python via `#[pyfunction]`, `#[pyclass]`, `#[pymodule]`
- Python provides the user-facing API surface
- Type stubs in `fast_paseto.pyi` provide IDE support

### Module Organization
- `lib.rs`: Entry point, defines `#[pymodule] fn fast_paseto`
- Separate modules for distinct concerns (claims, keys, tokens, errors)
- Error types implement `From` traits for PyO3 exception conversion
- All public Rust APIs must be exposed through `lib.rs` module

### Build System
- Cargo builds Rust as `cdylib` (C-compatible dynamic library)
- Maturin bridges Cargo and Python packaging
- `maturin develop` for local development (editable install)
- `maturin build` for distribution wheels

## File Modification Guidelines

### When modifying Rust code:
- Changes in `src/*.rs` require `maturin develop` to rebuild
- Add new Python-facing functions to `lib.rs` with `#[pyfunction]`
- Update `fast_paseto.pyi` type stubs when changing Python API
- Run `cargo test` for Rust unit tests, `pytest` for integration tests

### When modifying Python code:
- `main.py` is for examples only, not part of the package
- Tests go in `tests/` directory using pytest conventions
- No Python runtime code in package (pure Rust extension)

### When adding dependencies:
- Rust deps: Add to `Cargo.toml` under `[dependencies]`
- Python dev deps: Add to `pyproject.toml` under `[project.optional-dependencies]`
- Build deps: Add to `[build-system.requires]` in `pyproject.toml`

## Key Conventions

- Module name: `fast_paseto` (importable after `maturin develop`)
- Rust edition: 2024
- Python version: 3.11+ required
- All cryptographic operations stay in Rust (never implement in Python)
- Error handling: Rust errors convert to Python exceptions via PyO3
- Testing: Rust unit tests in `src/`, Python integration tests in `tests/`
