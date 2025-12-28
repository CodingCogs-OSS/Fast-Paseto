---
inclusion: always
---

# Project Structure

## Directory Layout

```
fast-paseto/
├── src/                    # Rust source code (all crypto logic lives here)
│   ├── lib.rs             # PyO3 module entry point, re-exports public API
│   ├── bindings.rs        # PyO3 function bindings for Python
│   ├── claims_manager.rs  # JWT-like claims handling (exp, iat, etc.)
│   ├── error.rs           # Error types using thiserror
│   ├── exceptions.rs      # Python exception mappings
│   ├── key_generator.rs   # Cryptographic key generation
│   ├── key_manager.rs     # Key storage and management
│   ├── pae.rs             # Pre-Authentication Encoding (PASETO spec)
│   ├── paseto.rs          # Main Paseto class implementation
│   ├── payload.rs         # Token payload structures
│   ├── token.rs           # Token data container
│   ├── token_generator.rs # Token creation logic
│   ├── token_verifier.rs  # Token verification logic
│   └── version.rs         # PASETO version handling (v2, v3, v4)
├── tests/
│   ├── python/            # Python integration tests (pytest)
│   └── rust/              # Rust unit/property tests
├── Cargo.toml             # Rust manifest (cdylib target)
├── pyproject.toml         # Python config (maturin backend)
├── fast_paseto.pyi        # Python type stubs (keep in sync with API)
└── main.py                # Example usage only, not part of package
```

## Architecture

### Rust-Python Bridge Pattern
- Rust owns all cryptographic operations (security + performance)
- PyO3 exposes Rust to Python via `#[pyfunction]`, `#[pyclass]`, `#[pymethods]`
- `lib.rs` is the module entry point; `bindings.rs` contains function bindings
- Type stubs (`fast_paseto.pyi`) must mirror the Python-facing API exactly

### Module Responsibilities
| Module | Purpose |
|--------|---------|
| `lib.rs` | `#[pymodule]` definition, re-exports |
| `bindings.rs` | `#[pyfunction]` implementations |
| `paseto.rs` | `Paseto` class with configurable defaults |
| `token.rs` | Immutable `Token` container returned from decode |
| `error.rs` | `PasetoError` enum with `thiserror` |
| `exceptions.rs` | `From<PasetoError> for PyErr` conversions |

### Build Pipeline
1. Cargo compiles Rust → `cdylib` (shared library)
2. Maturin packages as Python wheel
3. `maturin develop` installs editable for local dev

## File Modification Rules

### Rust Changes (`src/*.rs`)
1. Run `maturin develop` after every change (required)
2. New Python-facing functions → add to `bindings.rs`, register in `lib.rs`
3. New Python-facing classes → add `#[pyclass]` in dedicated module
4. Update `fast_paseto.pyi` when changing any Python API signature
5. Run `cargo test` then `pytest` to verify

### Python Test Changes (`tests/python/`)
- Use pytest conventions (`test_*.py`, `def test_*`)
- Tests require `maturin develop` first or imports fail
- Property-based tests use `hypothesis`

### Type Stub Changes (`fast_paseto.pyi`)
- Must stay synchronized with Rust `#[pyfunction]`/`#[pyclass]` signatures
- Run `uvx ty check` to validate stubs

### Dependency Changes
| Type | Location |
|------|----------|
| Rust runtime | `Cargo.toml` → `[dependencies]` |
| Rust dev-only | `Cargo.toml` → `[dev-dependencies]` |
| Python dev | `pyproject.toml` → `[project.optional-dependencies]` |
| Build system | `pyproject.toml` → `[build-system.requires]` |

## Key Constraints

- **No Python runtime deps**: Pure Rust extension, no `[project.dependencies]`
- **Crypto stays in Rust**: Never implement cryptographic operations in Python
- **Rebuild required**: Any `src/` change needs `maturin develop` before testing
- **Type stubs required**: All public API must have corresponding `.pyi` entries
- **Python 3.11+**: Minimum supported version
- **Rust 2024 edition**: Use modern Rust idioms
