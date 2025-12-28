---
inclusion: always
---

# Project Structure

## Directory Layout

```
fast-paseto/
├── src/                    # Rust source (ALL crypto logic here)
│   ├── lib.rs             # PyO3 module entry, re-exports
│   ├── bindings.rs        # #[pyfunction] bindings
│   ├── claims_manager.rs  # Claims handling (exp, iat)
│   ├── error.rs           # PasetoError with thiserror
│   ├── exceptions.rs      # PyErr mappings
│   ├── key_generator.rs   # Key generation
│   ├── key_manager.rs     # Key storage
│   ├── pae.rs             # Pre-Authentication Encoding
│   ├── paseto.rs          # Paseto class
│   ├── payload.rs         # Payload structures
│   ├── token.rs           # Token container
│   ├── token_generator.rs # Token creation
│   ├── token_verifier.rs  # Token verification
│   └── version.rs         # Version handling (v2, v3, v4)
├── tests/
│   ├── python/            # pytest integration tests
│   ├── rust/              # Rust unit/property tests
│   └── vectors/           # Official PASETO test vectors (JSON)
├── Cargo.toml             # Rust manifest (cdylib)
├── pyproject.toml         # Python config (maturin)
├── fast_paseto.pyi        # Type stubs (MUST sync with API)
└── main.py                # Example usage only
```

## Architecture Rules

### Rust-Python Bridge
- Rust owns ALL cryptographic operations
- PyO3 decorators: `#[pyfunction]`, `#[pyclass]`, `#[pymethods]`
- `lib.rs` = module entry; `bindings.rs` = function bindings
- `fast_paseto.pyi` MUST mirror Python-facing API exactly

### Module Mapping

| Module | Responsibility |
|--------|----------------|
| `lib.rs` | `#[pymodule]`, re-exports |
| `bindings.rs` | `#[pyfunction]` implementations |
| `paseto.rs` | `Paseto` class with defaults |
| `token.rs` | Immutable `Token` from decode |
| `error.rs` | `PasetoError` enum |
| `exceptions.rs` | `From<PasetoError> for PyErr` |

## Modification Checklist

### When Changing `src/*.rs`
1. Run `maturin develop` (REQUIRED after every change)
2. New Python function → add to `bindings.rs`, register in `lib.rs`
3. New Python class → `#[pyclass]` in dedicated module
4. API signature change → update `fast_paseto.pyi`
5. Verify: `cargo test && pytest`

### When Changing `tests/python/`
- Follow pytest conventions: `test_*.py`, `def test_*`
- Run `maturin develop` first or imports fail
- Property tests use `hypothesis`

### When Changing `fast_paseto.pyi`
- Sync with `#[pyfunction]`/`#[pyclass]` signatures
- Validate: `uvx ty check`

### Dependency Locations

| Type | File | Section |
|------|------|---------|
| Rust runtime | `Cargo.toml` | `[dependencies]` |
| Rust dev | `Cargo.toml` | `[dev-dependencies]` |
| Python dev | `pyproject.toml` | `[project.optional-dependencies]` |
| Build | `pyproject.toml` | `[build-system.requires]` |

## Hard Constraints

| Rule | Rationale |
|------|-----------|
| No `[project.dependencies]` | Pure Rust extension |
| Crypto in Rust only | Security requirement |
| `maturin develop` after `src/` changes | Rebuild required |
| All public API in `.pyi` | Type safety |
| Python 3.11+ | Minimum version |
| Rust 2024 edition | Modern idioms |
