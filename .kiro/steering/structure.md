---
inclusion: always
---

# Project Structure & Architecture

## Core Architecture Pattern

This is a **Rust-Python hybrid library** where:
- Rust (`src/`) implements ALL cryptographic operations and core logic
- Python bindings expose the API via PyO3
- Zero Python runtime dependencies (pure Rust extension)

## Critical File Locations

### Rust Core (`src/`)
- `lib.rs` - PyO3 module entry point, defines `#[pymodule]`, re-exports public types
- `bindings.rs` - All `#[pyfunction]` implementations exposed to Python
- `paseto.rs` - Main `Paseto` class with `#[pyclass]` and `#[pymethods]`
- `token.rs` - Immutable `Token` class returned from decode operations
- `error.rs` - `PasetoError` enum using `thiserror::Error`
- `exceptions.rs` - Converts Rust errors to Python exceptions via `From<PasetoError> for PyErr`
- `key_generator.rs` - Key generation functions
- `key_manager.rs` - Key storage and management
- `token_generator.rs` - Token creation logic
- `token_verifier.rs` - Token verification logic
- `claims_manager.rs` - Claims handling (exp, iat, etc.)
- `payload.rs` - Payload data structures
- `version.rs` - PASETO version handling (v2, v3, v4)
- `pae.rs` - Pre-Authentication Encoding implementation

### Python Interface
- `fast_paseto.pyi` - Type stubs defining the Python API surface (MUST stay in sync with Rust)
- `main.py` - Example usage only (not part of the library)

### Configuration
- `Cargo.toml` - Rust dependencies and build config (crate-type = "cdylib")
- `pyproject.toml` - Python packaging, maturin build config, dev dependencies

### Tests
- `tests/python/` - pytest integration tests (test Python API)
- `tests/rust/` - Rust unit and property tests
- `tests/vectors/` - Official PASETO test vectors in JSON format

## Module Responsibilities

| Module | What It Does | Key Exports |
|--------|--------------|-------------|
| `lib.rs` | Defines the Python module, registers functions/classes | `#[pymodule] fn fast_paseto(...)` |
| `bindings.rs` | Standalone Python functions | `encode()`, `decode()`, `generate_*()` |
| `paseto.rs` | Stateful Paseto class with defaults | `Paseto` class |
| `token.rs` | Decoded token container | `Token` class (immutable) |
| `error.rs` | Error types | `PasetoError` enum |
| `exceptions.rs` | Error conversion | `impl From<PasetoError> for PyErr` |

## Adding New Functionality

### Adding a New Python Function
1. Implement in `src/bindings.rs` with `#[pyfunction]` decorator
2. Register in `src/lib.rs` using `.add_function(wrap_pyfunction!(...))`
3. Add type signature to `fast_paseto.pyi`
4. Run `maturin develop` to rebuild
5. Add tests in `tests/python/`
6. Verify with `cargo test && pytest`

### Adding a New Python Class
1. Create dedicated module in `src/` (e.g., `src/my_class.rs`)
2. Use `#[pyclass]` on struct, `#[pymethods]` on impl block
3. Re-export from `src/lib.rs` using `pub use`
4. Register in `lib.rs` using `.add_class::<MyClass>()`
5. Add type stubs to `fast_paseto.pyi`
6. Run `maturin develop` to rebuild
7. Add tests in `tests/python/`

### Modifying Existing API
1. Update Rust implementation in appropriate `src/` file
2. Update `fast_paseto.pyi` to match new signature
3. Run `maturin develop` to rebuild
4. Update affected tests
5. Validate type stubs: `uvx ty check`
6. Run full test suite: `cargo test && pytest`

## Dependency Management

| Dependency Type | Location | Section | Example |
|----------------|----------|---------|---------|
| Rust runtime | `Cargo.toml` | `[dependencies]` | `ed25519-dalek`, `chacha20poly1305` |
| Rust dev/test | `Cargo.toml` | `[dev-dependencies]` | `proptest`, `serde_json` |
| Python dev/test | `pyproject.toml` | `[project.optional-dependencies]` | `pytest`, `hypothesis` |
| Build tools | `pyproject.toml` | `[build-system.requires]` | `maturin` |

**CRITICAL**: `[project.dependencies]` in `pyproject.toml` MUST remain empty (pure Rust extension).

## Workflow Rules

### After ANY Rust Change
```bash
maturin develop  # Rebuild the extension (REQUIRED)
```

### Before Committing
```bash
cargo fmt        # Format Rust code
cargo clippy     # Lint Rust code
ruff format .    # Format Python code
ruff check .     # Lint Python code
uvx ty check     # Validate type stubs
cargo test       # Run Rust tests
pytest           # Run Python tests
```

Or use: `pre-commit run --all-files`

### Testing Workflow
- Python tests REQUIRE `maturin develop` first (imports will fail otherwise)
- Rust tests can run standalone with `cargo test`
- Property tests use `hypothesis` (Python) and `proptest` (Rust)

## Hard Constraints

These rules MUST NOT be violated:

1. **No Python runtime dependencies** - `[project.dependencies]` stays empty
2. **All crypto in Rust** - Never implement cryptographic operations in Python
3. **Rebuild after Rust changes** - Always run `maturin develop` after editing `src/`
4. **Type stub sync** - `fast_paseto.pyi` must exactly match the Python-facing API
5. **Python 3.11+ only** - Minimum supported version
6. **Rust 2024 edition** - Use modern Rust idioms

## Common Pitfalls

- Forgetting to run `maturin develop` after Rust changes → ImportError
- Adding dependencies to `[project.dependencies]` → Violates design
- Implementing crypto in Python → Security risk
- Type stubs out of sync → Type checking fails
- Using `pip install -e .` → Wrong build tool (use `maturin develop`)
