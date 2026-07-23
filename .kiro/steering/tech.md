# Technology Stack

## Core Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Rust | Edition 2024 | All cryptographic operations and core logic |
| Python | 3.11+ | User-facing API |
| PyO3 | 0.27.0 | Rust ↔ Python FFI bindings |
| Maturin | >=1.10,<2.0 | Build tool (bridges Cargo + Python packaging) |
| uv | latest | Python environment & dependency management |

Crate type is `["cdylib", "rlib"]`; the module is named `fast_paseto`.

## Key Rust Dependencies

- Crypto: `chacha20poly1305`, `chacha20`, `blake2`, `ed25519-dalek`, `p384` (ECDSA), `aes`, `ctr`, `hmac`, `hkdf`, `sha2`, `argon2`, `subtle` (constant-time compares).
- Encoding/serialization: `base64`, `hex`, `pem`, `serde`, `serde_json`.
- Errors: `thiserror`.
- Dev/test: `proptest` (property tests).

## Critical Rules

### Build
- **ALWAYS run `maturin develop` after ANY change to `src/*.rs`** — otherwise Python imports use a stale build (`ImportError`).
- Use `uv` for the Python environment (not raw pip/venv). Never use `pip install -e .` (wrong build tool).
- Windows activation: `.venv\Scripts\activate`.

### Cryptographic Constraints
- ALL crypto MUST stay in Rust — never implement crypto in Python.
- Validate key lengths at runtime; incorrect sizes must raise `PasetoKeyError`.
- Use constant-time comparisons (`subtle`) for sensitive data.

### Dependency Placement
| Dependency Type | File | Section |
|-----------------|------|---------|
| Rust runtime | `Cargo.toml` | `[dependencies]` |
| Rust dev/test | `Cargo.toml` | `[dev-dependencies]` |
| Python dev/test | `pyproject.toml` | `[dependency-groups] dev` |
| Build tools | `pyproject.toml` | `[build-system] requires` |

Keep Python runtime dependencies (`[project] dependencies`) minimal — this is a pure Rust extension. Test-only tools like `hypothesis` belong with the dev tooling, not runtime.

## Command Reference

### Setup
```bash
uv venv
.venv\Scripts\activate
maturin develop
```

### After Rust Changes
```bash
maturin develop && pytest
```

### Test Vectors (feature-gated)
Rust test-vector suites require the `test-vectors` feature:
```bash
cargo test --features test-vectors
```

### Pre-Commit / Full Checks
```bash
cargo fmt && cargo clippy && ruff format . && ruff check . && uvx ty check && cargo test && pytest
```
Or: `pre-commit run --all-files`

## Testing

| Test Type | Command | Requires |
|-----------|---------|----------|
| Rust unit/property tests | `cargo test` | Nothing |
| Rust test-vector suites | `cargo test --features test-vectors` | Nothing |
| Python integration tests | `pytest` | `maturin develop` first |

Property tests use `proptest` (Rust) and `hypothesis` (Python). Pytest runs on **pre-push** (not pre-commit) to keep commits fast.

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: cannot import name` | Missing rebuild | `maturin develop` |
| `pip install -e .` fails | Wrong build tool | Use `maturin develop` |
| Type stub mismatch | `fast_paseto.pyi` out of sync | Update stub, run `uvx ty check` |
| Crypto added in Python | Security/design violation | Move to Rust in `src/` |
