---
inclusion: always
---

# Technology Stack

## Core Stack
| Technology | Version | Purpose |
|------------|---------|---------|
| Rust | Edition 2024 | Cryptographic operations, core logic |
| Python | 3.11+ | User-facing API |
| PyO3 | 0.27.0 | Rust-Python FFI bindings |
| Maturin | latest | Build tool (bridges Cargo + Python packaging) |

## Critical Rules

### Build Requirements
- **ALWAYS** run `maturin develop` after ANY change to `src/*.rs` files
- Python has ZERO runtime dependencies — pure Rust extension only
- Use `uv` for Python environment management (not pip/venv)
- Windows activation: `.venv\Scripts\activate` (not `source`)

### Cryptographic Constraints
- ALL crypto operations MUST remain in Rust — never implement in Python
- v4.local: XChaCha20-Poly1305 + BLAKE2b-MAC (32-byte symmetric key)
- v4.public: Ed25519 signatures (64-byte secret, 32-byte public key)
- Key lengths validated at runtime — incorrect sizes raise errors

## Command Reference

### Setup
```bash
uv venv && .venv\Scripts\activate && maturin develop
```

### After Rust Changes
```bash
maturin develop && pytest
```

### Pre-Commit Checks
```bash
cargo fmt && cargo clippy && ruff format . && ruff check . && uvx ty check && cargo test && pytest
```

Or: `pre-commit run --all-files`

## Testing

| Test Type | Command | Requires |
|-----------|---------|----------|
| Rust unit tests | `cargo test` | Nothing |
| Python integration | `pytest` | `maturin develop` first |

Pre-commit runs pytest on **pre-push** (not pre-commit) to avoid slow commits.

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: cannot import name` | Missing rebuild | Run `maturin develop` |
| `pip install -e .` fails | Wrong build tool | Use `maturin develop` |
| Python runtime dep added | Violates design | Remove from `[project.dependencies]` |
| Crypto implemented in Python | Security risk | Move to Rust in `src/` |
