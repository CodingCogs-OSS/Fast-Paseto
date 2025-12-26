---
inclusion: always
---

# Technology Stack

## Core Technologies
- **Rust (Edition 2024)**: All cryptographic operations and core logic
- **Python 3.11+**: User-facing API via PyO3 bindings
- **PyO3 0.27.0**: Rust-Python FFI layer
- **Maturin**: Build tool for PyO3 projects (bridges Cargo and Python packaging)

## Critical Build Rules
- After ANY Rust code changes in `src/`, run `maturin develop` to rebuild the extension
- Python has NO runtime dependencies - this is a pure Rust extension module
- Use `uv` for Python environment management (not pip/venv directly)
- Windows users: Use `.venv\Scripts\activate` instead of `source .venv/bin/activate`

## Development Workflow

### Initial Setup
```bash
uv venv
.venv\Scripts\activate  # Windows
maturin develop
```

### After Modifying Rust Code
```bash
maturin develop  # Required to see changes in Python
pytest           # Verify changes work
```

### Before Committing
```bash
cargo fmt        # Format Rust code
cargo clippy     # Lint Rust code
ruff format .    # Format Python code
ruff check .     # Lint Python code
uvx ty check     # Type check Python stubs
cargo test       # Run Rust unit tests
pytest           # Run Python integration tests
```

Or use pre-commit hooks:
```bash
pre-commit run --all-files
```

## Testing Strategy
- **Rust tests** (`cargo test`): Unit tests for internal logic, run in Rust
- **Python tests** (`pytest`): Integration tests for Python API, require `maturin develop` first
- Never skip `maturin develop` before running pytest - tests will fail with import errors
- Pre-commit runs pytest on pre-push (not pre-commit) to avoid slow commits

## Code Quality Tools
- **Rust**: `cargo fmt` (formatting), `cargo clippy` (linting)
- **Python**: `ruff format` (formatting), `ruff check` (linting), `uvx ty` (type checking)
- All configured in `.pre-commit-config.yaml` with auto-fix enabled where safe

## Cryptographic Standards (PASETO v4)
- **v4.local**: XChaCha20-Poly1305 encryption + BLAKE2b-MAC (32-byte symmetric key)
- **v4.public**: Ed25519 signatures (64-byte secret key, 32-byte public key)
- All crypto operations MUST stay in Rust - never implement in Python
- Key lengths are validated at runtime - incorrect sizes will error

## Common Pitfalls
- Forgetting `maturin develop` after Rust changes (most common error)
- Using `pip install -e .` instead of `maturin develop` (won't work)
- Trying to run pytest without building the extension first
- Adding Python runtime dependencies (violates pure-extension design)
- Implementing crypto in Python instead of Rust (security risk)
