# Technology Stack

## Languages
- Rust (core implementation)
- Python (bindings and user-facing API)

## Build System
- Maturin: Rust-Python build tool for PyO3 projects
- Cargo: Rust package manager

## Key Dependencies
- PyO3 (0.27.0): Rust bindings for Python
- Rust Edition 2024

## Python Requirements
- Python 3.11+
- No runtime Python dependencies (pure Rust extension)

## Common Commands

### Development Setup
```bash
# Create virtual environment
uv venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode
maturin develop
```

### Building
```bash
# Build release wheel
maturin build --release

# Build and install locally
maturin develop --release
```

### Testing
```bash
# Run Rust tests
cargo test

# Run Python tests (after maturin develop)
pytest
```

### Linting & Formatting
```bash
# Rust
cargo fmt
cargo clippy

# Python
ruff check .
ruff format .

# Type checking
uvx ty check
```

### Pre-commit Hooks
```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run all hooks manually
pre-commit run --all-files
```

Configured hooks:
- ty: Type checking (via uvx)
- ruff: Linting with auto-fix
- ruff-format: Code formatting
- pytest: Tests (on pre-push)

## Cryptographic Algorithms (v4 - Primary)
- v4.local: XChaCha20 + BLAKE2b-MAC (32-byte key)
- v4.public: Ed25519 (64-byte secret, 32-byte public)
