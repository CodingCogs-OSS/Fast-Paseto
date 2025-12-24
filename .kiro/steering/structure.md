# Project Structure

```
fast-paseto/
├── src/
│   └── lib.rs          # Rust library entry point, PyO3 module definition
├── Cargo.toml          # Rust dependencies and package config
├── Cargo.lock          # Rust dependency lockfile
├── pyproject.toml      # Python package config (maturin build backend)
├── main.py             # Python entry point / example usage
├── uv.lock             # Python dependency lockfile (uv)
└── .kiro/
    ├── steering/       # AI assistant guidance files
    └── specs/          # Feature specifications
```

## Key Files

### Rust Side
- `src/lib.rs`: Main module exposing Python bindings via `#[pymodule]`
- `Cargo.toml`: Defines crate as `cdylib` for Python extension

### Python Side
- `pyproject.toml`: Maturin build config, package metadata
- Module name: `fast_paseto` (importable after build)

## Conventions
- Rust code in `src/` directory
- Python bindings exposed through PyO3's `#[pyfunction]` and `#[pymodule]` macros
- Use `maturin develop` to build and install for local development
