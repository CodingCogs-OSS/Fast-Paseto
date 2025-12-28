---
inclusion: always
---

# Product Overview

fast-paseto is a high-performance PASETO library: Rust core with Python bindings via PyO3.

## What This Library Does

| Token Type | Crypto | Use Case |
|------------|--------|----------|
| `local` (symmetric) | XChaCha20-Poly1305 | Encrypted confidential data |
| `public` (asymmetric) | Ed25519 | Signed verifiable data (not encrypted) |

Supported versions: v4 (default), v3 (NIST), v2 (legacy)

## API Patterns

Two usage styles exist:

1. **Module functions** — `encode()`, `decode()` for one-off operations
2. **Paseto class** — Configurable instance with defaults (expiration, serializer, etc.)

Key behaviors:
- Auto-injects `exp` and `iat` claims when configured
- JSON serialization by default; custom serializers via Protocol
- Returns immutable `Token` objects from decode operations

## Code Generation Rules

When generating code for this library:

| Do | Don't |
|----|-------|
| Use `generate_symmetric_key()` for local tokens | Hardcode or generate keys manually |
| Use `generate_asymmetric_keypair()` for public tokens | Implement any crypto in Python |
| Default to v4 unless user specifies otherwise | Mix key types across token purposes |
| Validate key lengths (32B symmetric, 64B secret, 32B public) | Put sensitive data in public tokens |
| Use type stubs from `fast_paseto.pyi` for signatures | Add Python runtime dependencies |

## Key Lengths

| Key Type | Length | Token Type |
|----------|--------|------------|
| Symmetric | 32 bytes | local |
| Secret (private) | 64 bytes | public |
| Public | 32 bytes | public |

## Common Mistakes to Prevent

- Using public tokens for confidential data (they're signed, not encrypted)
- Reusing keys between local and public token operations
- Implementing cryptographic operations outside Rust
- Using PASETO for long-lived session storage (prefer short expiration)
- Forgetting to rebuild with `maturin develop` after Rust changes
