# Product Overview

fast-paseto is a high-performance [PASETO](https://paseto.io/) (Platform-Agnostic Security Tokens) library: a Rust core exposed to Python via PyO3. It aims to be significantly faster than pure-Python alternatives (benchmarked against `pyseto`) while keeping a clean, type-hinted Python API.

## Token Types

| Type | Crypto (v4) | Use Case |
|------|-------------|----------|
| `local` (symmetric) | XChaCha20-Poly1305 | Encrypted, confidential data |
| `public` (asymmetric) | Ed25519 signatures | Signed, verifiable data (NOT encrypted) |

## Supported Versions

| Version | Local (encryption) | Public (signatures) |
|---------|--------------------|----------------------|
| v4 (default) | XChaCha20-Poly1305 | Ed25519 |
| v3 (NIST) | AES-256-CTR + HMAC-SHA384 | ECDSA P-384 |
| v2 (legacy) | XChaCha20-Poly1305 | Ed25519 |

## API Surface

Two usage styles:

1. **Module functions** — `encode()`, `decode()`, `generate_symmetric_key()`, `generate_keypair()` for one-off operations.
2. **`Paseto` class** — Configurable instance with defaults: `default_exp`, `include_iat`, `leeway`.

Additional capabilities:
- **PASERK** — key serialization (`to_paserk_local/secret/public`, `from_paserk`), key IDs (`generate_lid/sid/pid`), key wrapping (`local_wrap/unwrap`, `secret_wrap/unwrap`), password protection with Argon2id (`local_pw_encrypt/decrypt`, `secret_pw_encrypt/decrypt`).
- **PEM loading** — `ed25519_from_pem`, `ed25519_public_from_pem`.
- **Footers & implicit assertions** — supported on encode/decode.
- **Custom serialization** — JSON by default; pass an object implementing the `Serializer`/`Deserializer` protocol.
- Auto-injects `exp`/`iat` claims when configured on a `Paseto` instance.
- `decode()` returns an immutable `Token` (supports attribute access, `[]`, `in`, `to_dict()`).

## Key Lengths

| Key Type | Length | Token Type |
|----------|--------|------------|
| Symmetric | 32 bytes | local |
| Ed25519 secret | 64 bytes | public (signing) |
| Ed25519 public | 32 bytes | public (verification) |

## Code Generation Rules

| Do | Don't |
|----|-------|
| Use `generate_symmetric_key()` for local tokens | Hardcode or hand-roll keys |
| Use `generate_keypair()` for public tokens | Implement any crypto in Python |
| Default to v4 unless the user specifies otherwise | Mix key types across purposes |
| Validate key lengths (32B symmetric, 64B secret, 32B public) | Put confidential data in public tokens (signed, not encrypted) |
| Match signatures to `fast_paseto.pyi` | Use PASETO for long-lived session storage (prefer short exp) |
