---
inclusion: always
---

# Product Overview

fast-paseto is a high-performance PASETO (Platform-Agnostic Security Tokens) library implemented in Rust with Python bindings via PyO3.

## Core Purpose

Provide a secure, fast, and easy-to-use API for creating and verifying PASETO tokens in Python applications, leveraging Rust's performance and memory safety guarantees.

## Key Capabilities

### Token Operations
- **Local tokens** (symmetric): XChaCha20-Poly1305 encryption for confidential data
- **Public tokens** (asymmetric): Ed25519 signatures for verifiable, non-confidential data
- Support for v4 (primary), v3 (NIST-compliant), and v2 (legacy) protocols

### API Design Principles
- **Two usage patterns**: Module-level functions (`encode()`, `decode()`) for simple use cases; `Paseto` class for configurable defaults
- **Automatic claim management**: Optional auto-injection of `exp` (expiration) and `iat` (issued-at) claims
- **Flexible serialization**: JSON by default, custom serializers supported via Protocol
- **Type safety**: Full type stubs provided in `fast_paseto.pyi`

### Security Features
- Cryptographic operations handled entirely in Rust
- Time-based claim validation with configurable leeway
- Footer and implicit assertion support per PASETO spec
- Proper key length validation (32 bytes symmetric, 64 bytes secret, 32 bytes public)

## Design Constraints

- **No runtime Python dependencies**: Pure Rust extension module
- **Python 3.11+ only**: Leverages modern Python features
- **v4 tokens are default**: Older versions require explicit version parameter
- **Immutable Token objects**: Decoded tokens are read-only data containers

## Target Users

Python developers building authentication systems who need:
- Better security defaults than JWT
- High performance token operations
- Type-safe token handling
- Protection against common JWT vulnerabilities (algorithm confusion, weak signatures)

## Anti-Patterns to Avoid

- Don't use PASETO for session storage (use local tokens with short expiration instead)
- Don't put sensitive data in public tokens (they're signed, not encrypted)
- Don't reuse keys across different purposes (local vs public)
- Don't implement custom crypto - use provided key generation functions
