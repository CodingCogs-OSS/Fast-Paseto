# fast-paseto

A high-performance [PASETO](https://paseto.io/) (Platform-Agnostic Security Tokens) library with a Rust core and Python bindings via PyO3.

## Features

- **Blazing fast** — Cryptographic operations implemented in Rust
- **Zero Python dependencies** — Pure Rust extension module
- **Type-safe** — Full type hints with `.pyi` stubs
- **PASETO v2, v3, v4** — All modern versions supported
- **PASERK support** — Key serialization, wrapping, and password protection
- **PEM key loading** — Import Ed25519 keys from standard PEM format

## Performance

Benchmarked against [pyseto](https://github.com/dajiaji/pyseto), the most popular Python PASETO library.

| Operation | fast-paseto | pyseto | Speedup |
|-----------|-------------|--------|---------|
| generate_symmetric_key | 0.2 µs | 1.1 µs | 6x |
| generate_keypair | 16 µs | 80 µs | 5x |
| v4.local encode | 5 µs | 16 µs | 3x |
| v4.local decode | 5 µs | 18 µs | 3.5x |
| v4.public encode (sign) | 43 µs | 41 µs | ~1x |
| v4.public decode (verify) | 37 µs | 98 µs | 2.7x |

Note: [python-paseto](https://github.com/purificant/python-paseto) requires libsodium and was excluded from benchmarks.

Run benchmarks yourself: `python profiling/benchmark.py`

## Installation

```bash
pip install fast-paseto
```

## Quick Start

### Local Tokens (Symmetric Encryption)

```python
import fast_paseto

# Generate a random 32-byte symmetric key
key = fast_paseto.generate_symmetric_key()

# Create an encrypted token
token = fast_paseto.encode(
    key=key,
    payload={"user_id": 123, "role": "admin"},
    purpose="local",
)
# => "v4.local...."

# Decode and verify the token
decoded = fast_paseto.decode(token, key, purpose="local")
print(decoded.payload)  # {"user_id": 123, "role": "admin"}
```

### Public Tokens (Asymmetric Signatures)

```python
import fast_paseto

# Generate an Ed25519 keypair
secret_key, public_key = fast_paseto.generate_keypair()

# Create a signed token (not encrypted!)
token = fast_paseto.encode(
    key=secret_key,
    payload={"user_id": 123, "permissions": ["read", "write"]},
    purpose="public",
)
# => "v4.public...."

# Verify the signature and decode
decoded = fast_paseto.decode(token, public_key, purpose="public")
print(decoded.payload)  # {"user_id": 123, "permissions": ["read", "write"]}
```

## Using the Paseto Class

For applications that need consistent defaults across multiple tokens:

```python
from fast_paseto import Paseto, generate_symmetric_key

# Create a configured instance
paseto = Paseto(
    default_exp=3600,    # Tokens expire in 1 hour
    include_iat=True,    # Auto-add issued-at timestamp
    leeway=60,           # Allow 60s clock skew on verification
)

key = generate_symmetric_key()

# Encode with automatic exp/iat claims
token = paseto.encode(key, {"user_id": 123})

# Decode with leeway applied
decoded = paseto.decode(token, key)
print(decoded["user_id"])  # 123
```

## Token Types

| Type | Purpose | Use Case |
|------|---------|----------|
| `local` | Symmetric encryption | Confidential data between trusted parties |
| `public` | Asymmetric signatures | Verifiable claims (not encrypted!) |

## Supported Versions

| Version | Local (Encryption) | Public (Signatures) |
|---------|-------------------|---------------------|
| v4 (default) | XChaCha20-Poly1305 | Ed25519 |
| v3 | AES-256-CTR + HMAC-SHA384 | ECDSA P-384 |
| v2 | XChaCha20-Poly1305 | Ed25519 |

## Key Management (PASERK)

### Key Serialization

```python
import fast_paseto

key = fast_paseto.generate_symmetric_key()

# Serialize to PASERK format
paserk = fast_paseto.to_paserk_local(key)
# => "k4.local.AAAA..."

# Deserialize back
key_type, key_bytes = fast_paseto.from_paserk(paserk)
```

### Key IDs

```python
# Generate deterministic key identifiers
lid = fast_paseto.generate_lid(symmetric_key)   # k4.lid.XXXX...
sid = fast_paseto.generate_sid(secret_key)      # k4.sid.XXXX...
pid = fast_paseto.generate_pid(public_key)      # k4.pid.XXXX...
```

### Key Wrapping

```python
# Wrap a key with another key
wrapping_key = fast_paseto.generate_symmetric_key()
wrapped = fast_paseto.local_wrap(key, wrapping_key)

# Unwrap
original_key = fast_paseto.local_unwrap(wrapped, wrapping_key)
```

### Password-Protected Keys

```python
# Encrypt a key with a password (uses Argon2id)
encrypted = fast_paseto.local_pw_encrypt(key, "my-secure-password")

# Decrypt with password
decrypted_key = fast_paseto.local_pw_decrypt(encrypted, "my-secure-password")
```

## Loading PEM Keys

```python
import fast_paseto

# Load Ed25519 private key from PEM
with open("private_key.pem") as f:
    secret_key = fast_paseto.ed25519_from_pem(f.read())

# Load Ed25519 public key from PEM
with open("public_key.pem") as f:
    public_key = fast_paseto.ed25519_public_from_pem(f.read())
```

## Custom Serialization

```python
import msgpack
import fast_paseto

class MsgPackSerializer:
    def dumps(self, obj):
        return msgpack.packb(obj)

class MsgPackDeserializer:
    def loads(self, data):
        return msgpack.unpackb(data)

token = fast_paseto.encode(
    key=key,
    payload={"data": [1, 2, 3]},
    serializer=MsgPackSerializer(),
)

decoded = fast_paseto.decode(
    token,
    key,
    deserializer=MsgPackDeserializer(),
)
```

## Footers and Implicit Assertions

```python
# Add a footer (included in token, not encrypted)
token = fast_paseto.encode(
    key=key,
    payload={"user_id": 123},
    footer={"kid": "key-001"},
)

# Add implicit assertion (not in token, must match on decode)
token = fast_paseto.encode(
    key=key,
    payload={"user_id": 123},
    implicit_assertion=b"context-data",
)

decoded = fast_paseto.decode(
    token,
    key,
    implicit_assertion=b"context-data",  # Must match!
)
```

## Error Handling

```python
from fast_paseto import (
    PasetoError,
    PasetoKeyError,
    PasetoCryptoError,
    PasetoExpiredError,
    PasetoNotYetValidError,
)

try:
    decoded = fast_paseto.decode(token, key)
except PasetoExpiredError:
    print("Token has expired")
except PasetoKeyError:
    print("Invalid key")
except PasetoCryptoError:
    print("Decryption/verification failed")
except PasetoError as e:
    print(f"PASETO error: {e}")
```

## Key Lengths

| Key Type | Length | Token Type |
|----------|--------|------------|
| Symmetric | 32 bytes | local |
| Ed25519 Secret | 64 bytes | public (signing) |
| Ed25519 Public | 32 bytes | public (verification) |

## Development

### Prerequisites

- Python 3.11+
- Rust (2024 edition)
- [uv](https://docs.astral.sh/uv/) for Python environment management
- [maturin](https://www.maturin.rs/) for building

### Setup

```bash
uv venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/macOS
maturin develop
```

### Running Tests

```bash
# Rust tests
cargo test

# Python tests (requires maturin develop first)
pytest

# All checks
cargo fmt && cargo clippy && ruff format . && ruff check . && cargo test && pytest
```

## License

MIT

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=CodingCogs-OSS/Fast-Paseto&type=date&legend=top-left)](https://www.star-history.com/#CodingCogs-OSS/Fast-Paseto&type=date&legend=top-left)
