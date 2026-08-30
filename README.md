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

Time per operation, lower is better. Measured on Python 3.11 / Windows 11 (i7-13xxH) with a
release build. Every library performs the same logical work: v4 tokens, the same claims dict,
JSON serialization included.

| Operation | fast-paseto | [pyseto](https://github.com/dajiaji/pyseto) | [python-paseto](https://github.com/purificant/python-paseto) | [pypaseto](https://github.com/rlittlefield/pypaseto) | [PyJWT](https://github.com/jpadilla/pyjwt) |
|-----------|-------------|--------|---------------|----------|-------|
| generate symmetric key | **0.11 µs** | 1.03 µs | 0.67 µs | 0.47 µs | 0.18 µs |
| generate keypair | **14.2 µs** | 74.5 µs | 27.7 µs | 26.1 µs | 30.4 µs |
| v4.local encode | **4.33 µs** | 19.0 µs | 8.98 µs | 13.1 µs | 9.28 µs |
| v4.local decode | **4.02 µs** | 21.5 µs | 9.68 µs | 12.6 µs | 11.4 µs |
| v4.public encode (sign) | 35.8 µs | 40.0 µs | 32.3 µs | **32.0 µs** | 36.5 µs |
| v4.public decode (verify) | **34.9 µs** | 99.9 µs | 86.4 µs | 87.6 µs | 94.1 µs |

Relative to fast-paseto (higher means slower than fast-paseto):

| Operation | pyseto | python-paseto | pypaseto | PyJWT |
|-----------|--------|---------------|----------|-------|
| generate symmetric key | 9.3x | 6.1x | 4.3x | 1.7x |
| generate keypair | 5.2x | 1.9x | 1.8x | 2.1x |
| v4.local encode | 4.4x | 2.1x | 3.0x | 2.1x |
| v4.local decode | 5.3x | 2.4x | 3.1x | 2.8x |
| v4.public encode (sign) | 1.1x | 0.9x | 0.9x | 1.0x |
| v4.public decode (verify) | 2.9x | 2.5x | 2.5x | 2.7x |

Reading the numbers:

- Symmetric paths are where the Rust core pays off most: 4-5x faster than the other PASETO
  libraries on encode/decode, and roughly 9x on key generation versus pyseto.
- Ed25519 **signing** is a wash. The libsodium-backed libraries edge ahead by roughly 10%,
  because that operation is dominated by the same underlying primitive everywhere.
  Ed25519 **verification** is ~2.5x faster in fast-paseto.
- PyJWT is included as a reference point, not a like-for-like comparison. Its "local" rows are
  HS256, which is *signed but not encrypted*, so it is doing strictly less work than a PASETO
  local token yet still comes out slower.

### Running the benchmarks

```bash
python profiling/benchmark.py                     # all libraries
python profiling/benchmark.py --only pyseto pyjwt  # a subset
python profiling/benchmark.py --json out.json     # keep the raw timings
```

`python-paseto` and `pypaseto` both ship a top-level `paseto` module, so they cannot be
installed side by side. The benchmark works around this by measuring each library in its own
throwaway environment via `uv run --no-project --with <package>`; nothing but fast-paseto needs
to be present in your venv.

Both of those libraries also bind libsodium through `pysodium`, so it must be installed for
their rows to appear:

```bash
sudo apt install libsodium23        # Debian/Ubuntu
brew install libsodium              # macOS
# Windows: put libsodium.dll on PATH, or point LIBSODIUM_DIR at its folder
```

Libraries that cannot be loaded are reported as unavailable with the reason, rather than
silently dropped from the table.

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
