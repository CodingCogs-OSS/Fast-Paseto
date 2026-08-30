"""fast-paseto: high-performance PASETO tokens implemented in Rust.

The public API is implemented in the compiled Rust extension module
``fast_paseto._fast_paseto`` and re-exported here so that ``import fast_paseto``
exposes everything directly.

The ``Serializer`` / ``Deserializer`` typing protocols are declared in the
accompanying ``__init__.pyi`` stub only; they are structural (duck-typed) and
have no runtime object here.
"""

from ._fast_paseto import (
    Paseto,
    PasetoCryptoError,
    PasetoError,
    PasetoExpiredError,
    PasetoKeyError,
    PasetoNotYetValidError,
    PasetoValidationError,
    Token,
    decode,
    ed25519_from_pem,
    ed25519_public_from_pem,
    encode,
    from_paserk,
    generate_keypair,
    generate_lid,
    generate_pid,
    generate_sid,
    generate_symmetric_key,
    local_pw_decrypt,
    local_pw_encrypt,
    local_unwrap,
    local_wrap,
    secret_pw_decrypt,
    secret_pw_encrypt,
    secret_unwrap,
    secret_wrap,
    to_paserk_local,
    to_paserk_public,
    to_paserk_secret,
)

__all__ = [
    "Paseto",
    "PasetoCryptoError",
    "PasetoError",
    "PasetoExpiredError",
    "PasetoKeyError",
    "PasetoNotYetValidError",
    "PasetoValidationError",
    "Token",
    "decode",
    "ed25519_from_pem",
    "ed25519_public_from_pem",
    "encode",
    "from_paserk",
    "generate_keypair",
    "generate_lid",
    "generate_pid",
    "generate_sid",
    "generate_symmetric_key",
    "local_pw_decrypt",
    "local_pw_encrypt",
    "local_unwrap",
    "local_wrap",
    "secret_pw_decrypt",
    "secret_pw_encrypt",
    "secret_unwrap",
    "secret_wrap",
    "to_paserk_local",
    "to_paserk_public",
    "to_paserk_secret",
]
