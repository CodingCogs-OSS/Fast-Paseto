"""Type stubs for the `fast_paseto` package.

The full public API is declared in `_fast_paseto.pyi` (the compiled Rust
extension) and re-exported here, mirroring the runtime `__init__.py`.
"""

from ._fast_paseto import (
    Deserializer as Deserializer,
    Paseto as Paseto,
    PasetoCryptoError as PasetoCryptoError,
    PasetoError as PasetoError,
    PasetoExpiredError as PasetoExpiredError,
    PasetoKeyError as PasetoKeyError,
    PasetoNotYetValidError as PasetoNotYetValidError,
    PasetoValidationError as PasetoValidationError,
    Serializer as Serializer,
    Token as Token,
    decode as decode,
    ed25519_from_pem as ed25519_from_pem,
    ed25519_public_from_pem as ed25519_public_from_pem,
    encode as encode,
    from_paserk as from_paserk,
    generate_keypair as generate_keypair,
    generate_lid as generate_lid,
    generate_pid as generate_pid,
    generate_sid as generate_sid,
    generate_symmetric_key as generate_symmetric_key,
    local_pw_decrypt as local_pw_decrypt,
    local_pw_encrypt as local_pw_encrypt,
    local_unwrap as local_unwrap,
    local_wrap as local_wrap,
    secret_pw_decrypt as secret_pw_decrypt,
    secret_pw_encrypt as secret_pw_encrypt,
    secret_unwrap as secret_unwrap,
    secret_wrap as secret_wrap,
    to_paserk_local as to_paserk_local,
    to_paserk_public as to_paserk_public,
    to_paserk_secret as to_paserk_secret,
)
