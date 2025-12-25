"""Type stubs for fast_paseto Rust extension module."""

from typing import Any, Dict, Optional, Union

class PasetoError(Exception):
    """Base exception for all PASETO errors."""

    ...

class PasetoValidationError(PasetoError):
    """Base exception for validation errors."""

    ...

class PasetoKeyError(PasetoValidationError):
    """Exception raised for key-related errors."""

    ...

class PasetoCryptoError(PasetoValidationError):
    """Exception raised for cryptographic operation failures."""

    ...

class PasetoExpiredError(PasetoValidationError):
    """Exception raised when a token has expired."""

    ...

class PasetoNotYetValidError(PasetoValidationError):
    """Exception raised when a token is not yet valid."""

    ...

class Token:
    """Represents a decoded PASETO token."""

    payload: Dict[str, Any]
    footer: Optional[Dict[str, Any]]
    version: str
    purpose: str

    def __init__(
        self,
        payload: Dict[str, Any],
        footer: Optional[Dict[str, Any]],
        version: str,
        purpose: str,
    ) -> None: ...
    def __getitem__(self, key: str) -> Any: ...
    def __contains__(self, key: str) -> bool: ...
    def to_dict(self) -> Dict[str, Any]: ...

def generate_symmetric_key() -> bytes:
    """Generate a random 32-byte symmetric key for v4.local tokens."""
    ...

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair for v4.public tokens.

    Returns:
        tuple: (secret_key, public_key) where secret_key is 64 bytes and public_key is 32 bytes
    """
    ...

def encode(
    key: Union[bytes, str],
    payload: Dict[str, Any],
    purpose: str,
    footer: Optional[Dict[str, Any]] = None,
    implicit_assertion: Optional[bytes] = None,
) -> str:
    """Encode a PASETO token.

    Args:
        key: Symmetric key (32 bytes) for local tokens or secret key (64 bytes) for public tokens
        payload: Dictionary containing the token claims
        purpose: Either "local" or "public"
        footer: Optional footer dictionary
        implicit_assertion: Optional implicit assertion bytes

    Returns:
        str: The encoded PASETO token

    Raises:
        PasetoKeyError: If the key is invalid
        PasetoError: If encoding fails
    """
    ...

def decode(
    token: str,
    key: Union[bytes, str],
    purpose: str,
    footer: Optional[Dict[str, Any]] = None,
    implicit_assertion: Optional[bytes] = None,
) -> Token:
    """Decode and verify a PASETO token.

    Args:
        token: The PASETO token string to decode
        key: Symmetric key (32 bytes) for local tokens or public key (32 bytes) for public tokens
        purpose: Either "local" or "public"
        footer: Optional expected footer dictionary
        implicit_assertion: Optional implicit assertion bytes

    Returns:
        Token: The decoded token object

    Raises:
        PasetoKeyError: If the key is invalid
        PasetoCryptoError: If verification fails
        PasetoExpiredError: If the token has expired
        PasetoNotYetValidError: If the token is not yet valid
        PasetoError: If decoding fails
    """
    ...
