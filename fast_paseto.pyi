"""Type stubs for fast_paseto Rust extension module."""

from typing import Any, Dict, Optional, Protocol, Union

class Serializer(Protocol):
    """Protocol for custom serializers."""
    def dumps(self, obj: Any) -> Union[bytes, str]: ...

class Deserializer(Protocol):
    """Protocol for custom deserializers."""
    def loads(self, data: Union[bytes, str]) -> Any: ...

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

    payload: Any
    footer: Optional[Any]
    version: str
    purpose: str

    def __init__(
        self,
        payload: Any,
        footer: Optional[Any],
        version: str,
        purpose: str,
    ) -> None: ...
    def __getitem__(self, key: str) -> Any: ...
    def __contains__(self, key: str) -> bool: ...
    def to_dict(self) -> Dict[str, Any]: ...

class Paseto:
    """Configurable Paseto instance with preset defaults.

    A Paseto instance allows you to configure default behavior for token
    operations, such as automatic expiration times, issued-at timestamps,
    and time-based claim validation leeway.

    Attributes:
        default_exp: Default expiration time in seconds (added to current time)
        include_iat: Whether to automatically include issued-at (iat) claim
        leeway: Time tolerance in seconds for time-based claim validation
    """

    default_exp: Optional[int]
    include_iat: bool
    leeway: int

    def __init__(
        self,
        default_exp: Optional[int] = None,
        include_iat: bool = True,
        leeway: int = 0,
    ) -> None:
        """Create a new Paseto instance with configuration.

        Args:
            default_exp: Default expiration time in seconds (added to current time).
                         If set, tokens will automatically get an exp claim. Default: None
            include_iat: Whether to automatically include issued-at (iat) claim.
                         Default: True
            leeway: Time tolerance in seconds for time-based claim validation.
                    Default: 0
        """
        ...

    def encode(
        self,
        key: Union[bytes, str],
        payload: Union[Dict[str, Any], bytes, str],
        purpose: str = "local",
        version: str = "v4",
        footer: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        implicit_assertion: Optional[bytes] = None,
        serializer: Optional[Serializer] = None,
    ) -> str:
        """Encode a PASETO token with configured defaults.

        Creates a PASETO token from a payload dict, automatically applying
        configured defaults (exp, iat) if not already present in the payload.

        Args:
            key: The cryptographic key (bytes or str)
            payload: The payload data as a Python dict, bytes, or str
            purpose: Token purpose - "local" or "public". Default: "local"
            version: PASETO version - "v2", "v3", or "v4". Default: "v4"
            footer: Optional footer data (bytes, str, or dict). Default: None
            implicit_assertion: Optional implicit assertion (bytes). Default: None
            serializer: Optional object with dumps() method for custom serialization.
                        If provided, will be used to serialize dict payloads and footers.
                        Default: None (uses JSON)

        Returns:
            str: The encoded PASETO token string

        Raises:
            PasetoKeyError: If the key format or length is invalid
            PasetoValidationError: If the payload cannot be serialized
            PasetoCryptoError: If encryption/signing fails
        """
        ...

    def decode(
        self,
        token: str,
        key: Union[bytes, str],
        purpose: str = "local",
        version: str = "v4",
        footer: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        implicit_assertion: Optional[bytes] = None,
        deserializer: Optional[Deserializer] = None,
    ) -> Token:
        """Decode a PASETO token with configured leeway.

        Verifies and decrypts a PASETO token, applying the configured leeway
        for time-based claim validation.

        Args:
            token: The PASETO token string to decode
            key: The cryptographic key (bytes or str)
            purpose: Token purpose - "local" or "public". Default: "local"
            version: PASETO version - "v2", "v3", or "v4". Default: "v4"
            footer: Optional expected footer data (bytes, str, or dict). Default: None
            implicit_assertion: Optional implicit assertion (bytes). Default: None
            deserializer: Optional object with loads() method for custom deserialization.
                          If provided, will be used to deserialize payload and footer.
                          Default: None (uses JSON)

        Returns:
            Token: A Token object with payload, footer, version, and purpose

        Raises:
            PasetoKeyError: If the key format or length is invalid
            PasetoValidationError: If the token format is invalid
            PasetoCryptoError: If decryption/verification fails
            PasetoExpiredError: If the token has expired
            PasetoNotYetValidError: If the token is not yet valid
        """
        ...

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
    payload: Union[Dict[str, Any], bytes, str],
    purpose: str = "local",
    version: str = "v4",
    footer: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    implicit_assertion: Optional[bytes] = None,
    serializer: Optional[Serializer] = None,
) -> str:
    """Encode a PASETO token.

    Args:
        key: Symmetric key (32 bytes) for local tokens or secret key (64 bytes) for public tokens
        payload: Dictionary, bytes, or string containing the token claims
        purpose: Either "local" or "public"
        version: PASETO version - "v2", "v3", or "v4". Default: "v4"
        footer: Optional footer (dict, bytes, or str)
        implicit_assertion: Optional implicit assertion bytes
        serializer: Optional object with dumps() method for custom serialization.
                    If provided, will be used to serialize dict payloads and footers.
                    Default: None (uses JSON)

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
    purpose: str = "local",
    version: str = "v4",
    footer: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    implicit_assertion: Optional[bytes] = None,
    deserializer: Optional[Deserializer] = None,
    leeway: int = 0,
) -> Token:
    """Decode and verify a PASETO token.

    Args:
        token: The PASETO token string to decode
        key: Symmetric key (32 bytes) for local tokens or public key (32 bytes) for public tokens
        purpose: Either "local" or "public"
        version: PASETO version - "v2", "v3", or "v4". Default: "v4"
        footer: Optional expected footer (dict, bytes, or str)
        implicit_assertion: Optional implicit assertion bytes
        deserializer: Optional object with loads() method for custom deserialization.
                      If provided, will be used to deserialize payload and footer.
                      Default: None (uses JSON)
        leeway: Time tolerance in seconds for time-based claims. Default: 0

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
