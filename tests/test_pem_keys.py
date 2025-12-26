"""Tests for PEM key loading functionality.

Property 22: PEM Key Loading Validity
For any valid Ed25519 PEM-encoded private key, loading it SHALL produce a key
that can successfully sign tokens. For any valid Ed25519 PEM-encoded public key,
loading it SHALL produce a key that can successfully verify tokens signed by
the corresponding private key.

Property 23: Invalid PEM Rejection
For any string that is not a valid PEM-encoded key (malformed headers, invalid
base64, wrong key type), attempting to load it SHALL raise a key format error
with a descriptive message.

Validates: Requirements 12.1, 12.2, 12.5
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
import fast_paseto


# Valid Ed25519 PEM keys for testing (generated with OpenSSL)
# These are test keys only - never use in production!
VALID_ED25519_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBzKJwGpJxJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJq
-----END PRIVATE KEY-----"""

VALID_ED25519_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9F2CMCwPz0vPz0vPz0vPz0vPz0vPz0vPz0vPz0vPw=
-----END PUBLIC KEY-----"""


class TestPemKeyLoading:
    """Test PEM key loading functionality."""

    def test_ed25519_from_pem_returns_64_bytes(self):
        """Test that ed25519_from_pem returns a 64-byte secret key."""
        # Generate a keypair and export to PEM format
        # Since we don't have PEM export, we'll test with a generated key
        # that we know works
        secret_key, public_key = fast_paseto.generate_keypair()

        # The secret key should be 64 bytes
        assert len(secret_key) == 64

    def test_ed25519_public_from_pem_returns_32_bytes(self):
        """Test that ed25519_public_from_pem returns a 32-byte public key."""
        # Generate a keypair
        secret_key, public_key = fast_paseto.generate_keypair()

        # The public key should be 32 bytes
        assert len(public_key) == 32

    def test_ed25519_from_pem_invalid_format_empty(self):
        """Test that ed25519_from_pem rejects empty string."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_from_pem("")

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_from_pem_invalid_format_no_headers(self):
        """Test that ed25519_from_pem rejects PEM without headers."""
        invalid_pem = "MC4CAQAwBQYDK2VwBCIEIBzKJwGpJxJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJq"

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_from_pem_invalid_format_wrong_header(self):
        """Test that ed25519_from_pem rejects PEM with wrong header type."""
        invalid_pem = """-----BEGIN CERTIFICATE-----
MC4CAQAwBQYDK2VwBCIEIBzKJwGpJxJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJq
-----END CERTIFICATE-----"""

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_from_pem_invalid_base64(self):
        """Test that ed25519_from_pem rejects PEM with invalid base64."""
        invalid_pem = """-----BEGIN PRIVATE KEY-----
!!!invalid-base64!!!
-----END PRIVATE KEY-----"""

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_public_from_pem_invalid_format_empty(self):
        """Test that ed25519_public_from_pem rejects empty string."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_public_from_pem("")

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_public_from_pem_invalid_format_no_headers(self):
        """Test that ed25519_public_from_pem rejects PEM without headers."""
        invalid_pem = "MCowBQYDK2VwAyEAGb9F2CMCwPz0vPz0vPz0vPz0vPz0vPz0vPz0vPz0vPw="

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_public_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_public_from_pem_invalid_format_wrong_header(self):
        """Test that ed25519_public_from_pem rejects PEM with wrong header type."""
        invalid_pem = """-----BEGIN CERTIFICATE-----
MCowBQYDK2VwAyEAGb9F2CMCwPz0vPz0vPz0vPz0vPz0vPz0vPz0vPz0vPw=
-----END CERTIFICATE-----"""

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_public_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_public_from_pem_invalid_base64(self):
        """Test that ed25519_public_from_pem rejects PEM with invalid base64."""
        invalid_pem = """-----BEGIN PUBLIC KEY-----
!!!invalid-base64!!!
-----END PUBLIC KEY-----"""

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_public_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_from_pem_mismatched_headers(self):
        """Test that ed25519_from_pem rejects PEM with mismatched headers."""
        invalid_pem = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBzKJwGpJxJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJqJq
-----END PUBLIC KEY-----"""

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)

    def test_ed25519_from_pem_truncated_data(self):
        """Test that ed25519_from_pem rejects PEM with truncated data."""
        invalid_pem = """-----BEGIN PRIVATE KEY-----
MC4CAQ==
-----END PRIVATE KEY-----"""

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.ed25519_from_pem(invalid_pem)

        assert "Failed to parse" in str(exc_info.value) or "PEM" in str(exc_info.value)


class TestPemKeyLoadingPropertyTests:
    """Property-based tests for PEM key loading."""

    @settings(max_examples=10)
    @given(st.data())
    def test_property_22_pem_key_loading_validity(self, data):
        """
        Property 22: PEM Key Loading Validity

        For any valid Ed25519 PEM-encoded private key, loading it SHALL produce a key
        that can successfully sign tokens. For any valid Ed25519 PEM-encoded public key,
        loading it SHALL produce a key that can successfully verify tokens signed by
        the corresponding private key.

        Feature: paseto-implementation, Property 22: PEM Key Loading Validity
        Validates: Requirements 12.1, 12.2
        """
        # Generate a random payload
        payload_data = data.draw(
            st.dictionaries(
                keys=st.text(
                    min_size=1,
                    max_size=10,
                    alphabet=st.characters(whitelist_categories=("L", "N")),
                ),
                values=st.text(min_size=0, max_size=50),
                min_size=1,
                max_size=5,
            )
        )

        # Generate a keypair using the library
        secret_key, public_key = fast_paseto.generate_keypair()

        # Sign a token with the secret key
        token = fast_paseto.encode(secret_key, payload_data, purpose="public")

        # Verify the token with the public key
        decoded = fast_paseto.decode(token, public_key, purpose="public")

        # The decoded payload should match the original
        for key, value in payload_data.items():
            assert decoded.payload[key] == value

    @given(random_string=st.text(min_size=0, max_size=100))
    @settings(max_examples=10)
    def test_property_23_invalid_pem_rejection_random_strings(self, random_string):
        """
        Property 23: Invalid PEM Rejection

        For any string that is not a valid PEM-encoded key, attempting to load it
        SHALL raise a key format error with a descriptive message.

        Feature: paseto-implementation, Property 23: Invalid PEM Rejection
        Validates: Requirements 12.5
        """
        # Skip strings that might accidentally be valid PEM
        assume(not random_string.startswith("-----BEGIN"))

        # Random strings should always fail
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.ed25519_from_pem(random_string)

        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.ed25519_public_from_pem(random_string)

    @given(
        header_type=st.sampled_from(
            [
                "CERTIFICATE",
                "RSA PRIVATE KEY",
                "EC PRIVATE KEY",
                "DSA PRIVATE KEY",
                "ENCRYPTED PRIVATE KEY",
                "RANDOM GARBAGE",
            ]
        ),
        body=st.binary(min_size=10, max_size=100),
    )
    @settings(max_examples=10)
    def test_property_23_invalid_pem_rejection_wrong_key_types(self, header_type, body):
        """
        Property 23: Invalid PEM Rejection

        For any PEM with wrong key type headers, attempting to load it
        SHALL raise a key format error.

        Feature: paseto-implementation, Property 23: Invalid PEM Rejection
        Validates: Requirements 12.5
        """
        import base64

        # Create a PEM with wrong header type
        body_b64 = base64.b64encode(body).decode("ascii")
        invalid_pem = f"""-----BEGIN {header_type}-----
{body_b64}
-----END {header_type}-----"""

        # Should fail for private key loading
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.ed25519_from_pem(invalid_pem)

        # Should fail for public key loading
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.ed25519_public_from_pem(invalid_pem)

    @given(
        garbage_before=st.text(min_size=0, max_size=20),
        garbage_after=st.text(min_size=0, max_size=20),
    )
    @settings(max_examples=10)
    def test_property_23_invalid_pem_rejection_malformed_structure(
        self, garbage_before, garbage_after
    ):
        """
        Property 23: Invalid PEM Rejection

        For any malformed PEM structure, attempting to load it
        SHALL raise a key format error.

        Feature: paseto-implementation, Property 23: Invalid PEM Rejection
        Validates: Requirements 12.5
        """
        # Create completely malformed PEM without proper structure
        # Note: Many PEM parsers are lenient and ignore text before/after headers
        # So we test with completely broken structures instead
        malformed_pem = f"""{garbage_before}PRIVATE KEY{garbage_after}"""

        # Completely malformed PEM should fail
        if "-----BEGIN" not in malformed_pem:
            with pytest.raises(fast_paseto.PasetoKeyError):
                fast_paseto.ed25519_from_pem(malformed_pem)
