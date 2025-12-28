#!/usr/bin/env python3
"""
PASETO v2 Test Vectors

This module tests the fast_paseto library for v2 tokens. v2 is a legacy version
that uses:
- v2.local: XChaCha20-Poly1305 encryption with a 32-byte symmetric key
- v2.public: Ed25519 signatures with a 64-byte secret key / 32-byte public key

Note: v2 tokens do NOT support implicit assertions (unlike v3/v4).

Since official test vectors require exact byte-for-byte matching of JSON
serialization, we focus on round-trip tests and security validation.
"""

import pytest

import fast_paseto


class TestV2LocalRoundTrip:
    """Test v2.local token round-trip encoding and decoding."""

    def test_basic_roundtrip(self):
        """Test basic v2.local encode/decode round-trip."""
        key = fast_paseto.generate_symmetric_key()
        payload = {
            "data": "this is a signed message",
            "exp": "2022-01-01T00:00:00+00:00",
        }

        token = fast_paseto.encode(key, payload, purpose="local", version="v2")
        assert token.startswith("v2.local.")

        decoded = fast_paseto.decode(token, key, purpose="local", version="v2")
        assert decoded.payload == payload
        assert decoded.version == "v2"
        assert decoded.purpose == "local"

    def test_roundtrip_with_footer(self):
        """Test v2.local round-trip with footer."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"sub": "user123", "data": "test message"}
        footer = {"kid": "zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v2", footer=footer
        )
        assert token.startswith("v2.local.")
        # Token should have 4 parts with footer
        assert len(token.split(".")) == 4

        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v2", footer=footer
        )
        assert decoded.payload == payload
        assert decoded.footer == footer

    def test_roundtrip_empty_payload(self):
        """Test v2.local round-trip with empty payload."""
        key = fast_paseto.generate_symmetric_key()
        payload = {}

        token = fast_paseto.encode(key, payload, purpose="local", version="v2")
        decoded = fast_paseto.decode(token, key, purpose="local", version="v2")
        assert decoded.payload == payload

    def test_roundtrip_complex_payload(self):
        """Test v2.local round-trip with complex payload."""
        key = fast_paseto.generate_symmetric_key()
        payload = {
            "sub": "user123",
            "name": "Test User",
            "roles": ["admin", "user"],
            "metadata": {"level": 5, "active": True},
        }

        token = fast_paseto.encode(key, payload, purpose="local", version="v2")
        decoded = fast_paseto.decode(token, key, purpose="local", version="v2")
        assert decoded.payload == payload


class TestV2LocalSecurity:
    """Security tests for v2.local tokens."""

    def test_wrong_key_fails_decryption(self):
        """Verify that decryption fails with wrong key."""
        correct_key = fast_paseto.generate_symmetric_key()
        wrong_key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret message"}

        token = fast_paseto.encode(correct_key, payload, purpose="local", version="v2")

        # Correct key works
        decoded = fast_paseto.decode(token, correct_key, purpose="local", version="v2")
        assert decoded.payload == payload

        # Wrong key fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(token, wrong_key, purpose="local", version="v2")

    def test_wrong_footer_fails(self):
        """Verify that decryption fails with wrong footer."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret message"}
        correct_footer = {"kid": "correct-key"}
        wrong_footer = {"kid": "wrong-key"}

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v2", footer=correct_footer
        )

        # Correct footer works
        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v2", footer=correct_footer
        )
        assert decoded.payload == payload

        # Wrong footer fails
        with pytest.raises(fast_paseto.PasetoValidationError):
            fast_paseto.decode(
                token, key, purpose="local", version="v2", footer=wrong_footer
            )

    def test_tokens_are_unique(self):
        """Verify that each token is unique due to random nonce."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "test"}

        token1 = fast_paseto.encode(key, payload, purpose="local", version="v2")
        token2 = fast_paseto.encode(key, payload, purpose="local", version="v2")

        assert token1 != token2, "Tokens should differ due to random nonce"


class TestV2PublicRoundTrip:
    """Test v2.public token round-trip signing and verification."""

    def test_basic_roundtrip(self):
        """Test basic v2.public sign/verify round-trip."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {
            "data": "this is a signed message",
            "exp": "2022-01-01T00:00:00+00:00",
        }

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v2")
        assert token.startswith("v2.public.")

        decoded = fast_paseto.decode(token, public_key, purpose="public", version="v2")
        assert decoded.payload == payload
        assert decoded.version == "v2"
        assert decoded.purpose == "public"

    def test_roundtrip_with_footer(self):
        """Test v2.public round-trip with footer."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"sub": "user123", "data": "test message"}
        footer = {"kid": "zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}

        token = fast_paseto.encode(
            secret_key, payload, purpose="public", version="v2", footer=footer
        )
        assert token.startswith("v2.public.")
        # Token should have 4 parts with footer
        assert len(token.split(".")) == 4

        decoded = fast_paseto.decode(
            token, public_key, purpose="public", version="v2", footer=footer
        )
        assert decoded.payload == payload
        assert decoded.footer == footer

    def test_deterministic_signatures(self):
        """Test that Ed25519 signatures are deterministic."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"data": "test"}

        # Same payload with same key should produce same token
        token1 = fast_paseto.encode(secret_key, payload, purpose="public", version="v2")
        token2 = fast_paseto.encode(secret_key, payload, purpose="public", version="v2")

        assert token1 == token2, "Ed25519 signatures should be deterministic"


class TestV2PublicSecurity:
    """Security tests for v2.public tokens."""

    def test_wrong_public_key_fails_verification(self):
        """Verify that verification fails with wrong public key."""
        secret_key, correct_public_key = fast_paseto.generate_keypair()
        _, wrong_public_key = fast_paseto.generate_keypair()
        payload = {"data": "signed message"}

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v2")

        # Correct key works
        decoded = fast_paseto.decode(
            token, correct_public_key, purpose="public", version="v2"
        )
        assert decoded.payload == payload

        # Wrong key fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(token, wrong_public_key, purpose="public", version="v2")

    def test_wrong_footer_fails_verification(self):
        """Verify that verification fails with wrong footer."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"data": "signed message"}
        correct_footer = {"kid": "correct-key"}
        wrong_footer = {"kid": "wrong-key"}

        token = fast_paseto.encode(
            secret_key, payload, purpose="public", version="v2", footer=correct_footer
        )

        # Correct footer works
        decoded = fast_paseto.decode(
            token, public_key, purpose="public", version="v2", footer=correct_footer
        )
        assert decoded.payload == payload

        # Wrong footer fails
        with pytest.raises(fast_paseto.PasetoValidationError):
            fast_paseto.decode(
                token, public_key, purpose="public", version="v2", footer=wrong_footer
            )


class TestV2NoImplicitAssertion:
    """Test that v2 tokens work without implicit assertions.

    Unlike v3 and v4, PASETO v2 does not support implicit assertions.
    """

    def test_v2_local_works_without_implicit_assertion(self):
        """Test that v2.local works without implicit assertion."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "test"}

        # Encode without implicit assertion
        token = fast_paseto.encode(key, payload, purpose="local", version="v2")

        # Decode without implicit assertion
        decoded = fast_paseto.decode(token, key, purpose="local", version="v2")
        assert decoded.payload == payload

    def test_v2_public_works_without_implicit_assertion(self):
        """Test that v2.public works without implicit assertion."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"data": "test"}

        # Sign without implicit assertion
        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v2")

        # Verify without implicit assertion
        decoded = fast_paseto.decode(token, public_key, purpose="public", version="v2")
        assert decoded.payload == payload


class TestV2KeyValidation:
    """Test key length validation for v2 tokens."""

    def test_v2_local_key_must_be_32_bytes(self):
        """Test that v2.local requires a 32-byte key."""
        payload = {"data": "test"}

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"short", payload, purpose="local", version="v2")

        # Too long
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"x" * 64, payload, purpose="local", version="v2")

        # Correct length works
        key = b"x" * 32
        token = fast_paseto.encode(key, payload, purpose="local", version="v2")
        assert token.startswith("v2.local.")

    def test_v2_public_secret_key_must_be_64_bytes(self):
        """Test that v2.public signing requires a 64-byte secret key."""
        payload = {"data": "test"}

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"short", payload, purpose="public", version="v2")

        # Wrong length (32 bytes)
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"x" * 32, payload, purpose="public", version="v2")

    def test_v2_public_public_key_must_be_32_bytes(self):
        """Test that v2.public verification requires a 32-byte public key."""
        secret_key, _ = fast_paseto.generate_keypair()
        payload = {"data": "test"}

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v2")

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.decode(token, b"short", purpose="public", version="v2")

        # Wrong length (64 bytes)
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.decode(token, b"x" * 64, purpose="public", version="v2")


class TestV2TokenFormat:
    """Test v2 token format validation."""

    def test_v2_local_token_format(self):
        """Test that v2.local tokens have correct format."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "test"}

        token = fast_paseto.encode(key, payload, purpose="local", version="v2")

        parts = token.split(".")
        assert len(parts) == 3
        assert parts[0] == "v2"
        assert parts[1] == "local"
        # Third part should be valid base64url
        import base64

        base64.urlsafe_b64decode(parts[2] + "==")  # Add padding for decode

    def test_v2_public_token_format(self):
        """Test that v2.public tokens have correct format."""
        secret_key, _ = fast_paseto.generate_keypair()
        payload = {"data": "test"}

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v2")

        parts = token.split(".")
        assert len(parts) == 3
        assert parts[0] == "v2"
        assert parts[1] == "public"
        # Third part should be valid base64url
        import base64

        base64.urlsafe_b64decode(parts[2] + "==")  # Add padding for decode

    def test_v2_token_with_footer_format(self):
        """Test that v2 tokens with footer have correct format."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "test"}
        footer = {"kid": "test-key"}

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v2", footer=footer
        )

        parts = token.split(".")
        assert len(parts) == 4
        assert parts[0] == "v2"
        assert parts[1] == "local"
        # Fourth part should be valid base64url footer
        import base64
        import json

        footer_bytes = base64.urlsafe_b64decode(parts[3] + "==")
        decoded_footer = json.loads(footer_bytes)
        assert decoded_footer == footer


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
