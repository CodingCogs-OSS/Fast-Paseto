#!/usr/bin/env python3
"""
PASETO v4 Test Vectors

This module tests the fast_paseto library for v4 tokens. Since official test vectors
require exact byte-for-byte matching of JSON serialization (which may differ between
implementations), we focus on:

1. Round-trip tests: encode then decode our own tokens
2. Security tests: verify that wrong keys/assertions fail
3. Format validation: ensure tokens have correct structure

For v4.local, encryption uses random nonces, so we can only test round-trips.
For v4.public, Ed25519 signatures are deterministic, but the signature depends
on the exact byte representation of the payload.
"""

import pytest

import fast_paseto


class TestV4LocalRoundTrip:
    """Test v4.local token round-trip encoding and decoding."""

    def test_basic_roundtrip(self):
        """Test basic v4.local encode/decode round-trip."""
        key = fast_paseto.generate_symmetric_key()
        payload = {
            "data": "this is a signed message",
            "exp": "2022-01-01T00:00:00+00:00",
        }

        token = fast_paseto.encode(key, payload, purpose="local", version="v4")
        assert token.startswith("v4.local.")

        decoded = fast_paseto.decode(token, key, purpose="local", version="v4")
        assert decoded.payload == payload
        assert decoded.version == "v4"
        assert decoded.purpose == "local"

    def test_roundtrip_with_footer(self):
        """Test v4.local round-trip with footer."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"sub": "user123", "data": "test message"}
        footer = {"kid": "zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v4", footer=footer
        )
        assert token.startswith("v4.local.")
        # Token should have 4 parts with footer
        assert len(token.split(".")) == 4

        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v4", footer=footer
        )
        assert decoded.payload == payload
        assert decoded.footer == footer

    def test_roundtrip_with_implicit_assertion(self):
        """Test v4.local round-trip with implicit assertion."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"sub": "user123"}
        assertion = b'{"test-vector":"4-E-4"}'

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v4", implicit_assertion=assertion
        )

        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v4", implicit_assertion=assertion
        )
        assert decoded.payload == payload

    def test_roundtrip_with_footer_and_assertion(self):
        """Test v4.local round-trip with both footer and implicit assertion."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"sub": "user123", "action": "test"}
        footer = {"kid": "my-key-id"}
        assertion = b"additional-context"

        token = fast_paseto.encode(
            key,
            payload,
            purpose="local",
            version="v4",
            footer=footer,
            implicit_assertion=assertion,
        )

        decoded = fast_paseto.decode(
            token,
            key,
            purpose="local",
            version="v4",
            footer=footer,
            implicit_assertion=assertion,
        )
        assert decoded.payload == payload
        assert decoded.footer == footer


class TestV4LocalSecurity:
    """Security tests for v4.local tokens."""

    def test_wrong_key_fails_decryption(self):
        """Verify that decryption fails with wrong key."""
        correct_key = fast_paseto.generate_symmetric_key()
        wrong_key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret message"}

        token = fast_paseto.encode(correct_key, payload, purpose="local", version="v4")

        # Correct key works
        decoded = fast_paseto.decode(token, correct_key, purpose="local", version="v4")
        assert decoded.payload == payload

        # Wrong key fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(token, wrong_key, purpose="local", version="v4")

    def test_wrong_implicit_assertion_fails(self):
        """Verify that decryption fails with wrong implicit assertion."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret message"}
        correct_assertion = b'{"test-vector":"correct"}'
        wrong_assertion = b'{"test-vector":"wrong"}'

        token = fast_paseto.encode(
            key,
            payload,
            purpose="local",
            version="v4",
            implicit_assertion=correct_assertion,
        )

        # Correct assertion works
        decoded = fast_paseto.decode(
            token,
            key,
            purpose="local",
            version="v4",
            implicit_assertion=correct_assertion,
        )
        assert decoded.payload == payload

        # Wrong assertion fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(
                token,
                key,
                purpose="local",
                version="v4",
                implicit_assertion=wrong_assertion,
            )

    def test_missing_implicit_assertion_fails(self):
        """Verify that decryption fails when implicit assertion is missing."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret message"}
        assertion = b"required-assertion"

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v4", implicit_assertion=assertion
        )

        # With assertion works
        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v4", implicit_assertion=assertion
        )
        assert decoded.payload == payload

        # Without assertion fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(token, key, purpose="local", version="v4")

    def test_wrong_footer_fails(self):
        """Verify that decryption fails with wrong footer."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret message"}
        correct_footer = {"kid": "correct-key"}
        wrong_footer = {"kid": "wrong-key"}

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v4", footer=correct_footer
        )

        # Correct footer works
        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v4", footer=correct_footer
        )
        assert decoded.payload == payload

        # Wrong footer fails
        with pytest.raises(fast_paseto.PasetoValidationError):
            fast_paseto.decode(
                token, key, purpose="local", version="v4", footer=wrong_footer
            )


class TestV4PublicRoundTrip:
    """Test v4.public token round-trip signing and verification."""

    def test_basic_roundtrip(self):
        """Test basic v4.public sign/verify round-trip."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {
            "data": "this is a signed message",
            "exp": "2022-01-01T00:00:00+00:00",
        }

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v4")
        assert token.startswith("v4.public.")

        decoded = fast_paseto.decode(token, public_key, purpose="public", version="v4")
        assert decoded.payload == payload
        assert decoded.version == "v4"
        assert decoded.purpose == "public"

    def test_roundtrip_with_footer(self):
        """Test v4.public round-trip with footer."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"sub": "user123", "data": "test message"}
        footer = {"kid": "zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}

        token = fast_paseto.encode(
            secret_key, payload, purpose="public", version="v4", footer=footer
        )
        assert token.startswith("v4.public.")
        # Token should have 4 parts with footer
        assert len(token.split(".")) == 4

        decoded = fast_paseto.decode(
            token, public_key, purpose="public", version="v4", footer=footer
        )
        assert decoded.payload == payload
        assert decoded.footer == footer

    def test_roundtrip_with_implicit_assertion(self):
        """Test v4.public round-trip with implicit assertion."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"sub": "user123"}
        assertion = b'{"test-vector":"4-S-3"}'

        token = fast_paseto.encode(
            secret_key,
            payload,
            purpose="public",
            version="v4",
            implicit_assertion=assertion,
        )

        decoded = fast_paseto.decode(
            token,
            public_key,
            purpose="public",
            version="v4",
            implicit_assertion=assertion,
        )
        assert decoded.payload == payload

    def test_roundtrip_with_footer_and_assertion(self):
        """Test v4.public round-trip with both footer and implicit assertion."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"sub": "user123", "action": "test"}
        footer = {"kid": "my-key-id"}
        assertion = b"additional-context"

        token = fast_paseto.encode(
            secret_key,
            payload,
            purpose="public",
            version="v4",
            footer=footer,
            implicit_assertion=assertion,
        )

        decoded = fast_paseto.decode(
            token,
            public_key,
            purpose="public",
            version="v4",
            footer=footer,
            implicit_assertion=assertion,
        )
        assert decoded.payload == payload
        assert decoded.footer == footer


class TestV4PublicSecurity:
    """Security tests for v4.public tokens."""

    def test_wrong_public_key_fails_verification(self):
        """Verify that verification fails with wrong public key."""
        secret_key, correct_public_key = fast_paseto.generate_keypair()
        _, wrong_public_key = fast_paseto.generate_keypair()
        payload = {"data": "signed message"}

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v4")

        # Correct key works
        decoded = fast_paseto.decode(
            token, correct_public_key, purpose="public", version="v4"
        )
        assert decoded.payload == payload

        # Wrong key fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(token, wrong_public_key, purpose="public", version="v4")

    def test_wrong_implicit_assertion_fails_verification(self):
        """Verify that verification fails with wrong implicit assertion."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"data": "signed message"}
        correct_assertion = b'{"test-vector":"correct"}'
        wrong_assertion = b'{"test-vector":"wrong"}'

        token = fast_paseto.encode(
            secret_key,
            payload,
            purpose="public",
            version="v4",
            implicit_assertion=correct_assertion,
        )

        # Correct assertion works
        decoded = fast_paseto.decode(
            token,
            public_key,
            purpose="public",
            version="v4",
            implicit_assertion=correct_assertion,
        )
        assert decoded.payload == payload

        # Wrong assertion fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(
                token,
                public_key,
                purpose="public",
                version="v4",
                implicit_assertion=wrong_assertion,
            )

    def test_missing_implicit_assertion_fails_verification(self):
        """Verify that verification fails when implicit assertion is missing."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"data": "signed message"}
        assertion = b"required-assertion"

        token = fast_paseto.encode(
            secret_key,
            payload,
            purpose="public",
            version="v4",
            implicit_assertion=assertion,
        )

        # With assertion works
        decoded = fast_paseto.decode(
            token,
            public_key,
            purpose="public",
            version="v4",
            implicit_assertion=assertion,
        )
        assert decoded.payload == payload

        # Without assertion fails
        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(token, public_key, purpose="public", version="v4")

    def test_wrong_footer_fails_verification(self):
        """Verify that verification fails with wrong footer."""
        secret_key, public_key = fast_paseto.generate_keypair()
        payload = {"data": "signed message"}
        correct_footer = {"kid": "correct-key"}
        wrong_footer = {"kid": "wrong-key"}

        token = fast_paseto.encode(
            secret_key, payload, purpose="public", version="v4", footer=correct_footer
        )

        # Correct footer works
        decoded = fast_paseto.decode(
            token, public_key, purpose="public", version="v4", footer=correct_footer
        )
        assert decoded.payload == payload

        # Wrong footer fails
        with pytest.raises(fast_paseto.PasetoValidationError):
            fast_paseto.decode(
                token, public_key, purpose="public", version="v4", footer=wrong_footer
            )


class TestV4KeyValidation:
    """Test key length validation for v4 tokens."""

    def test_v4_local_key_must_be_32_bytes(self):
        """Test that v4.local requires a 32-byte key."""
        payload = {"data": "test"}

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"short", payload, purpose="local", version="v4")

        # Too long
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"x" * 64, payload, purpose="local", version="v4")

        # Correct length works
        key = b"x" * 32
        token = fast_paseto.encode(key, payload, purpose="local", version="v4")
        assert token.startswith("v4.local.")

    def test_v4_public_secret_key_must_be_64_bytes(self):
        """Test that v4.public signing requires a 64-byte secret key."""
        payload = {"data": "test"}

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"short", payload, purpose="public", version="v4")

        # Wrong length (32 bytes)
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"x" * 32, payload, purpose="public", version="v4")

    def test_v4_public_public_key_must_be_32_bytes(self):
        """Test that v4.public verification requires a 32-byte public key."""
        secret_key, _ = fast_paseto.generate_keypair()
        payload = {"data": "test"}

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v4")

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.decode(token, b"short", purpose="public", version="v4")

        # Wrong length (64 bytes)
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.decode(token, b"x" * 64, purpose="public", version="v4")


class TestV4TokenFormat:
    """Test v4 token format validation."""

    def test_v4_local_token_format(self):
        """Test that v4.local tokens have correct format."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "test"}

        token = fast_paseto.encode(key, payload, purpose="local", version="v4")

        parts = token.split(".")
        assert len(parts) == 3
        assert parts[0] == "v4"
        assert parts[1] == "local"
        # Third part should be valid base64url
        import base64

        base64.urlsafe_b64decode(parts[2] + "==")  # Add padding for decode

    def test_v4_public_token_format(self):
        """Test that v4.public tokens have correct format."""
        secret_key, _ = fast_paseto.generate_keypair()
        payload = {"data": "test"}

        token = fast_paseto.encode(secret_key, payload, purpose="public", version="v4")

        parts = token.split(".")
        assert len(parts) == 3
        assert parts[0] == "v4"
        assert parts[1] == "public"
        # Third part should be valid base64url
        import base64

        base64.urlsafe_b64decode(parts[2] + "==")  # Add padding for decode

    def test_v4_token_with_footer_format(self):
        """Test that v4 tokens with footer have correct format."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "test"}
        footer = {"kid": "test-key"}

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v4", footer=footer
        )

        parts = token.split(".")
        assert len(parts) == 4
        assert parts[0] == "v4"
        assert parts[1] == "local"
        # Fourth part should be valid base64url footer
        import base64

        footer_bytes = base64.urlsafe_b64decode(parts[3] + "==")
        import json

        decoded_footer = json.loads(footer_bytes)
        assert decoded_footer == footer


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
