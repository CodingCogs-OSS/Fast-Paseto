#!/usr/bin/env python3
"""
PASETO v3 Test Vectors

v3 is the NIST-compliant version of PASETO that uses:
- v3.local: AES-256-CTR + HMAC-SHA-384 for authenticated encryption
- v3.public: P-384 ECDSA for digital signatures

NOTE: v3 support is NOT currently exposed in the Python API.
The Rust implementation exists but is not wired up in lib.rs.
These tests are marked as skipped until v3 is fully implemented.

Reference: https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md
"""

import pytest

import fast_paseto


# Mark all tests in this module as skipped
pytestmark = pytest.mark.skip(reason="v3 is not currently exposed in the Python API")


class TestV3LocalRoundTrip:
    """Test v3.local token round-trip encoding and decoding.

    v3.local uses AES-256-CTR + HMAC-SHA384 for authenticated encryption.
    """

    def test_basic_roundtrip(self):
        """Test basic v3.local encode/decode round-trip."""
        key = fast_paseto.generate_symmetric_key()
        payload = {
            "data": "this is a signed message",
            "exp": "2022-01-01T00:00:00+00:00",
        }

        token = fast_paseto.encode(key, payload, purpose="local", version="v3")
        assert token.startswith("v3.local.")

        decoded = fast_paseto.decode(token, key, purpose="local", version="v3")
        assert decoded.payload == payload
        assert decoded.version == "v3"
        assert decoded.purpose == "local"

    def test_roundtrip_with_footer(self):
        """Test v3.local round-trip with footer."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"sub": "user123"}
        footer = {"kid": "UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v3", footer=footer
        )
        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v3", footer=footer
        )

        assert decoded.payload == payload
        assert decoded.footer == footer

    def test_roundtrip_with_implicit_assertion(self):
        """Test v3.local round-trip with implicit assertion."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"sub": "user123"}
        assertion = b'{"test-vector":"3-E-4"}'

        token = fast_paseto.encode(
            key, payload, purpose="local", version="v3", implicit_assertion=assertion
        )
        decoded = fast_paseto.decode(
            token, key, purpose="local", version="v3", implicit_assertion=assertion
        )

        assert decoded.payload == payload


class TestV3LocalSecurity:
    """Security tests for v3.local tokens."""

    def test_wrong_key_fails(self):
        """Test that decryption fails with wrong key."""
        correct_key = fast_paseto.generate_symmetric_key()
        wrong_key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret"}

        token = fast_paseto.encode(correct_key, payload, purpose="local", version="v3")

        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(token, wrong_key, purpose="local", version="v3")

    def test_wrong_implicit_assertion_fails(self):
        """Test that decryption fails with wrong implicit assertion."""
        key = fast_paseto.generate_symmetric_key()
        payload = {"data": "secret"}
        correct_assertion = b"correct"
        wrong_assertion = b"wrong"

        token = fast_paseto.encode(
            key,
            payload,
            purpose="local",
            version="v3",
            implicit_assertion=correct_assertion,
        )

        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.decode(
                token,
                key,
                purpose="local",
                version="v3",
                implicit_assertion=wrong_assertion,
            )


class TestV3PublicRoundTrip:
    """Test v3.public token round-trip signing and verification.

    v3.public uses P-384 ECDSA for digital signatures.
    Note: v3 uses different key types than v2/v4 (P-384 instead of Ed25519).
    """

    def test_basic_roundtrip(self):
        """Test basic v3.public sign/verify round-trip."""
        # Note: v3 would need a different key generation function for P-384
        # This test is a placeholder for when v3 is implemented
        pass

    def test_roundtrip_with_footer(self):
        """Test v3.public round-trip with footer."""
        pass

    def test_roundtrip_with_implicit_assertion(self):
        """Test v3.public round-trip with implicit assertion."""
        pass


class TestV3KeyLengths:
    """Test that v3 key length validation works correctly."""

    def test_v3_local_key_must_be_32_bytes(self):
        """Test that v3.local requires a 32-byte key."""
        payload = {"data": "test"}

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"short", payload, purpose="local", version="v3")

        # Too long
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"x" * 64, payload, purpose="local", version="v3")

    def test_v3_public_secret_key_must_be_48_bytes(self):
        """Test that v3.public signing requires a 48-byte secret key (P-384)."""
        payload = {"data": "test"}

        # Too short
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"short", payload, purpose="public", version="v3")

        # Wrong length (64 bytes like Ed25519)
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.encode(b"x" * 64, payload, purpose="public", version="v3")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
