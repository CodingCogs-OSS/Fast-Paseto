"""Tests for PASERK serialization functionality."""

import pytest
import fast_paseto


class TestPaserkSerialization:
    """Test PASERK key serialization and deserialization."""

    def test_to_paserk_local(self):
        """Test serializing a symmetric key to PASERK local format."""
        key = fast_paseto.generate_symmetric_key()
        paserk = fast_paseto.to_paserk_local(key)

        assert paserk.startswith("k4.local.")
        assert len(paserk.split(".")) == 3
        assert "=" not in paserk  # No padding

    def test_to_paserk_secret(self):
        """Test serializing an Ed25519 secret key to PASERK secret format."""
        secret_key, _ = fast_paseto.generate_keypair()
        paserk = fast_paseto.to_paserk_secret(secret_key)

        assert paserk.startswith("k4.secret.")
        assert len(paserk.split(".")) == 3
        assert "=" not in paserk  # No padding

    def test_to_paserk_public(self):
        """Test serializing an Ed25519 public key to PASERK public format."""
        _, public_key = fast_paseto.generate_keypair()
        paserk = fast_paseto.to_paserk_public(public_key)

        assert paserk.startswith("k4.public.")
        assert len(paserk.split(".")) == 3
        assert "=" not in paserk  # No padding

    def test_from_paserk_local_roundtrip(self):
        """Test round-trip serialization of a local key."""
        key = fast_paseto.generate_symmetric_key()
        paserk = fast_paseto.to_paserk_local(key)
        key_type, decoded_key = fast_paseto.from_paserk(paserk)

        assert key_type == "local"
        assert decoded_key == key

    def test_from_paserk_secret_roundtrip(self):
        """Test round-trip serialization of a secret key."""
        secret_key, _ = fast_paseto.generate_keypair()
        paserk = fast_paseto.to_paserk_secret(secret_key)
        key_type, decoded_key = fast_paseto.from_paserk(paserk)

        assert key_type == "secret"
        assert decoded_key == secret_key

    def test_from_paserk_public_roundtrip(self):
        """Test round-trip serialization of a public key."""
        _, public_key = fast_paseto.generate_keypair()
        paserk = fast_paseto.to_paserk_public(public_key)
        key_type, decoded_key = fast_paseto.from_paserk(paserk)

        assert key_type == "public"
        assert decoded_key == public_key

    def test_to_paserk_local_invalid_length(self):
        """Test that to_paserk_local rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.to_paserk_local(b"short")

        assert "expected 32 bytes" in str(exc_info.value)

    def test_to_paserk_secret_invalid_length(self):
        """Test that to_paserk_secret rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.to_paserk_secret(b"short")

        assert "expected 64 bytes" in str(exc_info.value)

    def test_to_paserk_public_invalid_length(self):
        """Test that to_paserk_public rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.to_paserk_public(b"short")

        assert "expected 32 bytes" in str(exc_info.value)

    def test_from_paserk_invalid_format_too_few_parts(self):
        """Test that from_paserk rejects invalid format with too few parts."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.from_paserk("k4.local")

        assert "exactly 3 parts" in str(exc_info.value)

    def test_from_paserk_invalid_format_too_many_parts(self):
        """Test that from_paserk rejects invalid format with too many parts."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.from_paserk("k4.local.data.extra")

        assert "exactly 3 parts" in str(exc_info.value)

    def test_from_paserk_invalid_version(self):
        """Test that from_paserk rejects unsupported versions."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.from_paserk(
                "k3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )

        assert "Unsupported PASERK version" in str(exc_info.value)

    def test_from_paserk_invalid_type(self):
        """Test that from_paserk rejects unsupported key types."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.from_paserk(
                "k4.invalid.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )

        assert "Unsupported PASERK type" in str(exc_info.value)

    def test_from_paserk_invalid_base64(self):
        """Test that from_paserk rejects invalid base64url encoding."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.from_paserk("k4.local.invalid@base64!")

        assert "Invalid base64url encoding" in str(exc_info.value)

    def test_paserk_determinism(self):
        """Test that the same key always produces the same PASERK."""
        key = fast_paseto.generate_symmetric_key()
        paserk1 = fast_paseto.to_paserk_local(key)
        paserk2 = fast_paseto.to_paserk_local(key)

        assert paserk1 == paserk2

    def test_paserk_different_keys_different_paserks(self):
        """Test that different keys produce different PASERKs."""
        key1 = fast_paseto.generate_symmetric_key()
        key2 = fast_paseto.generate_symmetric_key()
        paserk1 = fast_paseto.to_paserk_local(key1)
        paserk2 = fast_paseto.to_paserk_local(key2)

        assert paserk1 != paserk2

    def test_paserk_with_token_operations(self):
        """Test that PASERK-serialized keys work with token operations."""
        # Generate and serialize a local key
        key = fast_paseto.generate_symmetric_key()
        paserk = fast_paseto.to_paserk_local(key)

        # Deserialize the key
        key_type, decoded_key = fast_paseto.from_paserk(paserk)
        assert key_type == "local"

        # Use the deserialized key to encode and decode a token
        payload = {"sub": "user123", "data": "test"}
        token = fast_paseto.encode(decoded_key, payload, purpose="local")
        decoded_token = fast_paseto.decode(token, decoded_key, purpose="local")

        assert decoded_token.payload["sub"] == "user123"
        assert decoded_token.payload["data"] == "test"

    def test_paserk_public_key_with_token_operations(self):
        """Test that PASERK-serialized public keys work with token operations."""
        # Generate and serialize a keypair
        secret_key, public_key = fast_paseto.generate_keypair()
        paserk_secret = fast_paseto.to_paserk_secret(secret_key)
        paserk_public = fast_paseto.to_paserk_public(public_key)

        # Deserialize the keys
        secret_type, decoded_secret = fast_paseto.from_paserk(paserk_secret)
        public_type, decoded_public = fast_paseto.from_paserk(paserk_public)

        assert secret_type == "secret"
        assert public_type == "public"

        # Use the deserialized keys to sign and verify a token
        payload = {"sub": "user123", "data": "test"}
        token = fast_paseto.encode(decoded_secret, payload, purpose="public")
        decoded_token = fast_paseto.decode(token, decoded_public, purpose="public")

        assert decoded_token.payload["sub"] == "user123"
        assert decoded_token.payload["data"] == "test"
