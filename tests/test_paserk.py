"""Tests for PASERK serialization functionality."""

import pytest
from hypothesis import given, strategies as st, settings
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


class TestKeyWrapping:
    """Test PASERK key wrapping functionality."""

    def test_local_wrap_format(self):
        """Test that local_wrap produces correct format."""
        key = fast_paseto.generate_symmetric_key()
        wrapping_key = fast_paseto.generate_symmetric_key()
        wrapped = fast_paseto.local_wrap(key, wrapping_key)

        assert wrapped.startswith("k4.local-wrap.pie.")
        assert len(wrapped.split(".")) == 4

    def test_local_wrap_unwrap_roundtrip(self):
        """Test that wrapping and unwrapping preserves the key."""
        key = fast_paseto.generate_symmetric_key()
        wrapping_key = fast_paseto.generate_symmetric_key()

        wrapped = fast_paseto.local_wrap(key, wrapping_key)
        unwrapped = fast_paseto.local_unwrap(wrapped, wrapping_key)

        assert unwrapped == key

    def test_local_unwrap_wrong_key(self):
        """Test that unwrapping with wrong key fails."""
        key = fast_paseto.generate_symmetric_key()
        wrapping_key1 = fast_paseto.generate_symmetric_key()
        wrapping_key2 = fast_paseto.generate_symmetric_key()

        wrapped = fast_paseto.local_wrap(key, wrapping_key1)

        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.local_unwrap(wrapped, wrapping_key2)

    def test_local_wrap_invalid_key_length(self):
        """Test that local_wrap rejects keys of wrong length."""
        wrapping_key = fast_paseto.generate_symmetric_key()

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.local_wrap(b"short", wrapping_key)

        assert "expected 32 bytes" in str(exc_info.value)

    def test_local_wrap_invalid_wrapping_key_length(self):
        """Test that local_wrap rejects wrapping keys of wrong length."""
        key = fast_paseto.generate_symmetric_key()

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.local_wrap(key, b"short")

        assert "expected 32 bytes" in str(exc_info.value)

    def test_local_unwrap_invalid_format(self):
        """Test that local_unwrap rejects invalid format."""
        wrapping_key = fast_paseto.generate_symmetric_key()

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.local_unwrap("invalid.format", wrapping_key)

        assert "exactly 4 parts" in str(exc_info.value)

    def test_secret_wrap_format(self):
        """Test that secret_wrap produces correct format."""
        secret_key, _ = fast_paseto.generate_keypair()
        wrapping_key = fast_paseto.generate_symmetric_key()
        wrapped = fast_paseto.secret_wrap(secret_key, wrapping_key)

        assert wrapped.startswith("k4.secret-wrap.pie.")
        assert len(wrapped.split(".")) == 4

    def test_secret_wrap_unwrap_roundtrip(self):
        """Test that wrapping and unwrapping preserves the secret key."""
        secret_key, _ = fast_paseto.generate_keypair()
        wrapping_key = fast_paseto.generate_symmetric_key()

        wrapped = fast_paseto.secret_wrap(secret_key, wrapping_key)
        unwrapped = fast_paseto.secret_unwrap(wrapped, wrapping_key)

        assert unwrapped == secret_key

    def test_secret_unwrap_wrong_key(self):
        """Test that unwrapping with wrong key fails."""
        secret_key, _ = fast_paseto.generate_keypair()
        wrapping_key1 = fast_paseto.generate_symmetric_key()
        wrapping_key2 = fast_paseto.generate_symmetric_key()

        wrapped = fast_paseto.secret_wrap(secret_key, wrapping_key1)

        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.secret_unwrap(wrapped, wrapping_key2)

    def test_secret_wrap_invalid_key_length(self):
        """Test that secret_wrap rejects keys of wrong length."""
        wrapping_key = fast_paseto.generate_symmetric_key()

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.secret_wrap(b"short", wrapping_key)

        assert "expected 64 bytes" in str(exc_info.value)

    def test_secret_wrap_invalid_wrapping_key_length(self):
        """Test that secret_wrap rejects wrapping keys of wrong length."""
        secret_key, _ = fast_paseto.generate_keypair()

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.secret_wrap(secret_key, b"short")

        assert "expected 32 bytes" in str(exc_info.value)

    def test_secret_unwrap_invalid_format(self):
        """Test that secret_unwrap rejects invalid format."""
        wrapping_key = fast_paseto.generate_symmetric_key()

        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.secret_unwrap("invalid.format", wrapping_key)

        assert "exactly 4 parts" in str(exc_info.value)

    def test_wrapped_keys_are_different_each_time(self):
        """Test that wrapping the same key twice produces different outputs (due to nonce)."""
        key = fast_paseto.generate_symmetric_key()
        wrapping_key = fast_paseto.generate_symmetric_key()

        wrapped1 = fast_paseto.local_wrap(key, wrapping_key)
        wrapped2 = fast_paseto.local_wrap(key, wrapping_key)

        # Different nonces mean different wrapped outputs
        assert wrapped1 != wrapped2

        # But both should unwrap to the same key
        assert fast_paseto.local_unwrap(wrapped1, wrapping_key) == key
        assert fast_paseto.local_unwrap(wrapped2, wrapping_key) == key


class TestPaserkIdGeneration:
    """Test PASERK ID generation functionality."""

    def test_generate_lid_format(self):
        """Test that generate_lid produces correct format."""
        key = fast_paseto.generate_symmetric_key()
        lid = fast_paseto.generate_lid(key)

        assert lid.startswith("k4.lid.")
        assert len(lid.split(".")) == 3
        assert "=" not in lid  # No padding


class TestPasswordBasedEncryption:
    """Test PASERK password-based key encryption functionality."""

    def test_local_pw_encrypt_format(self):
        """Test that local_pw_encrypt produces correct format."""
        key = fast_paseto.generate_symmetric_key()
        password = "test-password-123"
        encrypted = fast_paseto.local_pw_encrypt(key, password)

        assert encrypted.startswith("k4.local-pw.")
        assert len(encrypted.split(".")) == 3

    def test_local_pw_roundtrip(self):
        """Test that encrypting and decrypting preserves the key."""
        key = fast_paseto.generate_symmetric_key()
        password = "secure-password-456"

        encrypted = fast_paseto.local_pw_encrypt(key, password)
        decrypted = fast_paseto.local_pw_decrypt(encrypted, password)

        assert decrypted == key

    def test_local_pw_wrong_password(self):
        """Test that decrypting with wrong password fails."""
        key = fast_paseto.generate_symmetric_key()
        password = "correct-password"
        wrong_password = "wrong-password"

        encrypted = fast_paseto.local_pw_encrypt(key, password)

        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.local_pw_decrypt(encrypted, wrong_password)

    def test_local_pw_invalid_key_length(self):
        """Test that local_pw_encrypt rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.local_pw_encrypt(b"short", "password")

        assert "expected 32 bytes" in str(exc_info.value)

    def test_local_pw_invalid_format(self):
        """Test that local_pw_decrypt rejects invalid format."""
        # Wrong version
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.local_pw_decrypt("k3.local-pw.test", "password")

        # Wrong type
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.local_pw_decrypt("k4.secret-pw.test", "password")

        # Too few parts
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.local_pw_decrypt("k4.local-pw", "password")

    def test_local_pw_different_encryptions(self):
        """Test that encrypting the same key twice produces different outputs (due to random salt)."""
        key = fast_paseto.generate_symmetric_key()
        password = "same-password"

        encrypted1 = fast_paseto.local_pw_encrypt(key, password)
        encrypted2 = fast_paseto.local_pw_encrypt(key, password)

        # Different salts mean different encrypted outputs
        assert encrypted1 != encrypted2

        # But both should decrypt to the same key
        assert fast_paseto.local_pw_decrypt(encrypted1, password) == key
        assert fast_paseto.local_pw_decrypt(encrypted2, password) == key

    def test_secret_pw_encrypt_format(self):
        """Test that secret_pw_encrypt produces correct format."""
        secret_key, _ = fast_paseto.generate_keypair()
        password = "test-password-123"
        encrypted = fast_paseto.secret_pw_encrypt(secret_key, password)

        assert encrypted.startswith("k4.secret-pw.")
        assert len(encrypted.split(".")) == 3

    def test_secret_pw_roundtrip(self):
        """Test that encrypting and decrypting preserves the secret key."""
        secret_key, _ = fast_paseto.generate_keypair()
        password = "secure-password-456"

        encrypted = fast_paseto.secret_pw_encrypt(secret_key, password)
        decrypted = fast_paseto.secret_pw_decrypt(encrypted, password)

        assert decrypted == secret_key

    def test_secret_pw_wrong_password(self):
        """Test that decrypting with wrong password fails."""
        secret_key, _ = fast_paseto.generate_keypair()
        password = "correct-password"
        wrong_password = "wrong-password"

        encrypted = fast_paseto.secret_pw_encrypt(secret_key, password)

        with pytest.raises(fast_paseto.PasetoCryptoError):
            fast_paseto.secret_pw_decrypt(encrypted, wrong_password)

    def test_secret_pw_invalid_key_length(self):
        """Test that secret_pw_encrypt rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.secret_pw_encrypt(b"short", "password")

        assert "expected 64 bytes" in str(exc_info.value)

    def test_secret_pw_invalid_format(self):
        """Test that secret_pw_decrypt rejects invalid format."""
        # Wrong version
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.secret_pw_decrypt("k3.secret-pw.test", "password")

        # Wrong type
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.secret_pw_decrypt("k4.local-pw.test", "password")

        # Too few parts
        with pytest.raises(fast_paseto.PasetoKeyError):
            fast_paseto.secret_pw_decrypt("k4.secret-pw", "password")

    def test_secret_pw_different_encryptions(self):
        """Test that encrypting the same key twice produces different outputs (due to random salt)."""
        secret_key, _ = fast_paseto.generate_keypair()
        password = "same-password"

        encrypted1 = fast_paseto.secret_pw_encrypt(secret_key, password)
        encrypted2 = fast_paseto.secret_pw_encrypt(secret_key, password)

        # Different salts mean different encrypted outputs
        assert encrypted1 != encrypted2

        # But both should decrypt to the same key
        assert fast_paseto.secret_pw_decrypt(encrypted1, password) == secret_key
        assert fast_paseto.secret_pw_decrypt(encrypted2, password) == secret_key

    def test_generate_sid_format(self):
        """Test that generate_sid produces correct format."""
        secret_key, _ = fast_paseto.generate_keypair()
        sid = fast_paseto.generate_sid(secret_key)

        assert sid.startswith("k4.sid.")
        assert len(sid.split(".")) == 3
        assert "=" not in sid  # No padding

    def test_generate_pid_format(self):
        """Test that generate_pid produces correct format."""
        _, public_key = fast_paseto.generate_keypair()
        pid = fast_paseto.generate_pid(public_key)

        assert pid.startswith("k4.pid.")
        assert len(pid.split(".")) == 3
        assert "=" not in pid  # No padding

    def test_lid_determinism(self):
        """Test that the same key always produces the same LID."""
        key = fast_paseto.generate_symmetric_key()
        lid1 = fast_paseto.generate_lid(key)
        lid2 = fast_paseto.generate_lid(key)

        assert lid1 == lid2

    def test_sid_determinism(self):
        """Test that the same key always produces the same SID."""
        secret_key, _ = fast_paseto.generate_keypair()
        sid1 = fast_paseto.generate_sid(secret_key)
        sid2 = fast_paseto.generate_sid(secret_key)

        assert sid1 == sid2

    def test_pid_determinism(self):
        """Test that the same key always produces the same PID."""
        _, public_key = fast_paseto.generate_keypair()
        pid1 = fast_paseto.generate_pid(public_key)
        pid2 = fast_paseto.generate_pid(public_key)

        assert pid1 == pid2

    def test_different_keys_produce_different_lids(self):
        """Test that different keys produce different LIDs."""
        key1 = fast_paseto.generate_symmetric_key()
        key2 = fast_paseto.generate_symmetric_key()
        lid1 = fast_paseto.generate_lid(key1)
        lid2 = fast_paseto.generate_lid(key2)

        assert lid1 != lid2

    def test_different_keys_produce_different_sids(self):
        """Test that different keys produce different SIDs."""
        secret_key1, _ = fast_paseto.generate_keypair()
        secret_key2, _ = fast_paseto.generate_keypair()
        sid1 = fast_paseto.generate_sid(secret_key1)
        sid2 = fast_paseto.generate_sid(secret_key2)

        assert sid1 != sid2

    def test_different_keys_produce_different_pids(self):
        """Test that different keys produce different PIDs."""
        _, public_key1 = fast_paseto.generate_keypair()
        _, public_key2 = fast_paseto.generate_keypair()
        pid1 = fast_paseto.generate_pid(public_key1)
        pid2 = fast_paseto.generate_pid(public_key2)

        assert pid1 != pid2

    def test_generate_lid_invalid_length(self):
        """Test that generate_lid rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.generate_lid(b"short")

        assert "expected 32 bytes" in str(exc_info.value)

    def test_generate_sid_invalid_length(self):
        """Test that generate_sid rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.generate_sid(b"short")

        assert "expected 64 bytes" in str(exc_info.value)

    def test_generate_pid_invalid_length(self):
        """Test that generate_pid rejects keys of wrong length."""
        with pytest.raises(fast_paseto.PasetoKeyError) as exc_info:
            fast_paseto.generate_pid(b"short")

        assert "expected 32 bytes" in str(exc_info.value)


class TestPaserkPropertyTests:
    """Property-based tests for PASERK functionality."""

    @given(key_bytes=st.binary(min_size=32, max_size=32))
    @settings(max_examples=10)
    def test_property_17_paserk_local_roundtrip(self, key_bytes):
        """
        Property 17: PASERK Serialization Round-Trip (Local)

        For any valid 32-byte symmetric key, serializing to PASERK local format
        and deserializing SHALL return the original key bytes.

        Feature: paseto-implementation, Property 17: PASERK Serialization Round-Trip
        Validates: Requirements 10.1, 10.4
        """
        paserk = fast_paseto.to_paserk_local(key_bytes)
        key_type, decoded_key = fast_paseto.from_paserk(paserk)

        assert key_type == "local"
        assert decoded_key == key_bytes

    @given(key_bytes=st.binary(min_size=64, max_size=64))
    @settings(max_examples=10)
    def test_property_17_paserk_secret_roundtrip(self, key_bytes):
        """
        Property 17: PASERK Serialization Round-Trip (Secret)

        For any valid 64-byte Ed25519 secret key, serializing to PASERK secret format
        and deserializing SHALL return the original key bytes.

        Feature: paseto-implementation, Property 17: PASERK Serialization Round-Trip
        Validates: Requirements 10.2, 10.4
        """
        paserk = fast_paseto.to_paserk_secret(key_bytes)
        key_type, decoded_key = fast_paseto.from_paserk(paserk)

        assert key_type == "secret"
        assert decoded_key == key_bytes

    @given(key_bytes=st.binary(min_size=32, max_size=32))
    @settings(max_examples=10)
    def test_property_17_paserk_public_roundtrip(self, key_bytes):
        """
        Property 17: PASERK Serialization Round-Trip (Public)

        For any valid 32-byte Ed25519 public key, serializing to PASERK public format
        and deserializing SHALL return the original key bytes.

        Feature: paseto-implementation, Property 17: PASERK Serialization Round-Trip
        Validates: Requirements 10.3, 10.4
        """
        paserk = fast_paseto.to_paserk_public(key_bytes)
        key_type, decoded_key = fast_paseto.from_paserk(paserk)

        assert key_type == "public"
        assert decoded_key == key_bytes

    @given(key_bytes=st.binary(min_size=32, max_size=32))
    @settings(max_examples=10)
    def test_property_18_lid_determinism(self, key_bytes):
        """
        Property 18: PASERK ID Determinism (LID)

        For any symmetric key, generating a PASERK ID multiple times SHALL always
        produce the same ID string.

        Feature: paseto-implementation, Property 18: PASERK ID Determinism
        Validates: Requirements 10.5
        """
        lid1 = fast_paseto.generate_lid(key_bytes)
        lid2 = fast_paseto.generate_lid(key_bytes)

        assert lid1 == lid2
        assert lid1.startswith("k4.lid.")

    @given(key_bytes=st.binary(min_size=64, max_size=64))
    @settings(max_examples=10)
    def test_property_18_sid_determinism(self, key_bytes):
        """
        Property 18: PASERK ID Determinism (SID)

        For any Ed25519 secret key, generating a PASERK ID multiple times SHALL always
        produce the same ID string.

        Feature: paseto-implementation, Property 18: PASERK ID Determinism
        Validates: Requirements 10.5
        """
        sid1 = fast_paseto.generate_sid(key_bytes)
        sid2 = fast_paseto.generate_sid(key_bytes)

        assert sid1 == sid2
        assert sid1.startswith("k4.sid.")

    @given(key_bytes=st.binary(min_size=32, max_size=32))
    @settings(max_examples=10)
    def test_property_18_pid_determinism(self, key_bytes):
        """
        Property 18: PASERK ID Determinism (PID)

        For any Ed25519 public key, generating a PASERK ID multiple times SHALL always
        produce the same ID string.

        Feature: paseto-implementation, Property 18: PASERK ID Determinism
        Validates: Requirements 10.5
        """
        pid1 = fast_paseto.generate_pid(key_bytes)
        pid2 = fast_paseto.generate_pid(key_bytes)

        assert pid1 == pid2
        assert pid1.startswith("k4.pid.")

    @given(key_bytes=st.binary(min_size=32, max_size=32))
    @settings(max_examples=10)
    def test_paserk_format_validation(self, key_bytes):
        """
        Property: PASERK Format Validation

        All generated PASERK strings SHALL start with "k4." followed by the key type
        and SHALL contain exactly 3 dot-separated parts with no padding.
        """
        paserk_local = fast_paseto.to_paserk_local(key_bytes)
        assert paserk_local.startswith("k4.local.")
        assert len(paserk_local.split(".")) == 3
        assert "=" not in paserk_local

        paserk_public = fast_paseto.to_paserk_public(key_bytes)
        assert paserk_public.startswith("k4.public.")
        assert len(paserk_public.split(".")) == 3
        assert "=" not in paserk_public

    @given(
        key_bytes=st.binary(min_size=32, max_size=32),
        wrapping_key_bytes=st.binary(min_size=32, max_size=32),
    )
    @settings(max_examples=10)
    def test_property_19_local_wrap_roundtrip(self, key_bytes, wrapping_key_bytes):
        """
        Property 19: Key Wrapping Round-Trip (Local)

        For any symmetric key K and wrapping key W, wrapping K with W (local-wrap)
        and then unwrapping with W SHALL return the original key K.

        Feature: paseto-implementation, Property 19: Key Wrapping Round-Trip
        Validates: Requirements 10.6
        """
        wrapped = fast_paseto.local_wrap(key_bytes, wrapping_key_bytes)

        # Verify wrapped format
        assert wrapped.startswith("k4.local-wrap.pie.")
        assert len(wrapped.split(".")) == 4

        # Unwrap and verify round-trip
        unwrapped = fast_paseto.local_unwrap(wrapped, wrapping_key_bytes)
        assert unwrapped == key_bytes

    @given(
        key_bytes=st.binary(min_size=64, max_size=64),
        wrapping_key_bytes=st.binary(min_size=32, max_size=32),
    )
    @settings(max_examples=10)
    def test_property_19_secret_wrap_roundtrip(self, key_bytes, wrapping_key_bytes):
        """
        Property 19: Key Wrapping Round-Trip (Secret)

        For any secret key S and wrapping key W, wrapping S with W (secret-wrap)
        and then unwrapping with W SHALL return the original key S.

        Feature: paseto-implementation, Property 19: Key Wrapping Round-Trip
        Validates: Requirements 10.7
        """
        wrapped = fast_paseto.secret_wrap(key_bytes, wrapping_key_bytes)

        # Verify wrapped format
        assert wrapped.startswith("k4.secret-wrap.pie.")
        assert len(wrapped.split(".")) == 4

        # Unwrap and verify round-trip
        unwrapped = fast_paseto.secret_unwrap(wrapped, wrapping_key_bytes)
        assert unwrapped == key_bytes

    @given(
        key_bytes=st.binary(min_size=32, max_size=32),
        password=st.text(
            min_size=1,
            max_size=32,
            alphabet=st.characters(blacklist_categories=("Cs",)),
        ),
    )
    @settings(max_examples=10, deadline=60000)  # Reduced examples due to slow Argon2id
    def test_property_20_local_pw_roundtrip(self, key_bytes, password):
        """
        Property 20: Password-Based Key Encryption Round-Trip (Local)

        For any symmetric key K and password P, encrypting K with P (local-pw)
        and then decrypting with P SHALL return the original key K.

        Feature: paseto-implementation, Property 20: Password-Based Key Encryption Round-Trip
        Validates: Requirements 10.8
        """
        encrypted = fast_paseto.local_pw_encrypt(key_bytes, password)

        # Verify encrypted format
        assert encrypted.startswith("k4.local-pw.")
        assert len(encrypted.split(".")) == 3

        # Decrypt and verify round-trip
        decrypted = fast_paseto.local_pw_decrypt(encrypted, password)
        assert decrypted == key_bytes

    @given(
        key_bytes=st.binary(min_size=64, max_size=64),
        password=st.text(
            min_size=1,
            max_size=32,
            alphabet=st.characters(blacklist_categories=("Cs",)),
        ),
    )
    @settings(max_examples=10, deadline=60000)  # Reduced examples due to slow Argon2id
    def test_property_20_secret_pw_roundtrip(self, key_bytes, password):
        """
        Property 20: Password-Based Key Encryption Round-Trip (Secret)

        For any secret key S and password P, encrypting S with P (secret-pw)
        and then decrypting with P SHALL return the original key S.

        Feature: paseto-implementation, Property 20: Password-Based Key Encryption Round-Trip
        Validates: Requirements 10.9
        """
        encrypted = fast_paseto.secret_pw_encrypt(key_bytes, password)

        # Verify encrypted format
        assert encrypted.startswith("k4.secret-pw.")
        assert len(encrypted.split(".")) == 3

        # Decrypt and verify round-trip
        decrypted = fast_paseto.secret_pw_decrypt(encrypted, password)
        assert decrypted == key_bytes
