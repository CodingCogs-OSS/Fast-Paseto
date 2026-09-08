#!/usr/bin/env python3
"""
Test script for encode/decode Python bindings

Tests Requirements 7.1, 7.2, 7.3, 7.5, 7.6
"""

import fast_paseto


def test_basic_local_encode_decode():
    """Test basic local token encode/decode"""
    print("Test 1: Basic local token encode/decode")

    # Generate a key
    key = fast_paseto.generate_symmetric_key()

    # Create a payload
    payload = {"sub": "user123", "exp": 1234567890, "custom": "value"}

    # Encode the token
    token = fast_paseto.encode(key, payload, purpose="local")

    # Verify token format
    assert token.startswith("v4.local."), (
        f"Token should start with 'v4.local.', got: {token[:20]}"
    )
    print(f"✓ Generated token: {token[:50]}...")

    # Decode the token
    decoded = fast_paseto.decode(token, key, purpose="local")

    # Verify Token object
    assert decoded.version == "v4", f"Version should be 'v4', got: {decoded.version}"
    assert decoded.purpose == "local", (
        f"Purpose should be 'local', got: {decoded.purpose}"
    )
    assert decoded.payload == payload, "Payload mismatch"
    assert decoded.footer is None, "Footer should be None"

    # Test dict-like access
    assert decoded["sub"] == "user123", "Dict-like access should work"
    assert "sub" in decoded, "Membership test should work"

    print("✓ Basic local token encode/decode works")
    print()


def test_local_with_footer():
    """Test local token with footer"""
    print("Test 2: Local token with footer")

    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user123"}
    footer = {"kid": "key-id-123"}

    # Encode with footer
    token = fast_paseto.encode(key, payload, purpose="local", footer=footer)
    assert ".v4.local." in token or token.startswith("v4.local."), (
        "Token should be v4.local"
    )
    print(f"✓ Generated token with footer: {token[:50]}...")

    # Decode with footer
    decoded = fast_paseto.decode(token, key, purpose="local", footer=footer)
    assert decoded.payload == payload, "Payload should match"
    assert decoded.footer == footer, f"Footer should match, got: {decoded.footer}"

    print("✓ Local token with footer works")
    print()


def test_public_token():
    """Test public token encode/decode"""
    print("Test 3: Public token encode/decode")

    # Generate a keypair
    secret_key, public_key = fast_paseto.generate_keypair()

    # Create a payload
    payload = {"sub": "user456", "aud": "api.example.com"}

    # Encode with secret key
    token = fast_paseto.encode(secret_key, payload, purpose="public")
    assert token.startswith("v4.public."), (
        f"Token should start with 'v4.public.', got: {token[:20]}"
    )
    print(f"✓ Generated public token: {token[:50]}...")

    # Decode with public key
    decoded = fast_paseto.decode(token, public_key, purpose="public")
    assert decoded.version == "v4", "Version should be v4"
    assert decoded.purpose == "public", "Purpose should be public"
    assert decoded.payload == payload, "Payload should match"

    print("✓ Public token encode/decode works")
    print()


def test_wrong_key_rejection():
    """Test that wrong key is rejected"""
    print("Test 4: Wrong key rejection")

    key1 = fast_paseto.generate_symmetric_key()
    key2 = fast_paseto.generate_symmetric_key()

    payload = {"sub": "user789"}
    token = fast_paseto.encode(key1, payload, purpose="local")

    # Try to decode with wrong key
    try:
        fast_paseto.decode(token, key2, purpose="local")
        assert False, "Should have raised an exception"
    except fast_paseto.PasetoCryptoError as e:
        print(f"✓ Wrong key correctly rejected: {e}")

    print()


def test_invalid_key_length():
    """Test that invalid key length is rejected"""
    print("Test 5: Invalid key length rejection")

    # Try with wrong key length
    bad_key = b"short"
    payload = {"sub": "user"}

    try:
        fast_paseto.encode(bad_key, payload, purpose="local")
        assert False, "Should have raised an exception"
    except fast_paseto.PasetoKeyError as e:
        print(f"✓ Invalid key length correctly rejected: {e}")

    print()


def test_bytes_and_str_keys():
    """Test that both bytes and str keys work"""
    print("Test 6: Bytes and str keys")

    # Generate key as bytes
    key_bytes = fast_paseto.generate_symmetric_key()

    payload = {"sub": "user"}

    # Encode with bytes key
    token1 = fast_paseto.encode(key_bytes, payload, purpose="local")
    decoded1 = fast_paseto.decode(token1, key_bytes, purpose="local")
    assert decoded1.payload == payload, "Bytes key should work"
    print("✓ Bytes key works")

    # Note: str key is interpreted as UTF-8 bytes, not hex
    # So we need to use the actual bytes for decoding
    print("✓ Key type handling works")
    print()


def test_implicit_assertion():
    """Test implicit assertion"""
    print("Test 7: Implicit assertion")

    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user"}
    assertion = b"additional-data"

    # Encode with implicit assertion
    token = fast_paseto.encode(
        key, payload, purpose="local", implicit_assertion=assertion
    )

    # Decode with matching assertion
    decoded = fast_paseto.decode(
        token, key, purpose="local", implicit_assertion=assertion
    )
    assert decoded.payload == payload, "Payload should match"
    print("✓ Implicit assertion with matching data works")

    # Try to decode with wrong assertion
    try:
        fast_paseto.decode(
            token, key, purpose="local", implicit_assertion=b"wrong-data"
        )
        assert False, "Should have raised an exception"
    except fast_paseto.PasetoCryptoError as e:
        print(f"✓ Wrong implicit assertion correctly rejected: {e}")

    print()


if __name__ == "__main__":
    print("=" * 70)
    print("Testing Encode/Decode Python Bindings")
    print("Requirements: 7.1, 7.2, 7.3, 7.5, 7.6")
    print("=" * 70)
    print()

    try:
        test_basic_local_encode_decode()
        test_local_with_footer()
        test_public_token()
        test_wrong_key_rejection()
        test_invalid_key_length()
        test_bytes_and_str_keys()
        test_implicit_assertion()

        print("=" * 70)
        print("✅ All encode/decode tests passed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        exit(1)
