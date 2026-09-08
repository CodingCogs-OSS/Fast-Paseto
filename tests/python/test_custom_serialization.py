#!/usr/bin/env python3
"""
Test script for custom serialization support

Tests Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7
"""

import json
import fast_paseto


class JsonSerializer:
    """Wrapper for json module that matches Serializer Protocol."""

    def dumps(self, obj):
        return json.dumps(obj)

    def loads(self, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)


def test_custom_serializer_json_module():
    """Test using json module as custom serializer"""
    print("Test 1: Using json module as custom serializer")

    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user123", "data": {"nested": "value"}}
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = fast_paseto.encode(key, payload, purpose="local", serializer=serializer)
    assert token.startswith("v4.local."), (
        f"Token should start with 'v4.local.', got: {token[:20]}"
    )
    print(f"✓ Generated token with json serializer: {token[:50]}...")

    # Decode with json as deserializer
    decoded = fast_paseto.decode(token, key, purpose="local", deserializer=serializer)
    assert decoded.payload == payload, (
        f"Payload mismatch: {decoded.payload} != {payload}"
    )
    print("✓ Custom serializer (json module) works")
    print()


def test_custom_serializer_class():
    """Test using a custom serializer class"""
    print("Test 2: Using custom serializer class")

    class CustomSerializer:
        """Custom serializer that adds a prefix to JSON"""

        def dumps(self, obj):
            return json.dumps(obj)

        def loads(self, data):
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            return json.loads(data)

    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user456", "custom": True}
    serializer = CustomSerializer()

    # Encode with custom serializer
    token = fast_paseto.encode(key, payload, purpose="local", serializer=serializer)
    print(f"✓ Generated token with custom serializer: {token[:50]}...")

    # Decode with custom deserializer
    decoded = fast_paseto.decode(token, key, purpose="local", deserializer=serializer)
    assert decoded.payload == payload, (
        f"Payload mismatch: {decoded.payload} != {payload}"
    )
    print("✓ Custom serializer class works")
    print()


def test_bytes_payload_without_serializer():
    """Test using bytes payload directly without serializer"""
    print("Test 3: Using bytes payload without serializer")

    key = fast_paseto.generate_symmetric_key()
    payload_bytes = b'{"sub": "user789", "raw": true}'

    # Encode with bytes payload
    token = fast_paseto.encode(key, payload_bytes, purpose="local")
    print(f"✓ Generated token with bytes payload: {token[:50]}...")

    # Decode - should get back the JSON as dict
    decoded = fast_paseto.decode(token, key, purpose="local")
    assert decoded.payload["sub"] == "user789", "Payload sub mismatch"
    assert decoded.payload["raw"] is True, "Payload raw mismatch"
    print("✓ Bytes payload without serializer works")
    print()


def test_string_payload_without_serializer():
    """Test using string payload directly without serializer"""
    print("Test 4: Using string payload without serializer")

    key = fast_paseto.generate_symmetric_key()
    payload_str = '{"sub": "user101", "string": true}'

    # Encode with string payload
    token = fast_paseto.encode(key, payload_str, purpose="local")
    print(f"✓ Generated token with string payload: {token[:50]}...")

    # Decode - should get back the JSON as dict
    decoded = fast_paseto.decode(token, key, purpose="local")
    assert decoded.payload["sub"] == "user101", "Payload sub mismatch"
    assert decoded.payload["string"] is True, "Payload string mismatch"
    print("✓ String payload without serializer works")
    print()


def test_custom_serializer_with_footer():
    """Test custom serializer with footer"""
    print("Test 5: Custom serializer with footer")

    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user202"}
    footer = {"kid": "key-123", "version": 1}
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = fast_paseto.encode(
        key, payload, purpose="local", footer=footer, serializer=serializer
    )
    print(f"✓ Generated token with footer: {token[:50]}...")

    # Decode with json as deserializer
    decoded = fast_paseto.decode(
        token, key, purpose="local", footer=footer, deserializer=serializer
    )
    assert decoded.payload == payload, "Payload mismatch"
    assert decoded.footer == footer, f"Footer mismatch: {decoded.footer} != {footer}"
    print("✓ Custom serializer with footer works")
    print()


def test_paseto_instance_with_serializer():
    """Test Paseto instance with custom serializer"""
    print("Test 6: Paseto instance with custom serializer")

    paseto = fast_paseto.Paseto(default_exp=3600, include_iat=True)
    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user303"}
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = paseto.encode(key, payload, serializer=serializer)
    print(f"✓ Generated token with Paseto instance: {token[:50]}...")

    # Decode with json as deserializer
    decoded = paseto.decode(token, key, deserializer=serializer)
    assert decoded.payload["sub"] == "user303", "Payload sub mismatch"
    assert "exp" in decoded.payload, "exp claim should be present"
    assert "iat" in decoded.payload, "iat claim should be present"
    print("✓ Paseto instance with custom serializer works")
    print()


def test_public_token_with_serializer():
    """Test public token with custom serializer"""
    print("Test 7: Public token with custom serializer")

    secret_key, public_key = fast_paseto.generate_keypair()
    payload = {"sub": "user404", "aud": "api.example.com"}
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = fast_paseto.encode(
        secret_key, payload, purpose="public", serializer=serializer
    )
    assert token.startswith("v4.public."), "Token should start with 'v4.public.'"
    print(f"✓ Generated public token: {token[:50]}...")

    # Decode with json as deserializer
    decoded = fast_paseto.decode(
        token, public_key, purpose="public", deserializer=serializer
    )
    assert decoded.payload == payload, "Payload mismatch"
    print("✓ Public token with custom serializer works")
    print()


def test_fallback_to_json():
    """Test that JSON is used when no serializer is provided"""
    print("Test 8: Fallback to JSON when no serializer provided")

    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user505", "nested": {"key": "value"}}

    # Encode without serializer (should use JSON)
    token = fast_paseto.encode(key, payload, purpose="local")
    print(f"✓ Generated token without serializer: {token[:50]}...")

    # Decode without deserializer (should use JSON)
    decoded = fast_paseto.decode(token, key, purpose="local")
    assert decoded.payload == payload, "Payload mismatch"
    print("✓ Fallback to JSON works")
    print()


if __name__ == "__main__":
    print("=" * 70)
    print("Testing Custom Serialization Support")
    print("Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7")
    print("=" * 70)
    print()

    try:
        test_custom_serializer_json_module()
        test_custom_serializer_class()
        test_bytes_payload_without_serializer()
        test_string_payload_without_serializer()
        test_custom_serializer_with_footer()
        test_paseto_instance_with_serializer()
        test_public_token_with_serializer()
        test_fallback_to_json()

        print("=" * 70)
        print("✅ All custom serialization tests passed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        exit(1)
