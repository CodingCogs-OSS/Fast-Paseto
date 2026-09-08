#!/usr/bin/env python3
"""
Property-based test for Custom Serializer Round-Trip

Feature: paseto-implementation, Property 21: Custom Serializer Round-Trip
Validates: Requirements 11.1, 11.2, 11.3, 11.4
"""

import json
from hypothesis import given, strategies as st, settings
import fast_paseto


class JsonSerializer:
    """Wrapper for json module that matches Serializer Protocol."""

    def dumps(self, obj):
        return json.dumps(obj)

    def loads(self, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)


# Strategy for generating payload dicts with JSON-serializable values
payload_strategy = st.dictionaries(
    keys=st.text(
        alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd"),
            whitelist_characters="_-",
        ),
        min_size=1,
        max_size=20,
    ),
    values=st.one_of(
        st.text(max_size=100),
        st.integers(min_value=-(2**31), max_value=2**31),
        st.floats(
            allow_nan=False, allow_infinity=False, min_value=-1e10, max_value=1e10
        ),
        st.booleans(),
        st.none(),
    ),
    min_size=1,
    max_size=10,
)

# Strategy for generating optional footer dicts
footer_strategy = st.one_of(
    st.none(),
    st.dictionaries(
        keys=st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters="_-",
            ),
            min_size=1,
            max_size=20,
        ),
        values=st.one_of(
            st.text(max_size=50),
            st.integers(min_value=-(2**31), max_value=2**31),
            st.booleans(),
        ),
        min_size=1,
        max_size=5,
    ),
)


class CustomJsonSerializer:
    """Custom serializer that wraps json module for testing."""

    def dumps(self, obj):
        """Serialize object to JSON string."""
        return json.dumps(obj)

    def loads(self, data):
        """Deserialize JSON string/bytes to object."""
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)


class CustomBytesSerializer:
    """Custom serializer that returns bytes instead of string."""

    def dumps(self, obj):
        """Serialize object to JSON bytes."""
        return json.dumps(obj).encode("utf-8")

    def loads(self, data):
        """Deserialize JSON bytes/string to object."""
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)


@given(payload=payload_strategy)
@settings(max_examples=100)
def test_custom_serializer_round_trip_json_module(payload):
    """
    Property 21: Custom Serializer Round-Trip (json module)

    For any payload dict and the json module as serializer/deserializer,
    encoding a token with the serializer and decoding with the deserializer
    SHALL return the original payload dict.

    Validates: Requirements 11.1, 11.2, 11.3, 11.4
    """
    key = fast_paseto.generate_symmetric_key()
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = fast_paseto.encode(key, payload, purpose="local", serializer=serializer)

    # Decode with json as deserializer
    decoded = fast_paseto.decode(token, key, purpose="local", deserializer=serializer)

    # Verify round-trip: decoded payload should equal original payload
    assert decoded.payload == payload, (
        f"Round-trip failed: {decoded.payload} != {payload}"
    )


@given(payload=payload_strategy)
@settings(max_examples=100)
def test_custom_serializer_round_trip_custom_class(payload):
    """
    Property 21: Custom Serializer Round-Trip (custom class)

    For any payload dict and a custom serializer class with dumps()/loads() methods,
    encoding a token with the serializer and decoding with the deserializer
    SHALL return the original payload dict.

    Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
    """
    key = fast_paseto.generate_symmetric_key()
    serializer = CustomJsonSerializer()

    # Encode with custom serializer
    token = fast_paseto.encode(key, payload, purpose="local", serializer=serializer)

    # Decode with custom deserializer
    decoded = fast_paseto.decode(token, key, purpose="local", deserializer=serializer)

    # Verify round-trip: decoded payload should equal original payload
    assert decoded.payload == payload, (
        f"Round-trip failed: {decoded.payload} != {payload}"
    )


@given(payload=payload_strategy)
@settings(max_examples=100)
def test_custom_serializer_round_trip_bytes_serializer(payload):
    """
    Property 21: Custom Serializer Round-Trip (bytes serializer)

    For any payload dict and a custom serializer that returns bytes,
    encoding a token with the serializer and decoding with the deserializer
    SHALL return the original payload dict.

    Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
    """
    key = fast_paseto.generate_symmetric_key()
    serializer = CustomBytesSerializer()

    # Encode with custom serializer (returns bytes)
    token = fast_paseto.encode(key, payload, purpose="local", serializer=serializer)

    # Decode with custom deserializer
    decoded = fast_paseto.decode(token, key, purpose="local", deserializer=serializer)

    # Verify round-trip: decoded payload should equal original payload
    assert decoded.payload == payload, (
        f"Round-trip failed: {decoded.payload} != {payload}"
    )


@given(payload=payload_strategy, footer=footer_strategy)
@settings(max_examples=100)
def test_custom_serializer_round_trip_with_footer(payload, footer):
    """
    Property 21: Custom Serializer Round-Trip (with footer)

    For any payload dict and footer dict, encoding a token with a custom serializer
    and decoding with the deserializer SHALL return the original payload and footer.

    Validates: Requirements 11.1, 11.2, 11.3, 11.4
    """
    key = fast_paseto.generate_symmetric_key()
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = fast_paseto.encode(
        key, payload, purpose="local", footer=footer, serializer=serializer
    )

    # Decode with json as deserializer
    decoded = fast_paseto.decode(
        token, key, purpose="local", footer=footer, deserializer=serializer
    )

    # Verify round-trip: decoded payload should equal original payload
    assert decoded.payload == payload, (
        f"Payload round-trip failed: {decoded.payload} != {payload}"
    )

    # Verify footer round-trip
    if footer is not None:
        assert decoded.footer == footer, (
            f"Footer round-trip failed: {decoded.footer} != {footer}"
        )


@given(payload=payload_strategy)
@settings(max_examples=100)
def test_custom_serializer_round_trip_public_token(payload):
    """
    Property 21: Custom Serializer Round-Trip (public token)

    For any payload dict and the json module as serializer/deserializer,
    encoding a public token with the serializer and decoding with the deserializer
    SHALL return the original payload dict.

    Validates: Requirements 11.1, 11.2, 11.3, 11.4
    """
    secret_key, public_key = fast_paseto.generate_keypair()
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = fast_paseto.encode(
        secret_key, payload, purpose="public", serializer=serializer
    )

    # Decode with json as deserializer
    decoded = fast_paseto.decode(
        token, public_key, purpose="public", deserializer=serializer
    )

    # Verify round-trip: decoded payload should equal original payload
    assert decoded.payload == payload, (
        f"Round-trip failed: {decoded.payload} != {payload}"
    )


@given(payload=payload_strategy)
@settings(max_examples=100)
def test_custom_serializer_round_trip_paseto_instance(payload):
    """
    Property 21: Custom Serializer Round-Trip (Paseto instance)

    For any payload dict and a Paseto instance with custom serializer,
    encoding and decoding SHALL return the original payload dict
    (plus any auto-added claims like exp/iat).

    Validates: Requirements 11.1, 11.2, 11.3, 11.4
    """
    paseto = fast_paseto.Paseto(
        include_iat=False
    )  # Disable auto-iat for clean comparison
    key = fast_paseto.generate_symmetric_key()
    serializer = JsonSerializer()

    # Encode with json as serializer
    token = paseto.encode(key, payload, serializer=serializer)

    # Decode with json as deserializer
    decoded = paseto.decode(token, key, deserializer=serializer)

    # Verify round-trip: decoded payload should equal original payload
    assert decoded.payload == payload, (
        f"Round-trip failed: {decoded.payload} != {payload}"
    )


if __name__ == "__main__":
    import sys

    print("=" * 70)
    print("Property-Based Test: Custom Serializer Round-Trip")
    print("Feature: paseto-implementation, Property 21")
    print("Validates: Requirements 11.1, 11.2, 11.3, 11.4")
    print("=" * 70)
    print()

    tests = [
        (
            "test_custom_serializer_round_trip_json_module",
            test_custom_serializer_round_trip_json_module,
        ),
        (
            "test_custom_serializer_round_trip_custom_class",
            test_custom_serializer_round_trip_custom_class,
        ),
        (
            "test_custom_serializer_round_trip_bytes_serializer",
            test_custom_serializer_round_trip_bytes_serializer,
        ),
        (
            "test_custom_serializer_round_trip_with_footer",
            test_custom_serializer_round_trip_with_footer,
        ),
        (
            "test_custom_serializer_round_trip_public_token",
            test_custom_serializer_round_trip_public_token,
        ),
        (
            "test_custom_serializer_round_trip_paseto_instance",
            test_custom_serializer_round_trip_paseto_instance,
        ),
    ]

    for name, test_func in tests:
        print(f"Running property test: {name}...")
        try:
            test_func()
            print(f"✓ {name} - PASSED (100 cases)")
        except Exception as e:
            print(f"✗ {name} - FAILED")
            print(f"  Error: {e}")
            sys.exit(1)
        print()

    print("=" * 70)
    print("✅ All property tests passed!")
    print("=" * 70)
