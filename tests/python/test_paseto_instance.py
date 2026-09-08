#!/usr/bin/env python3
"""
Property-based test for Paseto instance default application

Feature: paseto-implementation, Property 24: Paseto Instance Default Application
Validates: Requirements 13.1, 13.2, 13.4
"""

import time
from hypothesis import given, strategies as st, settings
import fast_paseto


# Strategy for generating payload dicts without exp/iat claims
payload_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=20).filter(lambda k: k not in ["exp", "iat"]),
    values=st.one_of(
        st.text(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.booleans(),
        st.none(),
    ),
    min_size=0,
    max_size=10,
)

# Strategy for generating default_exp values (1 second to 1 hour)
default_exp_strategy = st.integers(min_value=1, max_value=3600)


@given(
    payload=payload_strategy,
    default_exp=default_exp_strategy,
)
@settings(max_examples=100)
def test_paseto_instance_default_exp_application(payload, default_exp):
    """
    Property 24: Paseto Instance Default Application (exp claim)

    For any Paseto instance configured with default_exp=E and include_iat=true,
    encoding a token without explicit exp/iat claims SHALL produce a token where:
    - The exp claim is set to approximately current_time + E

    Validates: Requirements 13.1, 13.4
    """
    # Create Paseto instance with default_exp
    paseto = fast_paseto.Paseto(default_exp=default_exp, include_iat=False)

    # Generate key
    key = fast_paseto.generate_symmetric_key()

    # Record time before encoding
    time_before = int(time.time())

    # Encode token (should automatically add exp claim)
    token = paseto.encode(key, payload, purpose="local")

    # Record time after encoding
    time_after = int(time.time())

    # Decode token
    decoded = paseto.decode(token, key, purpose="local")

    # Requirement 13.1: exp claim should be present
    assert "exp" in decoded.payload, (
        "Token should have exp claim when default_exp is set"
    )

    # Requirement 13.4: exp claim should be approximately current_time + default_exp
    exp_value = decoded.payload["exp"]
    expected_exp_min = time_before + default_exp
    expected_exp_max = time_after + default_exp + 1  # Add 1 second tolerance

    assert expected_exp_min <= exp_value <= expected_exp_max, (
        f"exp claim should be approximately current_time + {default_exp}, got {exp_value}, expected between {expected_exp_min} and {expected_exp_max}"
    )

    # Verify original payload fields are preserved
    for key_name, value in payload.items():
        assert key_name in decoded.payload, (
            f"Original payload field '{key_name}' should be preserved"
        )
        assert decoded.payload[key_name] == value, (
            f"Original payload field '{key_name}' value should be preserved"
        )


@given(
    payload=payload_strategy,
)
@settings(max_examples=100)
def test_paseto_instance_default_iat_application(payload):
    """
    Property 24: Paseto Instance Default Application (iat claim)

    For any Paseto instance configured with include_iat=true,
    encoding a token without explicit iat claim SHALL produce a token where:
    - The iat claim is set to approximately current_time

    Validates: Requirements 13.2, 13.4
    """
    # Create Paseto instance with include_iat=True
    paseto = fast_paseto.Paseto(default_exp=None, include_iat=True)

    # Generate key
    key = fast_paseto.generate_symmetric_key()

    # Record time before encoding
    time_before = int(time.time())

    # Encode token (should automatically add iat claim)
    token = paseto.encode(key, payload, purpose="local")

    # Record time after encoding
    time_after = int(time.time())

    # Decode token
    decoded = paseto.decode(token, key, purpose="local")

    # Requirement 13.2: iat claim should be present
    assert "iat" in decoded.payload, (
        "Token should have iat claim when include_iat is True"
    )

    # Requirement 13.4: iat claim should be approximately current_time
    iat_value = decoded.payload["iat"]

    assert (
        time_before <= iat_value <= time_after + 1  # Add 1 second tolerance
    ), (
        f"iat claim should be approximately current_time, got {iat_value}, expected between {time_before} and {time_after}"
    )

    # Verify original payload fields are preserved
    for key_name, value in payload.items():
        assert key_name in decoded.payload, (
            f"Original payload field '{key_name}' should be preserved"
        )
        assert decoded.payload[key_name] == value, (
            f"Original payload field '{key_name}' value should be preserved"
        )


@given(
    payload=payload_strategy,
    default_exp=default_exp_strategy,
)
@settings(max_examples=100)
def test_paseto_instance_both_defaults_application(payload, default_exp):
    """
    Property 24: Paseto Instance Default Application (both exp and iat)

    For any Paseto instance configured with default_exp=E and include_iat=true,
    encoding a token without explicit exp/iat claims SHALL produce a token where:
    - The exp claim is set to approximately current_time + E
    - The iat claim is set to approximately current_time

    Validates: Requirements 13.1, 13.2, 13.4
    """
    # Create Paseto instance with both defaults
    paseto = fast_paseto.Paseto(default_exp=default_exp, include_iat=True)

    # Generate key
    key = fast_paseto.generate_symmetric_key()

    # Record time before encoding
    time_before = int(time.time())

    # Encode token (should automatically add exp and iat claims)
    token = paseto.encode(key, payload, purpose="local")

    # Record time after encoding
    time_after = int(time.time())

    # Decode token
    decoded = paseto.decode(token, key, purpose="local")

    # Requirement 13.1: exp claim should be present
    assert "exp" in decoded.payload, (
        "Token should have exp claim when default_exp is set"
    )

    # Requirement 13.2: iat claim should be present
    assert "iat" in decoded.payload, (
        "Token should have iat claim when include_iat is True"
    )

    # Requirement 13.4: exp claim should be approximately current_time + default_exp
    exp_value = decoded.payload["exp"]
    expected_exp_min = time_before + default_exp
    expected_exp_max = time_after + default_exp + 1  # Add 1 second tolerance

    assert expected_exp_min <= exp_value <= expected_exp_max, (
        f"exp claim should be approximately current_time + {default_exp}"
    )

    # Requirement 13.4: iat claim should be approximately current_time
    iat_value = decoded.payload["iat"]

    assert (
        time_before <= iat_value <= time_after + 1  # Add 1 second tolerance
    ), "iat claim should be approximately current_time"

    # Verify original payload fields are preserved
    for key_name, value in payload.items():
        assert key_name in decoded.payload, (
            f"Original payload field '{key_name}' should be preserved"
        )
        assert decoded.payload[key_name] == value, (
            f"Original payload field '{key_name}' value should be preserved"
        )


@given(
    payload=payload_strategy,
)
@settings(max_examples=100)
def test_paseto_instance_no_defaults_override(payload):
    """
    Property: Paseto instance does not override explicit claims

    For any Paseto instance with defaults configured, if the payload already
    contains exp or iat claims, they should NOT be overridden.

    Validates: Requirements 13.1, 13.2
    """
    # Create Paseto instance with defaults
    paseto = fast_paseto.Paseto(default_exp=3600, include_iat=True)

    # Generate key
    key = fast_paseto.generate_symmetric_key()

    # Add explicit exp and iat claims to payload
    explicit_exp = 9999999999
    explicit_iat = 1234567890
    payload_with_claims = {**payload, "exp": explicit_exp, "iat": explicit_iat}

    # Encode token
    token = paseto.encode(key, payload_with_claims, purpose="local")

    # Decode token
    decoded = paseto.decode(token, key, purpose="local")

    # Verify explicit claims were NOT overridden
    assert decoded.payload["exp"] == explicit_exp, (
        "Explicit exp claim should not be overridden"
    )
    assert decoded.payload["iat"] == explicit_iat, (
        "Explicit iat claim should not be overridden"
    )


@given(
    payload=payload_strategy,
    leeway=st.integers(min_value=0, max_value=300),
)
@settings(max_examples=100)
def test_paseto_instance_leeway_application(payload, leeway):
    """
    Property: Paseto instance applies leeway to decode

    For any Paseto instance configured with leeway=L, decoding a token
    should apply the leeway to time-based claim validation.

    Validates: Requirements 13.3, 13.5, 13.6
    """
    # Create Paseto instance with leeway
    paseto = fast_paseto.Paseto(leeway=leeway)

    # Generate key
    key = fast_paseto.generate_symmetric_key()

    # Create payload with exp claim in the past (but within leeway)
    current_time = int(time.time())
    # Set exp to be expired by less than leeway seconds
    exp_time = current_time - (leeway // 2 if leeway > 0 else 0)
    payload_with_exp = {**payload, "exp": exp_time}

    # Encode token with module-level encode (no leeway)
    token = fast_paseto.encode(key, payload_with_exp, purpose="local")

    # Decode with Paseto instance (should succeed due to leeway)
    # If leeway is 0, this might fail, but that's expected
    if leeway > 0:
        # Should succeed because exp is within leeway
        decoded = paseto.decode(token, key, purpose="local")
        assert decoded.payload["exp"] == exp_time, "exp claim should be preserved"
    else:
        # With leeway=0, expired token should fail
        # But we can't test this reliably because the token might not be expired yet
        # Just verify decode works
        decoded = paseto.decode(token, key, purpose="local")
        assert decoded.payload["exp"] == exp_time, "exp claim should be preserved"


if __name__ == "__main__":
    import sys

    print("=" * 70)
    print("Property-Based Test: Paseto Instance Default Application")
    print("Feature: paseto-implementation, Property 24")
    print("Validates: Requirements 13.1, 13.2, 13.4")
    print("=" * 70)
    print()

    # Run the property tests
    print("Running property test: test_paseto_instance_default_exp_application...")
    try:
        test_paseto_instance_default_exp_application()
        print("✓ Property 24 (exp): Paseto Instance Default Exp - PASSED (100 cases)")
    except Exception as e:
        print("✗ Property 24 (exp): Paseto Instance Default Exp - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("Running property test: test_paseto_instance_default_iat_application...")
    try:
        test_paseto_instance_default_iat_application()
        print("✓ Property 24 (iat): Paseto Instance Default Iat - PASSED (100 cases)")
    except Exception as e:
        print("✗ Property 24 (iat): Paseto Instance Default Iat - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("Running property test: test_paseto_instance_both_defaults_application...")
    try:
        test_paseto_instance_both_defaults_application()
        print(
            "✓ Property 24 (both): Paseto Instance Both Defaults - PASSED (100 cases)"
        )
    except Exception as e:
        print("✗ Property 24 (both): Paseto Instance Both Defaults - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("Running property test: test_paseto_instance_no_defaults_override...")
    try:
        test_paseto_instance_no_defaults_override()
        print("✓ Paseto Instance No Override - PASSED (100 cases)")
    except Exception as e:
        print("✗ Paseto Instance No Override - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("Running property test: test_paseto_instance_leeway_application...")
    try:
        test_paseto_instance_leeway_application()
        print("✓ Paseto Instance Leeway Application - PASSED (100 cases)")
    except Exception as e:
        print("✗ Paseto Instance Leeway Application - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("=" * 70)
    print("✅ All property tests passed!")
    print("=" * 70)
