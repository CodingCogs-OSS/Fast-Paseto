#!/usr/bin/env python3
"""
Property-based test for Token object field exposure

Feature: paseto-implementation, Property 25: Token Object Field Exposure
Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5
"""

from hypothesis import given, strategies as st
import fast_paseto


# Strategy for generating valid version strings
version_strategy = st.sampled_from(["v2", "v3", "v4"])

# Strategy for generating valid purpose strings
purpose_strategy = st.sampled_from(["local", "public"])

# Strategy for generating payload dicts
payload_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=20),
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

# Strategy for generating optional footer dicts
footer_strategy = st.one_of(
    st.none(),
    st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.one_of(
            st.text(),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.booleans(),
            st.none(),
        ),
        min_size=0,
        max_size=10,
    ),
)


@given(
    payload=payload_strategy,
    footer=footer_strategy,
    version=version_strategy,
    purpose=purpose_strategy,
)
def test_token_field_exposure(payload, footer, version, purpose):
    """
    Property 25: Token Object Field Exposure

    For any successfully decoded token, the Token_Object SHALL expose:
    - payload: the decoded payload as a dict
    - footer: the decoded footer (or None if not present)
    - version: the token version string (v2, v3, or v4)
    - purpose: the token purpose string (local or public)

    Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5
    """
    # Create a Token instance with random data
    token = fast_paseto.Token(
        payload=payload,
        footer=footer,
        version=version,
        purpose=purpose,
    )

    # Requirement 14.1: Token exposes the decoded payload
    assert token.payload == payload, "Token should expose payload"

    # Requirement 14.2: Token exposes the decoded footer (if present)
    assert token.footer == footer, "Token should expose footer"

    # Requirement 14.3: Token exposes the token version
    assert token.version == version, "Token should expose version"
    assert token.version in ["v2", "v3", "v4"], "Version should be valid"

    # Requirement 14.4: Token exposes the token purpose
    assert token.purpose == purpose, "Token should expose purpose"
    assert token.purpose in ["local", "public"], "Purpose should be valid"

    # Requirement 14.5: Token exposes version and purpose
    # (already tested above, but explicitly verify both are accessible)
    assert hasattr(token, "version"), "Token should have version attribute"
    assert hasattr(token, "purpose"), "Token should have purpose attribute"


@given(
    payload=payload_strategy,
    footer=footer_strategy,
    version=version_strategy,
    purpose=purpose_strategy,
)
def test_token_dict_like_access(payload, footer, version, purpose):
    """
    Property: Token dict-like access works for all payloads

    For any Token with a dict payload, dict-like access should work correctly.

    Validates: Requirement 14.6
    """
    # Create a Token instance
    token = fast_paseto.Token(
        payload=payload,
        footer=footer,
        version=version,
        purpose=purpose,
    )

    # Test __contains__ for all keys in payload
    for key in payload.keys():
        assert key in token, f"Key '{key}' should be in token"

    # Test __getitem__ for all keys in payload
    for key, value in payload.items():
        assert token[key] == value, f"token['{key}'] should equal payload['{key}']"

    # Test that non-existent keys are not in token
    assert (
        "nonexistent_key_12345" not in token
    ), "Non-existent key should not be in token"


@given(
    payload=payload_strategy,
    footer=footer_strategy,
    version=version_strategy,
    purpose=purpose_strategy,
)
def test_token_to_dict(payload, footer, version, purpose):
    """
    Property: Token to_dict() returns all fields

    For any Token, to_dict() should return a dict with all fields.

    Validates: Requirement 14.6
    """
    # Create a Token instance
    token = fast_paseto.Token(
        payload=payload,
        footer=footer,
        version=version,
        purpose=purpose,
    )

    # Convert to dict
    token_dict = token.to_dict()

    # Verify all fields are present
    assert "payload" in token_dict, "to_dict() should include payload"
    assert "footer" in token_dict, "to_dict() should include footer"
    assert "version" in token_dict, "to_dict() should include version"
    assert "purpose" in token_dict, "to_dict() should include purpose"

    # Verify values match
    assert token_dict["payload"] == payload, "to_dict() payload should match"
    assert token_dict["footer"] == footer, "to_dict() footer should match"
    assert token_dict["version"] == version, "to_dict() version should match"
    assert token_dict["purpose"] == purpose, "to_dict() purpose should match"


if __name__ == "__main__":
    import sys

    print("=" * 70)
    print("Property-Based Test: Token Object Field Exposure")
    print("Feature: paseto-implementation, Property 25")
    print("Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5")
    print("=" * 70)
    print()

    # Run the property tests
    print("Running property test: test_token_field_exposure...")
    try:
        test_token_field_exposure()
        print("✓ Property 25: Token Object Field Exposure - PASSED (100 cases)")
    except Exception as e:
        print("✗ Property 25: Token Object Field Exposure - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("Running property test: test_token_dict_like_access...")
    try:
        test_token_dict_like_access()
        print("✓ Token dict-like access property - PASSED (100 cases)")
    except Exception as e:
        print("✗ Token dict-like access property - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("Running property test: test_token_to_dict...")
    try:
        test_token_to_dict()
        print("✓ Token to_dict() property - PASSED (100 cases)")
    except Exception as e:
        print("✗ Token to_dict() property - FAILED")
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("=" * 70)
    print("✅ All property tests passed!")
    print("=" * 70)
