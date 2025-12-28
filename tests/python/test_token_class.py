"""
Test script for Token class implementation
Tests Requirements 14.1-14.6
"""

import fast_paseto


def test_token_creation():
    """Test creating a Token instance directly"""
    print("Test 1: Token creation")

    # Create a token with payload and metadata
    payload = {"sub": "user123", "exp": 1234567890, "custom_field": "value"}
    token = fast_paseto.Token(
        payload=payload, footer=None, version="v4", purpose="local"
    )

    # Test attribute access (Requirements 14.1-14.5)
    assert token.payload == payload, "Payload should match"
    assert token.footer is None, "Footer should be None"
    assert token.version == "v4", "Version should be v4"
    assert token.purpose == "local", "Purpose should be local"

    print("✓ Token attributes accessible")


def test_token_dict_like_access():
    """Test dict-like access to payload (Requirement 14.6)"""
    print("\nTest 2: Dict-like access")

    payload = {"sub": "user123", "exp": 1234567890, "custom_field": "value"}
    token = fast_paseto.Token(
        payload=payload, footer=None, version="v4", purpose="local"
    )

    # Test __getitem__ access
    assert token["sub"] == "user123", "Should access payload via []"
    assert token["exp"] == 1234567890, "Should access numeric values"
    assert token["custom_field"] == "value", "Should access custom fields"

    print("✓ Dict-like __getitem__ works")


def test_token_contains():
    """Test dict-like membership test (Requirement 14.6)"""
    print("\nTest 3: Membership test")

    payload = {"sub": "user123", "exp": 1234567890}
    token = fast_paseto.Token(
        payload=payload, footer=None, version="v4", purpose="local"
    )

    # Test __contains__
    assert "sub" in token, "Should find existing key"
    assert "exp" in token, "Should find existing key"
    assert "nonexistent" not in token, "Should not find missing key"

    print("✓ Dict-like __contains__ works")


def test_token_to_dict():
    """Test to_dict() method (Requirement 14.6)"""
    print("\nTest 4: to_dict() method")

    payload = {"sub": "user123"}
    footer = {"kid": "key-id-123"}
    token = fast_paseto.Token(
        payload=payload, footer=footer, version="v4", purpose="public"
    )

    # Test to_dict
    token_dict = token.to_dict()
    assert token_dict["payload"] == payload, "Dict should contain payload"
    assert token_dict["footer"] == footer, "Dict should contain footer"
    assert token_dict["version"] == "v4", "Dict should contain version"
    assert token_dict["purpose"] == "public", "Dict should contain purpose"

    print("✓ to_dict() method works")


def test_token_with_footer():
    """Test Token with footer present"""
    print("\nTest 5: Token with footer")

    payload = {"sub": "user123"}
    footer = {"kid": "key-id-123"}
    token = fast_paseto.Token(
        payload=payload, footer=footer, version="v4", purpose="local"
    )

    assert token.footer == footer, "Footer should be accessible"
    assert token.footer is not None, "Footer should not be None"

    print("✓ Token with footer works")


def test_token_repr():
    """Test Token string representation"""
    print("\nTest 6: Token __repr__")

    payload = {"sub": "user123"}
    token = fast_paseto.Token(
        payload=payload, footer=None, version="v4", purpose="local"
    )

    repr_str = repr(token)
    assert "Token" in repr_str, "Repr should contain 'Token'"
    assert "v4" in repr_str, "Repr should contain version"
    assert "local" in repr_str, "Repr should contain purpose"

    print(f"✓ Token repr: {repr_str}")


def test_token_key_error():
    """Test KeyError on missing key"""
    print("\nTest 7: KeyError on missing key")

    payload = {"sub": "user123"}
    token = fast_paseto.Token(
        payload=payload, footer=None, version="v4", purpose="local"
    )

    try:
        _ = token["nonexistent"]
        assert False, "Should raise KeyError"
    except KeyError as e:
        assert "nonexistent" in str(e), "Error should mention the key"
        print(f"✓ KeyError raised correctly: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Testing Token Class Implementation")
    print("Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6")
    print("=" * 60)

    try:
        test_token_creation()
        test_token_dict_like_access()
        test_token_contains()
        test_token_to_dict()
        test_token_with_footer()
        test_token_repr()
        test_token_key_error()

        print("\n" + "=" * 60)
        print("✅ All Token class tests passed!")
        print("=" * 60)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
