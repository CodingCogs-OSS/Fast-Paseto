"""Test Python exception hierarchy for fast_paseto"""

import fast_paseto


def test_exception_hierarchy():
    """Test that all exception classes are properly exposed and have correct inheritance"""
    # Check that all exception classes exist
    assert hasattr(fast_paseto, "PasetoError")
    assert hasattr(fast_paseto, "PasetoValidationError")
    assert hasattr(fast_paseto, "PasetoKeyError")
    assert hasattr(fast_paseto, "PasetoCryptoError")
    assert hasattr(fast_paseto, "PasetoExpiredError")
    assert hasattr(fast_paseto, "PasetoNotYetValidError")

    # Check inheritance hierarchy
    # PasetoValidationError inherits from PasetoError
    assert issubclass(fast_paseto.PasetoValidationError, fast_paseto.PasetoError)

    # PasetoKeyError inherits from PasetoValidationError (and transitively from PasetoError)
    assert issubclass(fast_paseto.PasetoKeyError, fast_paseto.PasetoValidationError)
    assert issubclass(fast_paseto.PasetoKeyError, fast_paseto.PasetoError)

    # PasetoCryptoError inherits from PasetoError
    assert issubclass(fast_paseto.PasetoCryptoError, fast_paseto.PasetoError)

    # PasetoExpiredError inherits from PasetoError
    assert issubclass(fast_paseto.PasetoExpiredError, fast_paseto.PasetoError)

    # PasetoNotYetValidError inherits from PasetoError
    assert issubclass(fast_paseto.PasetoNotYetValidError, fast_paseto.PasetoError)

    # All inherit from Exception
    assert issubclass(fast_paseto.PasetoError, Exception)

    print("✓ All exception classes exist and have correct inheritance")


def test_exception_instantiation():
    """Test that exceptions can be instantiated with messages"""
    try:
        raise fast_paseto.PasetoError("Base error")
    except fast_paseto.PasetoError as e:
        assert str(e) == "Base error"
        print("✓ PasetoError can be raised and caught")

    try:
        raise fast_paseto.PasetoKeyError("Invalid key")
    except fast_paseto.PasetoKeyError as e:
        assert str(e) == "Invalid key"
        print("✓ PasetoKeyError can be raised and caught")

    try:
        raise fast_paseto.PasetoKeyError("Invalid key")
    except fast_paseto.PasetoValidationError as e:
        # Should catch PasetoKeyError as PasetoValidationError
        assert str(e) == "Invalid key"
        print("✓ PasetoKeyError can be caught as PasetoValidationError")

    try:
        raise fast_paseto.PasetoExpiredError("Token expired")
    except fast_paseto.PasetoError as e:
        # Should catch PasetoExpiredError as PasetoError
        assert str(e) == "Token expired"
        print("✓ PasetoExpiredError can be caught as PasetoError")


if __name__ == "__main__":
    test_exception_hierarchy()
    test_exception_instantiation()
    print("\n✅ All exception hierarchy tests passed!")
