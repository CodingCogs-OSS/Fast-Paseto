#!/usr/bin/env python3
"""Test script for key generation Python bindings"""

import fast_paseto


def test_generate_symmetric_key():
    """Test symmetric key generation"""
    print("Testing generate_symmetric_key()...")

    # Generate a key
    key = fast_paseto.generate_symmetric_key()

    # Check type
    assert isinstance(key, bytes), f"Expected bytes, got {type(key)}"

    # Check length
    assert len(key) == 32, f"Expected 32 bytes, got {len(key)}"

    # Generate another key and ensure they're different
    key2 = fast_paseto.generate_symmetric_key()
    assert key != key2, "Two generated keys should be different"

    print(f"✓ Generated symmetric key: {len(key)} bytes")
    print(f"  First few bytes: {key[:8].hex()}")
    print()


def test_generate_keypair():
    """Test Ed25519 keypair generation"""
    print("Testing generate_keypair()...")

    # Generate a keypair
    secret_key, public_key = fast_paseto.generate_keypair()

    # Check types
    assert isinstance(secret_key, bytes), (
        f"Expected bytes for secret_key, got {type(secret_key)}"
    )
    assert isinstance(public_key, bytes), (
        f"Expected bytes for public_key, got {type(public_key)}"
    )

    # Check lengths
    assert len(secret_key) == 64, (
        f"Expected 64 bytes for secret_key, got {len(secret_key)}"
    )
    assert len(public_key) == 32, (
        f"Expected 32 bytes for public_key, got {len(public_key)}"
    )

    # Generate another keypair and ensure they're different
    secret_key2, public_key2 = fast_paseto.generate_keypair()
    assert secret_key != secret_key2, "Two generated secret keys should be different"
    assert public_key != public_key2, "Two generated public keys should be different"

    print("✓ Generated Ed25519 keypair:")
    print(f"  Secret key: {len(secret_key)} bytes")
    print(f"  Public key: {len(public_key)} bytes")
    print(f"  Public key (hex): {public_key.hex()}")
    print()


def test_multiple_generations():
    """Test generating multiple keys to ensure randomness"""
    print("Testing multiple key generations for randomness...")

    # Generate 10 symmetric keys
    symmetric_keys = [fast_paseto.generate_symmetric_key() for _ in range(10)]

    # Ensure all are unique
    unique_keys = set(symmetric_keys)
    assert len(unique_keys) == 10, f"Expected 10 unique keys, got {len(unique_keys)}"

    # Generate 10 keypairs
    keypairs = [fast_paseto.generate_keypair() for _ in range(10)]

    # Ensure all secret keys are unique
    unique_secrets = set(sk for sk, _ in keypairs)
    assert len(unique_secrets) == 10, (
        f"Expected 10 unique secret keys, got {len(unique_secrets)}"
    )

    # Ensure all public keys are unique
    unique_publics = set(pk for _, pk in keypairs)
    assert len(unique_publics) == 10, (
        f"Expected 10 unique public keys, got {len(unique_publics)}"
    )

    print("✓ Generated 10 unique symmetric keys")
    print("✓ Generated 10 unique Ed25519 keypairs")
    print()


if __name__ == "__main__":
    print("=" * 60)
    print("Testing Key Generation Python Bindings")
    print("=" * 60)
    print()

    try:
        test_generate_symmetric_key()
        test_generate_keypair()
        test_multiple_generations()

        print("=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
    except AssertionError as e:
        print(f"✗ Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        exit(1)
