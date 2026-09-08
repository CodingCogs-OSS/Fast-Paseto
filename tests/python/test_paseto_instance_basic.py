#!/usr/bin/env python3
"""
Basic integration test for Paseto instance class
"""

import time
import fast_paseto


def test_paseto_instance_basic():
    """Test basic Paseto instance functionality"""
    print("=" * 70)
    print("Testing Paseto Instance Class")
    print("=" * 70)
    print()

    # Test 1: Create Paseto instance with defaults
    print("Test 1: Create Paseto instance with defaults")
    paseto = fast_paseto.Paseto(default_exp=3600, include_iat=True, leeway=60)
    print(f"✓ Created Paseto instance: {paseto}")
    print()

    # Test 2: Encode with automatic exp and iat
    print("Test 2: Encode with automatic exp and iat")
    key = fast_paseto.generate_symmetric_key()
    payload = {"sub": "user123", "role": "admin"}
    token = paseto.encode(key, payload, purpose="local")
    print(f"✓ Encoded token: {token[:50]}...")
    print()

    # Test 3: Decode and verify exp/iat were added
    print("Test 3: Decode and verify exp/iat were added")
    decoded = paseto.decode(token, key, purpose="local")
    print(f"✓ Decoded payload: {decoded.payload}")
    assert "exp" in decoded.payload, "exp claim should be present"
    assert "iat" in decoded.payload, "iat claim should be present"
    assert decoded.payload["sub"] == "user123", "Original payload should be preserved"
    assert decoded.payload["role"] == "admin", "Original payload should be preserved"
    print("✓ exp and iat claims automatically added")
    print()

    # Test 4: Verify exp is approximately current_time + 3600
    print("Test 4: Verify exp is approximately current_time + 3600")
    current_time = int(time.time())
    exp_value = decoded.payload["exp"]
    expected_exp = current_time + 3600
    # Allow 5 second tolerance for test execution time
    assert abs(exp_value - expected_exp) <= 5, (
        f"exp should be approximately {expected_exp}, got {exp_value}"
    )
    print(f"✓ exp claim is correct: {exp_value} (expected ~{expected_exp})")
    print()

    # Test 5: Verify iat is approximately current_time
    print("Test 5: Verify iat is approximately current_time")
    iat_value = decoded.payload["iat"]
    assert abs(iat_value - current_time) <= 5, (
        f"iat should be approximately {current_time}, got {iat_value}"
    )
    print(f"✓ iat claim is correct: {iat_value} (expected ~{current_time})")
    print()

    # Test 6: Test with explicit exp/iat (should not override)
    print("Test 6: Test with explicit exp/iat (should not override)")
    explicit_exp = 9999999999
    explicit_iat = 1234567890
    payload_with_claims = {"sub": "user456", "exp": explicit_exp, "iat": explicit_iat}
    token2 = paseto.encode(key, payload_with_claims, purpose="local")
    decoded2 = paseto.decode(token2, key, purpose="local")
    assert decoded2.payload["exp"] == explicit_exp, (
        "Explicit exp should not be overridden"
    )
    assert decoded2.payload["iat"] == explicit_iat, (
        "Explicit iat should not be overridden"
    )
    print(
        f"✓ Explicit claims not overridden: exp={decoded2.payload['exp']}, iat={decoded2.payload['iat']}"
    )
    print()

    # Test 7: Test Paseto instance without defaults
    print("Test 7: Test Paseto instance without defaults")
    paseto_no_defaults = fast_paseto.Paseto(
        default_exp=None, include_iat=False, leeway=0
    )
    payload_simple = {"sub": "user789"}
    token3 = paseto_no_defaults.encode(key, payload_simple, purpose="local")
    decoded3 = paseto_no_defaults.decode(token3, key, purpose="local")
    assert "exp" not in decoded3.payload, (
        "exp should not be added when default_exp is None"
    )
    assert "iat" not in decoded3.payload, (
        "iat should not be added when include_iat is False"
    )
    print("✓ No defaults applied when not configured")
    print()

    # Test 8: Test leeway application
    print("Test 8: Test leeway application")
    paseto_with_leeway = fast_paseto.Paseto(leeway=300)  # 5 minutes leeway
    # Create a token that expired 2 minutes ago
    expired_time = int(time.time()) - 120
    payload_expired = {"sub": "user999", "exp": expired_time}
    token4 = fast_paseto.encode(key, payload_expired, purpose="local")
    # Should succeed because leeway is 300 seconds (5 minutes)
    decoded4 = paseto_with_leeway.decode(token4, key, purpose="local")
    print(f"✓ Expired token accepted with leeway: exp={decoded4.payload['exp']}")
    print()

    # Test 9: Test public tokens with Paseto instance
    print("Test 9: Test public tokens with Paseto instance")
    secret_key, public_key = fast_paseto.generate_keypair()
    paseto_public = fast_paseto.Paseto(default_exp=7200, include_iat=True)
    payload_public = {"sub": "user_public", "scope": "read"}
    token_public = paseto_public.encode(secret_key, payload_public, purpose="public")
    decoded_public = paseto_public.decode(token_public, public_key, purpose="public")
    assert "exp" in decoded_public.payload, "exp should be added to public tokens"
    assert "iat" in decoded_public.payload, "iat should be added to public tokens"
    assert decoded_public.payload["sub"] == "user_public", "Original payload preserved"
    print(f"✓ Public token with defaults: {decoded_public.payload}")
    print()

    print("=" * 70)
    print("✅ All Paseto instance tests passed!")
    print("=" * 70)


if __name__ == "__main__":
    test_paseto_instance_basic()
