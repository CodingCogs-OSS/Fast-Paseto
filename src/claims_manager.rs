use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::PasetoError;

/// Claims management utilities
pub struct ClaimsManager;

impl ClaimsManager {
    /// Create expiration claim relative to now
    pub fn exp_in(seconds: u64) -> u64 {
        Self::now() + seconds
    }

    /// Create not-before claim relative to now
    pub fn nbf_in(seconds: u64) -> u64 {
        Self::now() + seconds
    }

    /// Get current timestamp for iat claim
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Validate expiration claim
    pub fn validate_exp(exp: u64, leeway: u64) -> Result<(), PasetoError> {
        let now = Self::now();
        if now > exp + leeway {
            return Err(PasetoError::TokenExpired);
        }
        Ok(())
    }

    /// Validate not-before claim
    pub fn validate_nbf(nbf: u64, leeway: u64) -> Result<(), PasetoError> {
        let now = Self::now();
        if now + leeway < nbf {
            return Err(PasetoError::TokenNotYetValid);
        }
        Ok(())
    }

    /// Validate issued-at claim
    pub fn validate_iat(iat: u64, leeway: u64) -> Result<(), PasetoError> {
        let now = Self::now();
        if iat > now + leeway {
            return Err(PasetoError::TokenIssuedInFuture);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_exp_in() {
        let now = ClaimsManager::now();
        let exp = ClaimsManager::exp_in(3600);
        assert!(exp >= now + 3600);
        assert!(exp <= now + 3601); // Allow 1 second tolerance for test execution time
    }

    #[test]
    fn test_nbf_in() {
        let now = ClaimsManager::now();
        let nbf = ClaimsManager::nbf_in(60);
        assert!(nbf >= now + 60);
        assert!(nbf <= now + 61); // Allow 1 second tolerance
    }

    #[test]
    fn test_now() {
        let timestamp = ClaimsManager::now();
        // Should be a reasonable Unix timestamp (after 2020-01-01)
        assert!(timestamp > 1577836800);
    }

    #[test]
    fn test_validate_exp_valid() {
        let future_exp = ClaimsManager::now() + 3600;
        assert!(ClaimsManager::validate_exp(future_exp, 0).is_ok());
    }

    #[test]
    fn test_validate_exp_expired() {
        let past_exp = ClaimsManager::now() - 3600;
        let result = ClaimsManager::validate_exp(past_exp, 0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasetoError::TokenExpired));
    }

    #[test]
    fn test_validate_exp_with_leeway() {
        let exp = ClaimsManager::now() - 5; // 5 seconds in the past
        // Should fail with 0 leeway
        assert!(ClaimsManager::validate_exp(exp, 0).is_err());
        // Should succeed with 10 second leeway
        assert!(ClaimsManager::validate_exp(exp, 10).is_ok());
    }

    #[test]
    fn test_validate_nbf_valid() {
        let past_nbf = ClaimsManager::now() - 3600;
        assert!(ClaimsManager::validate_nbf(past_nbf, 0).is_ok());
    }

    #[test]
    fn test_validate_nbf_not_yet_valid() {
        let future_nbf = ClaimsManager::now() + 3600;
        let result = ClaimsManager::validate_nbf(future_nbf, 0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PasetoError::TokenNotYetValid));
    }

    #[test]
    fn test_validate_nbf_with_leeway() {
        let nbf = ClaimsManager::now() + 5; // 5 seconds in the future
        // Should fail with 0 leeway
        assert!(ClaimsManager::validate_nbf(nbf, 0).is_err());
        // Should succeed with 10 second leeway
        assert!(ClaimsManager::validate_nbf(nbf, 10).is_ok());
    }

    #[test]
    fn test_validate_iat_valid() {
        let past_iat = ClaimsManager::now() - 3600;
        assert!(ClaimsManager::validate_iat(past_iat, 0).is_ok());
    }

    #[test]
    fn test_validate_iat_future() {
        let future_iat = ClaimsManager::now() + 3600;
        let result = ClaimsManager::validate_iat(future_iat, 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PasetoError::TokenIssuedInFuture
        ));
    }

    #[test]
    fn test_validate_iat_with_leeway() {
        let iat = ClaimsManager::now() + 5; // 5 seconds in the future
        // Should fail with 0 leeway
        assert!(ClaimsManager::validate_iat(iat, 0).is_err());
        // Should succeed with 10 second leeway
        assert!(ClaimsManager::validate_iat(iat, 10).is_ok());
    }

    // **Feature: paseto-implementation, Property 14: Expiration Claim Validation**
    // **Validates: Requirements 6.2, 6.7**
    //
    // For any token with an `exp` claim set to time T and any leeway L, verification at time T' SHALL:
    // - Succeed if T' ≤ T + L
    // - Fail with TokenExpired error if T' > T + L
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_expiration_claim_validation(
            exp_offset in -86400i64..86400i64,  // +/- 1 day from now
            leeway in 0u64..3600u64,             // 0 to 1 hour leeway
        ) {
            let now = ClaimsManager::now();
            let exp = (now as i64 + exp_offset) as u64;

            let result = ClaimsManager::validate_exp(exp, leeway);

            // Property: Should succeed if now <= exp + leeway
            // Property: Should fail with TokenExpired if now > exp + leeway
            if now <= exp + leeway {
                prop_assert!(result.is_ok(), "Expected validation to succeed when now ({}) <= exp ({}) + leeway ({})", now, exp, leeway);
            } else {
                prop_assert!(result.is_err(), "Expected validation to fail when now ({}) > exp ({}) + leeway ({})", now, exp, leeway);
                prop_assert!(matches!(result.unwrap_err(), PasetoError::TokenExpired), "Expected TokenExpired error");
            }
        }
    }

    // **Feature: paseto-implementation, Property 15: Not-Before Claim Validation**
    // **Validates: Requirements 6.3, 6.7**
    //
    // For any token with an `nbf` claim set to time T and any leeway L, verification at time T' SHALL:
    // - Succeed if T' + L ≥ T
    // - Fail with TokenNotYetValid error if T' + L < T
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_not_before_claim_validation(
            nbf_offset in -86400i64..86400i64,  // +/- 1 day from now
            leeway in 0u64..3600u64,             // 0 to 1 hour leeway
        ) {
            let now = ClaimsManager::now();
            let nbf = (now as i64 + nbf_offset) as u64;

            let result = ClaimsManager::validate_nbf(nbf, leeway);

            // Property: Should succeed if now + leeway >= nbf
            // Property: Should fail with TokenNotYetValid if now + leeway < nbf
            if now + leeway >= nbf {
                prop_assert!(result.is_ok(), "Expected validation to succeed when now ({}) + leeway ({}) >= nbf ({})", now, leeway, nbf);
            } else {
                prop_assert!(result.is_err(), "Expected validation to fail when now ({}) + leeway ({}) < nbf ({})", now, leeway, nbf);
                prop_assert!(matches!(result.unwrap_err(), PasetoError::TokenNotYetValid), "Expected TokenNotYetValid error");
            }
        }
    }

    // **Feature: paseto-implementation, Property 16: Issued-At Claim Validation**
    // **Validates: Requirements 6.4, 6.7**
    //
    // For any token with an `iat` claim set to time T and any leeway L, verification at time T' SHALL:
    // - Succeed if T ≤ T' + L
    // - Fail with TokenIssuedInFuture error if T > T' + L
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_issued_at_claim_validation(
            iat_offset in -86400i64..86400i64,  // +/- 1 day from now
            leeway in 0u64..3600u64,             // 0 to 1 hour leeway
        ) {
            let now = ClaimsManager::now();
            let iat = (now as i64 + iat_offset) as u64;

            let result = ClaimsManager::validate_iat(iat, leeway);

            // Property: Should succeed if iat <= now + leeway
            // Property: Should fail with TokenIssuedInFuture if iat > now + leeway
            if iat <= now + leeway {
                prop_assert!(result.is_ok(), "Expected validation to succeed when iat ({}) <= now ({}) + leeway ({})", iat, now, leeway);
            } else {
                prop_assert!(result.is_err(), "Expected validation to fail when iat ({}) > now ({}) + leeway ({})", iat, now, leeway);
                prop_assert!(matches!(result.unwrap_err(), PasetoError::TokenIssuedInFuture), "Expected TokenIssuedInFuture error");
            }
        }
    }
}
