//! PASETO version and purpose types
//!
//! This module defines the Version and Purpose enums for PASETO tokens.

use crate::error::PasetoError;

/// PASETO version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V2,
    V3,
    V4,
}

impl Version {
    /// Convert version to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V2 => "v2",
            Version::V3 => "v3",
            Version::V4 => "v4",
        }
    }

    /// Parse version from string
    pub fn from_str(s: &str) -> Result<Self, PasetoError> {
        match s {
            "v2" => Ok(Version::V2),
            "v3" => Ok(Version::V3),
            "v4" => Ok(Version::V4),
            _ => Err(PasetoError::UnsupportedVersion(s.to_string())),
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// PASETO purpose
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Local,
    Public,
}

impl Purpose {
    /// Convert purpose to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Purpose::Local => "local",
            Purpose::Public => "public",
        }
    }

    /// Parse purpose from string
    pub fn from_str(s: &str) -> Result<Self, PasetoError> {
        match s {
            "local" => Ok(Purpose::Local),
            "public" => Ok(Purpose::Public),
            _ => Err(PasetoError::InvalidTokenFormat(format!(
                "Invalid purpose: {}",
                s
            ))),
        }
    }
}

impl std::fmt::Display for Purpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
