use core::fmt;

/// Custom error type for cryptographic operations.
/// Groups common wolfCrypt error types into categories.
#[derive(Debug)]
pub enum WCError {
    /// Operation completed successfully (ret = 0)
    Success,
    /// Generic failure (-1)
    Failure,
    /// Memory-related errors (MEMORY_E, MP_MEM, etc.)
    Memory,
    /// Invalid arguments or state (BAD_FUNC_ARG, BAD_STATE_E, etc.)
    InvalidArgument,
    /// Buffer-related errors (BUFFER_E, RSA_BUFFER_E, etc.)
    Buffer,
    /// Authentication failures (MAC_CMP_FAILED_E, AES_GCM_AUTH_E, etc.)
    Authentication,
    /// Random number generation errors (RNG_FAILURE_E, MISSING_RNG_E, etc.)
    RandomError,
    /// ASN parsing errors (ASN_PARSE_E and related)
    ASNParse,
    /// Key-related errors (RSA_KEY_PAIR_E, ECC_PRIV_KEY_E, etc.)
    KeyError,
    /// Feature not available (NOT_COMPILED_IN, CRYPTOCB_UNAVAILABLE, etc.)
    NotAvailable,
}

impl fmt::Display for WCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WCError::Success => write!(f, "Operation successful"),
            WCError::Failure => write!(f, "Operation failed"),
            WCError::Memory => write!(f, "Memory allocation error"),
            WCError::InvalidArgument => write!(f, "Invalid argument or state"),
            WCError::Buffer => write!(f, "Buffer error"),
            WCError::Authentication => write!(f, "Authentication failed"),
            WCError::RandomError => write!(f, "Random number generation error"),
            WCError::ASNParse => write!(f, "ASN parsing error"),
            WCError::KeyError => write!(f, "Key-related error"),
            WCError::NotAvailable => write!(f, "Feature not available"),
        }
    }
}

/// A result type for cryptographic operations.
pub type WCResult = Result<(), WCError>;

/// Internal function to map wolfCrypt error codes to WCError variants
fn check_error(ret: i32) -> WCResult {
    match ret {
        0 => Ok(()),
        -1 => Err(WCError::Failure),
        -125 => Err(WCError::Memory),
        -173 => Err(WCError::InvalidArgument),
        -132 => Err(WCError::Buffer),
        -181..=-180 | -213 => Err(WCError::Authentication),
        -199 | -236 => Err(WCError::RandomError),
        -162..=-140 => Err(WCError::ASNParse),
        -262 | -216 => Err(WCError::KeyError),
        -174 | -271 => Err(WCError::NotAvailable),
        _ => Err(WCError::Failure),
    }
}

/// Checks if the FFI return value is `0` (indicating success).
/// Returns `Ok(())` if success, otherwise returns `Err(CryptoError::Failure)`
/// if the value is not `0`.
///
/// # Arguments
/// * `ret` - The return value from the FFI call (i32).
///
/// # Returns
/// `CryptoResult` indicating either success or failure.
pub fn check_if_zero(ret: i32) -> WCResult {
    check_error(ret)
}

/// Checks if the FFI return value is `1` (indicating success).
/// Returns `Ok(())` if success, otherwise returns `Err(CryptoError::Failure)`
/// if the value is not `1`.
///
/// # Arguments
/// * `stat` - The return value from the FFI call (i32).
///
/// # Returns
/// `CryptoResult` indicating either success or failure.
pub fn check_if_one(stat: i32) -> WCResult {
    match stat {
        1 => Ok(()),
        0 => Err(WCError::Failure),
        _ => check_error(stat)
    }
}

/// Checks if the FFI return value is greater than `0`
/// (indicating special success, e.g.: receiving a size in bytes).
/// Returns `Ok(())` for success, or `Err(CryptoError::Failure)` for values less than `0`.
///
/// # Arguments
/// * `ret` - The return value from the FFI call (i32).
///
/// # Returns
/// `CryptoResult` indicating either success or failure.
pub fn check_if_greater_than_zero(ret: i32) -> WCResult {
    match ret {
        x if x > 0 => Ok(()),
        0 => Err(WCError::Failure),
        _ => check_error(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(WCError::Success.to_string(), "Operation successful");
        assert_eq!(WCError::Failure.to_string(), "Operation failed");
        assert_eq!(WCError::Memory.to_string(), "Memory allocation error");
        assert_eq!(WCError::InvalidArgument.to_string(), "Invalid argument or state");
        assert_eq!(WCError::Buffer.to_string(), "Buffer error");
        assert_eq!(WCError::Authentication.to_string(), "Authentication failed");
        assert_eq!(WCError::RandomError.to_string(), "Random number generation error");
        assert_eq!(WCError::ASNParse.to_string(), "ASN parsing error");
        assert_eq!(WCError::KeyError.to_string(), "Key-related error");
        assert_eq!(WCError::NotAvailable.to_string(), "Feature not available");
    }

    #[test]
    fn test_check_error() {
        assert!(check_error(0).is_ok());
        assert!(matches!(check_error(-1), Err(WCError::Failure)));
        assert!(matches!(check_error(-125), Err(WCError::Memory)));
        assert!(matches!(check_error(-173), Err(WCError::InvalidArgument)));
        assert!(matches!(check_error(-132), Err(WCError::Buffer)));
        assert!(matches!(check_error(-180), Err(WCError::Authentication)));
        assert!(matches!(check_error(-199), Err(WCError::RandomError)));
        assert!(matches!(check_error(-140), Err(WCError::ASNParse)));
        assert!(matches!(check_error(-262), Err(WCError::KeyError)));
        assert!(matches!(check_error(-174), Err(WCError::NotAvailable)));
    }

    #[test]
    fn test_check_if_zero() {
        assert!(check_if_zero(0).is_ok());
        assert!(matches!(check_if_zero(-1), Err(WCError::Failure)));
        assert!(matches!(check_if_zero(-125), Err(WCError::Memory)));
    }

    #[test]
    fn test_check_if_one() {
        assert!(check_if_one(1).is_ok());
        assert!(check_if_one(0).is_err());
        assert!(matches!(check_if_one(-1), Err(WCError::Failure)));
    }

    #[test]
    fn test_check_if_greater_than_zero() {
        assert!(check_if_greater_than_zero(1).is_ok());
        assert!(check_if_greater_than_zero(0).is_err());
        assert!(matches!(check_if_greater_than_zero(-1), Err(WCError::Failure)));
    }
}
