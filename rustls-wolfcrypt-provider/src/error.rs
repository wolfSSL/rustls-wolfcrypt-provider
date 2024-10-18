/// Custom error type for cryptographic operations, only indicating failure.
/// Errors are generalized to avoid the leaking of information.
#[derive(Debug)]
pub enum WCError {
    Failure,
}

/// A result type for cryptographic operations.
pub type WCResult = Result<(), WCError>;

/// Checks if the FFI return value is `0` (indicating success).
/// Returns `Ok(())` if success, otherwise returns `Err(CryptoError::Failure)`
/// if the value is not `0`.
///
/// # Arguments
/// * `stat` - The return value from the FFI call (i32).
///
/// # Returns
/// `CryptoResult` indicating either success or failure.
pub fn check_if_zero(ret: i32) -> WCResult {
    if ret == 0 {
        Ok(())
    } else {
        Err(WCError::Failure)
    }
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
    if stat == 1 {
        Ok(())
    } else {
        Err(WCError::Failure)
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
    if ret > 0 {
        Ok(())
    } else {
        Err(WCError::Failure)
    }
}
