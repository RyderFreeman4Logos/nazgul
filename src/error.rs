//! Module for defining library-wide error types.

/// Represents the possible errors that can occur during signature operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum SignatureError {
    /// Occurs when the signer's public key is not found within the provided ring.
    SignerNotFound,
    /// Provided precomputed ring data is not compatible with the ring in use
    /// (e.g., length mismatch).
    InvalidPrecomputedData,
    /// The precomputed ring data was computed for a different ring than the one
    /// being used for signing or verification.
    RingMismatch,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignatureError::SignerNotFound => {
                write!(f, "The signer's public key was not found in the ring")
            }
            SignatureError::InvalidPrecomputedData => {
                write!(f, "Invalid precomputed ring data for the given ring")
            }
            SignatureError::RingMismatch => {
                write!(f, "Precomputed ring data was computed for a different ring")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignatureError {}
