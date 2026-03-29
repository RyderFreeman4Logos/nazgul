//! Memory strategy selection for bLSAG signing and verification.
//!
//! This module provides [`MemoryStrategy`], a semantic enum that documents
//! the two approaches available for ring signature operations:
//!
//! - **One-shot** (default): load the entire ring into memory for maximum throughput.
//! - **Streaming**: process ring members one at a time with O(1) memory overhead,
//!   suitable for embedded or memory-constrained targets.
//!
//! # Choosing a strategy
//!
//! | Strategy | Memory | Throughput | Use case |
//! |---|---|---|---|
//! | [`MaxPerformance`](MemoryStrategy::MaxPerformance) | O(n) | Highest | Servers, desktops |
//! | [`MinMemory`](MemoryStrategy::MinMemory) | O(1) | Lower | Embedded, hardware keys |
//!
//! The standard [`BLSAG`](super::BLSAG) one-shot `sign` / `verify` functions implement
//! `MaxPerformance`, while [`StreamingBlsagSigner`](super::StreamingBlsagSigner) /
//! [`StreamingBlsagVerifier`](super::StreamingBlsagVerifier) implement `MinMemory`.

/// Describes how ring signature operations manage memory.
///
/// This is a **documentation-level** enum that makes the memory/performance
/// trade-off explicit in API surface.  It does not perform dispatch on its own;
/// callers choose the corresponding implementation directly.
///
/// # Examples
///
/// ```
/// use nazgul::blsag::MemoryStrategy;
///
/// let strategy = MemoryStrategy::default();
/// assert!(matches!(strategy, MemoryStrategy::MaxPerformance));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryStrategy {
    /// Load the entire ring into memory and compute in one shot.
    ///
    /// This is the traditional approach used by [`BLSAG`](super::BLSAG) one-shot
    /// `sign` / `verify` (via the `SignRef` and `VerifyRef` traits).
    /// It requires O(n) memory where n is the ring size, but achieves the
    /// highest throughput thanks to batch scalar-point operations.
    MaxPerformance,

    /// Process ring members one at a time with O(1) memory overhead.
    ///
    /// Implemented by [`StreamingBlsagSigner`](super::StreamingBlsagSigner) and
    /// [`StreamingBlsagVerifier`](super::StreamingBlsagVerifier).
    /// Ideal for hardware security keys, embedded targets (e.g. RP2350),
    /// and any environment where RAM is scarce.
    MinMemory,
}

impl Default for MemoryStrategy {
    /// Defaults to [`MaxPerformance`](MemoryStrategy::MaxPerformance) for
    /// backward compatibility with the one-shot API.
    fn default() -> Self {
        Self::MaxPerformance
    }
}

impl core::fmt::Display for MemoryStrategy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MaxPerformance => f.write_str("MaxPerformance (one-shot, O(n) memory)"),
            Self::MinMemory => f.write_str("MinMemory (streaming, O(1) memory)"),
        }
    }
}
