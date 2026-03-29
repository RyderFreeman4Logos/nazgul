//! BLAKE3-based 512-bit hash wrapper for use with Nazgul ring signatures.
//!
//! BLAKE3 has a 256-bit internal state (128-bit collision resistance), which
//! aligns with Ristretto255's ~126-bit discrete-log security level. The 64-byte
//! output is obtained via BLAKE3's extensible output function (XOF), not by
//! running a separate 512-bit hash — there is no additional collision resistance
//! beyond 128 bits.
//!
//! # When to use
//!
//! BLAKE3 offers excellent performance, especially on platforms with AVX2/AVX-512.
//! Use `Blake3_512` when throughput matters and the 128-bit collision resistance
//! floor is acceptable for your threat model (it matches Ristretto255's security).

use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;
use digest::{FixedOutput, HashMarker, OutputSizeUser, Reset, Update};

/// A BLAKE3-based hash producing 64-byte output via XOF mode.
///
/// Implements `Digest<OutputSize = U64>` so it can be used with all Nazgul
/// signature schemes as a drop-in replacement for SHA-512 or BLAKE2b-512.
///
/// # Security margin
///
/// BLAKE3 provides 128-bit collision resistance regardless of output length.
/// This is sufficient for Ristretto255 (~126-bit DLP security) but is lower
/// than SHA-512's 256-bit collision resistance. Choose based on your security
/// requirements.
#[derive(Clone)]
pub struct Blake3_512 {
    hasher: blake3::Hasher,
}

impl Default for Blake3_512 {
    fn default() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl Update for Blake3_512 {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

impl OutputSizeUser for Blake3_512 {
    type OutputSize = U64;
}

impl FixedOutput for Blake3_512 {
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let mut reader = self.hasher.finalize_xof();
        reader.fill(out.as_mut_slice());
    }
}

impl Reset for Blake3_512 {
    fn reset(&mut self) {
        self.hasher.reset();
    }
}

impl HashMarker for Blake3_512 {}
