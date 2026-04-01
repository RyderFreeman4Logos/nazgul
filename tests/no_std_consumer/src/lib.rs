#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use nazgul::blsag::{streaming::StreamingBlsagSigner, BLSAG, ContextualBLSAG};
use nazgul::ring::Ring;
use rand_core::{CryptoRng, RngCore};
use sha3::Sha3_512;

#[derive(Default)]
pub struct ZeroRng;

impl CryptoRng for ZeroRng {}

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = 0;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub fn build_ring(points: Vec<RistrettoPoint>) -> Ring {
    Ring::new(points)
}

pub fn build_streaming_signer() -> StreamingBlsagSigner<Sha3_512, ZeroRng> {
    StreamingBlsagSigner::new(ZeroRng)
}

pub fn canonical_hash_with<H: Digest<OutputSize = digest::generic_array::typenum::U64> + Clone + Default>(
    ring: &Ring,
) -> [u8; 32] {
    ring.canonical_hash_with::<H>().0
}

pub fn make_fake_signature(ring: &Ring) -> BLSAG {
    let mut rng = ZeroRng;
    BLSAG::generate_fake_with_rng(ring, &mut rng)
}

pub fn make_fake_contextual_signature(ring: &Ring) -> ContextualBLSAG {
    ContextualBLSAG::generate_fake_compact::<ZeroRng>(ring)
}

pub fn compressed_identity() -> CompressedRistretto {
    (Scalar::ONE * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT).compress()
}
