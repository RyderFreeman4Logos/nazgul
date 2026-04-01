//! Verification logic for bLSAG signatures.

use super::engine;
use super::BLSAG;
use crate::ring::{PreparedRing, Ring};
use crate::traits::VerifyRef;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::ristretto::VartimeRistrettoPrecomputation;
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;

impl BLSAG {
    /// Verifies a signature with progress reporting via callback.
    ///
    /// Identical to [`verify`](BLSAG::verify) but fires `progress` approximately
    /// every 10% of ring members. The callback receives `(completed_members, total_members)`.
    ///
    /// # WASM adaptation
    ///
    /// See [`sign_with_rng_and_progress`](BLSAG::sign_with_rng_and_progress) for notes
    /// on wasm-bindgen closure wrappers. The chunked callback firing reduces
    /// WASM/JS boundary crossing overhead.
    #[cfg(feature = "progress-callback")]
    pub fn verify_with_progress<H: Digest<OutputSize = U64> + Clone + Default>(
        signature: &BLSAG,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<H>>,
        message: &[u8],
        mut progress: impl FnMut(usize, usize),
    ) -> bool {
        if !ring.is_decompressed() {
            return false;
        }
        let mut reconstructed_c: Scalar = signature.challenge;
        let message_hash = H::default()
            .chain_update(b"nazgul-chal-v3")
            .chain_update(message);
        let ring_members = ring.members();

        let n = ring_members.len();
        if signature.responses.len() != n {
            return false;
        }
        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash_with::<H>() {
                return false;
            }
            if d.hashed_points().len() != n {
                return false;
            }
        }

        let chunk = engine::progress_chunk_size(n);

        #[cfg(feature = "optimized-msm")]
        {
            let ki_table = VartimeRistrettoPrecomputation::new([signature.key_image]);

            for (j, ring_member) in ring_members.iter().enumerate() {
                reconstructed_c = engine::hash_ring_member_optimized::<H>(
                    &message_hash,
                    signature.responses[j],
                    reconstructed_c,
                    *ring_member,
                    &ki_table,
                    precomputed_data.map(|d| d.hashed_points()[j]),
                );

                if (j + 1) % chunk == 0 || j + 1 == n {
                    progress(j + 1, n);
                }
            }
        }

        #[cfg(not(feature = "optimized-msm"))]
        {
            for (j, ring_member) in ring_members.iter().enumerate() {
                reconstructed_c = engine::hash_ring_member_components::<H>(
                    &message_hash,
                    signature.responses[j],
                    reconstructed_c,
                    *ring_member,
                    signature.key_image,
                    precomputed_data.map(|d| d.hashed_points()[j]),
                );

                if (j + 1) % chunk == 0 || j + 1 == n {
                    progress(j + 1, n);
                }
            }
        }

        signature.challenge == reconstructed_c
    }
}

impl VerifyRef for BLSAG {
    /// To verify a `signature` you need the `message` too
    fn verify<H: Digest<OutputSize = U64> + Clone + Default>(
        signature: &BLSAG,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<H>>,
        message: &[u8],
    ) -> bool {
        if !ring.is_decompressed() {
            return false;
        }
        let mut reconstructed_c: Scalar = signature.challenge;
        let message_hash = H::default()
            .chain_update(b"nazgul-chal-v3")
            .chain_update(message);
        let ring_members = ring.members();

        // Length guards: never index untrusted inputs without validating sizes first.
        let n = ring_members.len();
        if signature.responses.len() != n {
            return false;
        }
        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash_with::<H>() {
                return false;
            }
            if d.hashed_points().len() != n {
                return false;
            }
        }

        #[cfg(feature = "optimized-msm")]
        {
            // Precompute key_image table once before the loop.
            let ki_table = VartimeRistrettoPrecomputation::new([signature.key_image]);

            for (j, ring_member) in ring_members.iter().enumerate() {
                reconstructed_c = engine::hash_ring_member_optimized::<H>(
                    &message_hash,
                    signature.responses[j],
                    reconstructed_c,
                    *ring_member,
                    &ki_table,
                    precomputed_data.map(|d| d.hashed_points()[j]),
                );
            }
        }

        #[cfg(not(feature = "optimized-msm"))]
        {
            for (j, ring_member) in ring_members.iter().enumerate() {
                reconstructed_c = engine::hash_ring_member_components::<H>(
                    &message_hash,
                    signature.responses[j],
                    reconstructed_c,
                    *ring_member,
                    signature.key_image,
                    precomputed_data.map(|d| d.hashed_points()[j]),
                );
            }
        }

        signature.challenge == reconstructed_c
    }
}
