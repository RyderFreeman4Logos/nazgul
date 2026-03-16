use crate::prelude::*;
use crate::ring::{PreparedRing, Ring, RingContext};
use crate::traits::{SignRef, VerifyRef};
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::BLSAG;

/// A wrapper around a BLSAG signature that includes ring context information.
///
/// This structure allows for two modes of operation:
/// 1.  **Compact**: Stores only the consensus hash of the ring. This assumes the verifier
///     can retrieve the full ring definition from elsewhere (e.g., a cache or DB) using the hash.
///     This is ideal for efficient transmission and storage.
/// 2.  **Archival**: Stores the full ring definition alongside the signature. This creates
///     a self-contained proof that can be verified offline or cross-system without external dependencies.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ContextualBLSAG {
    pub signature: BLSAG,
    pub context: RingContext,
}

impl ContextualBLSAG {
    /// Returns a reference to the inner BLSAG signature.
    pub fn signature(&self) -> &BLSAG {
        &self.signature
    }

    /// Returns a reference to the ring context.
    pub fn context(&self) -> &RingContext {
        &self.context
    }

    /// Signs a message and stores only the Ring's canonical hash (Compact mode).
    ///
    /// Use this when you expect the verifier to have access to the Ring definition.
    pub fn sign_compact<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
    ) -> Result<Self, SignatureError> {
        let signature = BLSAG::sign::<H, CSPRNG>(k, ring, precomputed_data, message)?;
        Ok(Self {
            signature,
            context: RingContext::Compact(ring.canonical_hash()),
        })
    }

    /// Signs a message and stores the full Ring (Archival mode).
    ///
    /// Use this when you want a self-contained signature.
    pub fn sign_archival<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
    ) -> Result<Self, SignatureError> {
        let signature = BLSAG::sign::<H, CSPRNG>(k, ring, precomputed_data, message)?;
        Ok(Self {
            signature,
            context: RingContext::Archival(ring.clone()),
        })
    }

    /// Generates a fake ContextualBLSAG with Compact context.
    ///
    /// See `BLSAG::generate_fake` for details.
    pub fn generate_fake_compact<CSPRNG: CryptoRng + RngCore + Default>(ring: &Ring) -> Self {
        let signature = BLSAG::generate_fake::<CSPRNG>(ring);
        Self {
            signature,
            context: RingContext::Compact(ring.canonical_hash()),
        }
    }

    /// Generates a fake ContextualBLSAG with Archival context.
    ///
    /// See `BLSAG::generate_fake` for details.
    pub fn generate_fake_archival<CSPRNG: CryptoRng + RngCore + Default>(ring: &Ring) -> Self {
        let signature = BLSAG::generate_fake::<CSPRNG>(ring);
        Self {
            signature,
            context: RingContext::Archival(ring.clone()),
        }
    }

    /// Verifies the signature.
    ///
    /// *   `external_ring`:
    ///     *   If `context` is `Compact`, this is **REQUIRED**. The verification will fail if `None`.
    ///         The method checks if `external_ring.canonical_hash() == stored_hash` before verifying.
    ///     *   If `context` is `Archival`, this is **OPTIONAL**.
    ///         *   If provided, it checks if `external_ring` matches the stored ring.
    ///         *   It always uses the stored (internal) ring for the mathematical verification.
    pub fn verify<H: Digest<OutputSize = U64> + Clone + Default>(
        &self,
        external_ring: Option<&Ring>,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
    ) -> bool {
        match &self.context {
            RingContext::Compact(stored_hash) => {
                let ring = match external_ring {
                    Some(r) => r,
                    None => return false,
                };

                if *stored_hash != ring.canonical_hash() {
                    return false;
                }

                // After deserialization the external ring may be in Compressed
                // state; decompress transparently so callers don't have to.
                if ring.is_decompressed() {
                    BLSAG::verify::<H>(&self.signature, ring, precomputed_data, message)
                } else {
                    match ring.clone().decompress() {
                        Ok(decompressed) => BLSAG::verify::<H>(
                            &self.signature,
                            &decompressed,
                            precomputed_data,
                            message,
                        ),
                        Err(_) => false,
                    }
                }
            }
            RingContext::Archival(internal_ring) => {
                if let Some(external) = external_ring {
                    if internal_ring.canonical_hash() != external.canonical_hash() {
                        return false;
                    }
                }

                // After deserialization the ring may be in Compressed state;
                // decompress transparently so callers don't have to.
                if internal_ring.is_decompressed() {
                    BLSAG::verify::<H>(&self.signature, internal_ring, precomputed_data, message)
                } else {
                    match internal_ring.clone().decompress() {
                        Ok(ring) => {
                            BLSAG::verify::<H>(&self.signature, &ring, precomputed_data, message)
                        }
                        Err(_) => false,
                    }
                }
            }
        }
    }
}
