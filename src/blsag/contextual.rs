use crate::prelude::*;
use crate::ring::{PreparedRing, Ring, RingContext, RingHash};
use crate::traits::VerifyRef;
use core::ops::Deref;
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
    context: RingContext,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    compact_selected_hash: Option<RingHash>,
}

/// Public construction/deconstruction parts for [`ContextualBLSAG`].
#[derive(Clone, Debug)]
pub struct ContextualBlsagParts {
    pub signature: BLSAG,
    pub context: RingContext,
    pub compact_selected_hash: Option<RingHash>,
}

/// A view over a [`ContextualBLSAG`] ring context that preserves compact-mode
/// hash-suite metadata when it is available.
#[derive(Clone, Copy, Debug)]
pub struct ContextualRingContext<'a> {
    raw: &'a RingContext,
    compact_selected_hash: Option<RingHash>,
}

impl<'a> ContextualRingContext<'a> {
    /// Returns the backwards-compatible default lookup hash.
    pub fn canonical_hash(&self) -> RingHash {
        self.raw.canonical_hash()
    }

    /// Returns the canonical hash associated with this context using the
    /// caller-chosen digest `H`.
    ///
    /// Compact contextual signatures keep the legacy lookup hash inside
    /// [`RingContext`] for backwards compatibility and store the suite-aware
    /// compact hash as side metadata. Prefer that metadata when it exists so
    /// callers observe the correct hash for the selected digest suite.
    pub fn canonical_hash_with<H: Digest<OutputSize = U64> + Clone + Default>(&self) -> RingHash {
        self.compact_selected_hash
            .unwrap_or_else(|| self.raw.canonical_hash_with::<H>())
    }

    /// Returns the compact-mode hash metadata for the selected digest suite, if present.
    pub fn selected_compact_hash(&self) -> Option<RingHash> {
        self.compact_selected_hash
    }
}

impl<'a> Deref for ContextualRingContext<'a> {
    type Target = RingContext;

    fn deref(&self) -> &Self::Target {
        self.raw
    }
}

impl ContextualBLSAG {
    /// Constructs a contextual signature from explicit parts.
    pub fn from_parts(parts: ContextualBlsagParts) -> Self {
        Self {
            signature: parts.signature,
            context: parts.context,
            compact_selected_hash: parts.compact_selected_hash,
        }
    }

    /// Deconstructs this contextual signature into explicit parts.
    pub fn into_parts(self) -> ContextualBlsagParts {
        ContextualBlsagParts {
            signature: self.signature,
            context: self.context,
            compact_selected_hash: self.compact_selected_hash,
        }
    }

    /// Returns a reference to the inner BLSAG signature.
    pub fn signature(&self) -> &BLSAG {
        &self.signature
    }

    /// Returns the raw stored ring context.
    ///
    /// Compact contextual signatures store the backwards-compatible lookup hash
    /// here. Use [`context`](Self::context) when you need suite-aware hash
    /// semantics for compact signatures.
    pub fn context_ref(&self) -> &RingContext {
        &self.context
    }

    /// Returns a suite-aware view over the ring context.
    pub fn context(&self) -> ContextualRingContext<'_> {
        ContextualRingContext {
            raw: &self.context,
            compact_selected_hash: self.compact_selected_hash,
        }
    }

    /// Signs a message in Compact mode using an externally provided RNG.
    ///
    /// Stores the Ring's default canonical lookup hash plus compact metadata
    /// for the selected digest suite. Use this when you expect the verifier to
    /// have access to the Ring definition. The BLSAG mathematics follow `H`
    /// while the compact lookup key stays on the backwards-compatible default
    /// digest. Accepts an external `rng` source for embedded/hardware TRNG
    /// support.
    pub fn sign_compact_with_rng<
        H: Digest<OutputSize = U64> + Clone + Default,
        R: CryptoRng + RngCore,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<H>>,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self, SignatureError> {
        let signature = BLSAG::sign_with_rng::<H, R>(k, ring, precomputed_data, message, rng)?;
        let canonical_hash = ring.canonical_hash();
        let selected_hash = ring.canonical_hash_with::<H>();
        Ok(Self {
            signature,
            context: RingContext::Compact(canonical_hash),
            compact_selected_hash: (selected_hash != canonical_hash).then_some(selected_hash),
        })
    }

    /// Signs a message and stores only the Ring's canonical hash (Compact mode).
    ///
    /// Convenience wrapper that creates a CSPRNG via `Default` and delegates to
    /// [`sign_compact_with_rng`](Self::sign_compact_with_rng).
    pub fn sign_compact<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<H>>,
        message: &[u8],
    ) -> Result<Self, SignatureError> {
        let mut csprng = CSPRNG::default();
        Self::sign_compact_with_rng::<H, CSPRNG>(k, ring, precomputed_data, message, &mut csprng)
    }

    /// Signs a message in Archival mode using an externally provided RNG.
    ///
    /// Stores the full Ring alongside the signature. Use this when you want a
    /// self-contained signature. Accepts an external `rng` source for
    /// embedded/hardware TRNG support.
    pub fn sign_archival_with_rng<
        H: Digest<OutputSize = U64> + Clone + Default,
        R: CryptoRng + RngCore,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<H>>,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self, SignatureError> {
        let signature = BLSAG::sign_with_rng::<H, R>(k, ring, precomputed_data, message, rng)?;
        Ok(Self {
            signature,
            context: RingContext::Archival(ring.clone()),
            compact_selected_hash: None,
        })
    }

    /// Signs a message and stores the full Ring (Archival mode).
    ///
    /// Convenience wrapper that creates a CSPRNG via `Default` and delegates to
    /// [`sign_archival_with_rng`](Self::sign_archival_with_rng).
    pub fn sign_archival<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<H>>,
        message: &[u8],
    ) -> Result<Self, SignatureError> {
        let mut csprng = CSPRNG::default();
        Self::sign_archival_with_rng::<H, CSPRNG>(k, ring, precomputed_data, message, &mut csprng)
    }

    /// Generates a fake ContextualBLSAG with Compact context using an externally provided RNG.
    ///
    /// See `BLSAG::generate_fake_with_rng` for details.
    pub fn generate_fake_compact_with_rng<R: CryptoRng + RngCore>(
        ring: &Ring,
        rng: &mut R,
    ) -> Self {
        let signature = BLSAG::generate_fake_with_rng(ring, rng);
        Self {
            signature,
            context: RingContext::Compact(ring.canonical_hash()),
            compact_selected_hash: None,
        }
    }

    /// Generates a fake ContextualBLSAG with Compact context.
    ///
    /// Convenience wrapper that creates a CSPRNG via `Default` and delegates to
    /// [`generate_fake_compact_with_rng`](Self::generate_fake_compact_with_rng).
    pub fn generate_fake_compact<CSPRNG: CryptoRng + RngCore + Default>(ring: &Ring) -> Self {
        let mut csprng = CSPRNG::default();
        Self::generate_fake_compact_with_rng(ring, &mut csprng)
    }

    /// Generates a fake ContextualBLSAG with Archival context using an externally provided RNG.
    ///
    /// See `BLSAG::generate_fake_with_rng` for details.
    pub fn generate_fake_archival_with_rng<R: CryptoRng + RngCore>(
        ring: &Ring,
        rng: &mut R,
    ) -> Self {
        let signature = BLSAG::generate_fake_with_rng(ring, rng);
        Self {
            signature,
            context: RingContext::Archival(ring.clone()),
            compact_selected_hash: None,
        }
    }

    /// Generates a fake ContextualBLSAG with Archival context.
    ///
    /// Convenience wrapper that creates a CSPRNG via `Default` and delegates to
    /// [`generate_fake_archival_with_rng`](Self::generate_fake_archival_with_rng).
    pub fn generate_fake_archival<CSPRNG: CryptoRng + RngCore + Default>(ring: &Ring) -> Self {
        let mut csprng = CSPRNG::default();
        Self::generate_fake_archival_with_rng(ring, &mut csprng)
    }

    /// Verifies the signature.
    ///
    /// *   `external_ring`:
    ///     *   If `context` is `Compact`, this is **REQUIRED**. The verification will fail if `None`.
    ///         The method checks if `external_ring.canonical_hash() == stored_hash`
    ///         before verifying.
    ///     *   If `context` is `Archival`, this is **OPTIONAL**.
    ///         *   If provided, it checks if `external_ring` matches the stored ring.
    ///         *   It always uses the stored (internal) ring for the mathematical verification.
    pub fn verify<H: Digest<OutputSize = U64> + Clone + Default>(
        &self,
        external_ring: Option<&Ring>,
        precomputed_data: Option<&PreparedRing<H>>,
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
                if let Some(selected_hash) = self.compact_selected_hash {
                    if selected_hash != ring.canonical_hash_with::<H>() {
                        return false;
                    }
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
                    if internal_ring.canonical_hash_with::<H>()
                        != external.canonical_hash_with::<H>()
                    {
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
