//! Back's Linkable Spontaneous Anonymous Group (bLSAG) signatures.
//!
//! This module implements bLSAG, an enhanced version of the Linkable Spontaneous Anonymous Group
//! (LSAG) signature scheme where linkability is independent of the ring's decoy members.
//! It provides signer ambiguity, unforgeability, and linkability.
//!
//! Signer ambiguity ensures that a signature can be verified without revealing which member of
//! the ring created it. Unforgeability prevents an unauthorized party from creating a valid
//! signature on behalf of the ring. Linkability allows for determining if two signatures were
//! produced by the same signer, without revealing the signer's identity.
//!
//! # Example
//!
//! ```
//! # fn main() {
//! use nazgul::blsag::BLSAG;
//! use nazgul::keypair::KeyPair;
//! use nazgul::ring::Ring;
//! use nazgul::traits::{SignRef, VerifyRef};
//! use rand::rngs::OsRng;
//! use sha2::Sha512;
//!
//! let mut csprng = OsRng;
//!
//! // 1. Key Generation
//! // The signer generates a keypair.
//! let signer_keypair = KeyPair::generate(&mut csprng);
//!
//! // 2. Ring Formation
//! // A ring is formed with the signer's public key and several decoy public keys.
//! let num_decoys = 10;
//! let mut public_keys: Vec<_> = (0..num_decoys)
//!     .map(|_| *KeyPair::generate(&mut csprng).public())
//!     .collect();
//! public_keys.push(*signer_keypair.public());
//!
//! let ring = Ring::new(public_keys);
//!
//! // 3. Signing
//! // The signer creates a signature for a message using their private key and the ring.
//! let message = b"The traceability is a secret to everybody.";
//! let signature = BLSAG::sign::<Sha512, OsRng>(
//!     *signer_keypair.secret().unwrap(),
//!     &ring,
//!     None, // No precomputed data
//!     message,
//! ).unwrap();
//!
//! // 4. Verification
//! // A verifier checks the signature against the message and the public ring.
//! // They do not need to know who the signer is.
//! let is_valid = BLSAG::verify::<Sha512>(&signature, &ring, None, message);
//!
//! assert!(is_valid);
//! # }
//! ```

mod engine;

use crate::prelude::*;
use crate::ring::{PreparedRing, Ring, RingContext, RingHash};
use crate::traits::{KeyImageGen, LinkRef, SignRef, VerifyRef};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::ristretto::VartimeRistrettoPrecomputation;
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde-derive")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Response vector type: uses `SmallVec<[Scalar; 16]>` when the `smallvec-responses`
/// feature is enabled (inline storage for rings up to 16 members), otherwise
/// falls back to `Vec<Scalar>`.
#[cfg(feature = "smallvec-responses")]
pub(crate) type ResponseVec = smallvec::SmallVec<[Scalar; 16]>;

#[cfg(not(feature = "smallvec-responses"))]
pub(crate) type ResponseVec = Vec<Scalar>;

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

/// Message-independent precomputation for BLSAG signing.
///
/// Captures all nonce-derived values (`alpha`, `alpha*G`, `alpha*H_p`) and random
/// responses so that the actual signing step only needs the message. The struct is
/// move-consumed by [`BLSAG::sign_precomputed`] and the secret nonce `alpha` is
/// zeroized on drop.
///
/// # Security properties
///
/// * **Not `Clone`/`Copy`**: prevents nonce reuse.
/// * **Not `Debug`/`Serialize`/`Deserialize`**: prevents accidental leakage.
/// * **`ZeroizeOnDrop`**: secret scalars `alpha` and `secret_key` are erased
///   from memory when this value is dropped.
/// * **Ring binding**: stores a `RingHash` that is checked against the ring
///   supplied to `sign_precomputed` to prevent ring-switching attacks.
///
/// # Compile-time security constraints
///
/// `SigningPrecomputation` intentionally does **not** implement `Clone`, `Copy`,
/// or `Debug`. These doc-tests verify that as a compile-time guarantee.
///
/// ## Not `Clone`
///
/// Cloning would allow nonce reuse, which breaks the security of the scheme.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// let _copy = precomp.clone(); // ERROR: Clone is not implemented
/// ```
///
/// ## Not `Copy`
///
/// Copy semantics would defeat move-consumption and allow nonce reuse.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// fn takes_by_value(_p: SigningPrecomputation) {}
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// takes_by_value(precomp);
/// takes_by_value(precomp); // ERROR: use of moved value
/// ```
///
/// ## Not `Debug`
///
/// Debug formatting would risk leaking secret nonce material.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// println!("{:?}", precomp); // ERROR: Debug is not implemented
/// ```
///
/// ## Not `Serialize`
///
/// Serialization would allow persisting secret nonce material, enabling nonce
/// reuse across sessions.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// fn requires_serialize<T: serde::Serialize>(_v: &T) {}
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// requires_serialize(&precomp); // ERROR: Serialize is not implemented
/// ```
///
/// ## Not `Deserialize`
///
/// Deserialization would allow reconstructing secret nonce material from
/// untrusted input, enabling nonce reuse.
///
/// ```compile_fail
/// use nazgul::blsag::SigningPrecomputation;
///
/// fn requires_deserialize<'de, T: serde::Deserialize<'de>>() {}
///
/// requires_deserialize::<SigningPrecomputation>(); // ERROR: Deserialize is not implemented
/// ```
///
/// ## Move-consumed by `sign_precomputed`
///
/// After calling `sign_precomputed`, the precomputation is consumed and cannot
/// be reused, preventing nonce reuse at the type-system level.
///
/// ```compile_fail
/// use nazgul::blsag::BLSAG;
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// let _sig1 = BLSAG::sign_precomputed::<Sha512>(precomp, &ring, None, b"msg1");
/// let _sig2 = BLSAG::sign_precomputed::<Sha512>(precomp, &ring, None, b"msg2"); // ERROR: use of moved value
/// ```
pub struct SigningPrecomputation {
    /// Secret nonce (zeroized on drop via `SecretScalar`).
    alpha: SecretScalar,
    /// `alpha * G` — the nonce commitment on the base point.
    alpha_g: RistrettoPoint,
    /// `alpha * H_p(signer_pubkey)` — the nonce commitment on the hash-to-point.
    alpha_hp: RistrettoPoint,
    /// Canonical hash of the ring used during precomputation.
    ring_hash: RingHash,
    /// Position of the signer's public key in the sorted ring.
    signer_index: usize,
    /// Key image (`k * H_p(K)`).
    key_image: RistrettoPoint,
    /// Pre-generated random responses for every ring member.
    responses: ResponseVec,
    /// The signer's secret key (zeroized on drop via `SecretScalar`).
    secret_key: SecretScalar,
}

/// Wrapper around `Scalar` that zeroizes on drop.
///
/// `curve25519-dalek::Scalar` implements `Zeroize` when the `zeroize` feature
/// is enabled, so we delegate directly. The wrapper provides `Drop`-based
/// automatic zeroization without requiring the parent struct to implement
/// `Drop` (which would prevent field moves).
struct SecretScalar(Scalar);

impl Zeroize for SecretScalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretScalar {}

/// Back's Linkable Spontaneous Anonymous Group (bLSAG) signatures
/// > This an enhanced version of the LSAG algorithm where linkability
/// > is independent of the ring's decoy members.
///
/// Please read tests at the bottom of the source code for this module for examples on how to use
/// it
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct BLSAG {
    challenge: Scalar,
    responses: ResponseVec,
    key_image: RistrettoPoint,
}

impl BLSAG {
    /// Returns a reference to the initial challenge scalar (`c_0`).
    pub fn challenge(&self) -> &Scalar {
        &self.challenge
    }

    /// Returns the response scalars as a slice.
    pub fn responses(&self) -> &[Scalar] {
        &self.responses
    }

    /// Returns a reference to the key image point.
    pub fn key_image(&self) -> &RistrettoPoint {
        &self.key_image
    }

    /// Constructs a `BLSAG` from its raw components.
    ///
    /// Intended for testing (e.g., tamper-rejection tests) where individual
    /// fields need to be modified independently.
    pub fn from_parts(
        challenge: Scalar,
        responses: impl Into<ResponseVec>,
        key_image: RistrettoPoint,
    ) -> Self {
        let responses = responses.into();
        Self {
            challenge,
            responses,
            key_image,
        }
    }

    /// Signs a message using an externally provided RNG.
    ///
    /// This is the core signing implementation. It accepts `k` (your private key), `ring`
    /// (the public keys of all ring members including yourself), optional `precomputed_data`,
    /// the `message` to sign, and an external `rng` source.
    ///
    /// Providing an external RNG enables deterministic signature generation when used with
    /// a seeded RNG, which is useful for testing and reproducibility.
    pub fn sign_with_rng<H: Digest<OutputSize = U64> + Clone + Default, R: CryptoRng + RngCore>(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
        rng: &mut R,
    ) -> Result<BLSAG, SignatureError> {
        Self::sign_inner::<H, R>(k, ring, precomputed_data, message, rng, None)
    }

    /// Shared signing implementation for both `sign_with_rng` and
    /// `sign_with_rng_and_progress`. When `progress` is `Some`, the callback
    /// fires approximately every 10% of ring members processed.
    fn sign_inner<H: Digest<OutputSize = U64> + Clone + Default, R: CryptoRng + RngCore>(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
        rng: &mut R,
        mut progress: Option<&mut dyn FnMut(usize, usize)>,
    ) -> Result<BLSAG, SignatureError> {
        if !ring.is_decompressed() {
            return Err(SignatureError::CompressedRing);
        }
        let ring_members = ring.members();

        // Prover's public key
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let secret_index = ring_members
            .binary_search_by_key(&k_point.compress().to_bytes(), |p| p.compress().to_bytes())
            .map_err(|_| SignatureError::SignerNotFound)?;

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k);

        let n = ring_members.len();

        // If precomputed data is provided, verify it belongs to this ring.
        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash() {
                return Err(SignatureError::RingMismatch);
            }
            if d.hashed_points().len() != n {
                return Err(SignatureError::InvalidPrecomputedData);
            }
        }

        let a = SecretScalar(Scalar::random(rng));

        let mut rs: ResponseVec = (0..n).map(|_| Scalar::random(rng)).collect();

        // Hash of message is shared by all challenges H_n(m, ....)
        let mut message_hash = H::default();
        message_hash.update(message);

        let mut h = message_hash.clone();
        h.update(
            (a.0 * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        h.update(
            (a.0 * RistrettoPoint::from_hash(
                H::default().chain_update(k_point.compress().as_bytes()),
            ))
            .compress()
            .as_bytes(),
        );

        let c_plus_1 = Scalar::from_hash(h);

        let mut current_challenge = c_plus_1;
        let mut c_0 = if secret_index == n - 1 {
            c_plus_1
        } else {
            Scalar::ZERO
        };

        // We iterate starting from the member *after* the signer (secret_index + 1).
        // We wrap around using cycle() and stop after processing n - 1 members.
        // The last member processed will be the one *before* the signer (secret_index - 1).
        let loop_len = n - 1;
        let chunk = engine::progress_chunk_size(loop_len);

        #[cfg(feature = "optimized-msm")]
        {
            let ki_table = VartimeRistrettoPrecomputation::new([key_image]);

            for (step, (i, ring_member)) in ring_members
                .iter()
                .enumerate()
                .cycle()
                .skip(secret_index + 1)
                .take(loop_len)
                .enumerate()
            {
                let next_challenge = engine::hash_ring_member_optimized::<H>(
                    &message_hash,
                    rs[i],
                    current_challenge,
                    *ring_member,
                    &ki_table,
                    precomputed_data.map(|d| d.hashed_points()[i]),
                );

                current_challenge = next_challenge;

                if i == n - 1 {
                    c_0 = current_challenge;
                }

                if let Some(ref mut cb) = progress {
                    if (step + 1) % chunk == 0 || step + 1 == loop_len {
                        cb(step + 1, loop_len);
                    }
                }
            }
        }

        #[cfg(not(feature = "optimized-msm"))]
        {
            for (step, (i, ring_member)) in ring_members
                .iter()
                .enumerate()
                .cycle()
                .skip(secret_index + 1)
                .take(loop_len)
                .enumerate()
            {
                let next_challenge = engine::hash_ring_member_components::<H>(
                    &message_hash,
                    rs[i],
                    current_challenge,
                    *ring_member,
                    key_image,
                    precomputed_data.map(|d| d.hashed_points()[i]),
                );

                current_challenge = next_challenge;

                if i == n - 1 {
                    c_0 = current_challenge;
                }

                if let Some(ref mut cb) = progress {
                    if (step + 1) % chunk == 0 || step + 1 == loop_len {
                        cb(step + 1, loop_len);
                    }
                }
            }
        }

        // After the loop, `current_challenge` holds the challenge for the signer (c_{secret_index}).
        rs[secret_index] = a.0 - (current_challenge * k);

        Ok(BLSAG {
            challenge: c_0,
            responses: rs,
            key_image,
        })
    }

    /// Creates a message-independent precomputation for later use with
    /// [`sign_precomputed`](BLSAG::sign_precomputed).
    ///
    /// This extracts the nonce generation, nonce commitments, and random
    /// response vectors out of the signing hot path. The returned
    /// [`SigningPrecomputation`] is bound to this specific ring via its
    /// canonical hash and must be consumed (moved) into `sign_precomputed`.
    pub fn precompute_signing<
        H: Digest<OutputSize = U64> + Clone + Default,
        R: CryptoRng + RngCore,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        rng: &mut R,
    ) -> Result<SigningPrecomputation, SignatureError> {
        if !ring.is_decompressed() {
            return Err(SignatureError::CompressedRing);
        }
        let ring_members = ring.members();
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let secret_index = ring_members
            .binary_search_by_key(&k_point.compress().to_bytes(), |p| p.compress().to_bytes())
            .map_err(|_| SignatureError::SignerNotFound)?;

        let n = ring_members.len();

        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash() {
                return Err(SignatureError::RingMismatch);
            }
            if d.hashed_points().len() != n {
                return Err(SignatureError::InvalidPrecomputedData);
            }
        }

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k);

        let alpha = Scalar::random(rng);
        let alpha_g = alpha * constants::RISTRETTO_BASEPOINT_POINT;

        let hp_signer = precomputed_data
            .map(|d| d.hashed_points()[secret_index])
            .unwrap_or_else(|| {
                RistrettoPoint::from_hash(H::default().chain_update(k_point.compress().as_bytes()))
            });
        let alpha_hp = alpha * hp_signer;

        let responses: ResponseVec = (0..n).map(|_| Scalar::random(rng)).collect();

        Ok(SigningPrecomputation {
            alpha: SecretScalar(alpha),
            alpha_g,
            alpha_hp,
            ring_hash: ring.canonical_hash(),
            signer_index: secret_index,
            key_image,
            responses,
            secret_key: SecretScalar(k),
        })
    }

    /// Completes a BLSAG signature using a previously created
    /// [`SigningPrecomputation`].
    ///
    /// The precomputation is consumed (moved) so the nonce cannot be reused.
    /// Returns [`SignatureError::RingMismatch`] if the ring's canonical hash
    /// differs from the one recorded during precomputation.
    pub fn sign_precomputed<H: Digest<OutputSize = U64> + Clone + Default>(
        precomp: SigningPrecomputation,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
    ) -> Result<BLSAG, SignatureError> {
        if !ring.is_decompressed() {
            return Err(SignatureError::CompressedRing);
        }
        if precomp.ring_hash != ring.canonical_hash() {
            return Err(SignatureError::RingMismatch);
        }

        let ring_members = ring.members();
        let n = ring_members.len();

        if precomp.responses.len() != n {
            return Err(SignatureError::RingMismatch);
        }

        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash() {
                return Err(SignatureError::RingMismatch);
            }
            if d.hashed_points().len() != n {
                return Err(SignatureError::InvalidPrecomputedData);
            }
        }

        // Destructure the precomputation to consume it (SecretScalar fields
        // are dropped at the end of this scope, zeroizing secrets).
        let SigningPrecomputation {
            alpha,
            alpha_g,
            alpha_hp,
            ring_hash: _,
            signer_index: secret_index,
            key_image,
            responses,
            secret_key,
        } = precomp;
        let mut rs = responses;

        // Build the message hash prefix shared by all challenge computations.
        let mut message_hash = H::default();
        message_hash.update(message);

        // Compute c_{secret_index + 1} from the precomputed alpha commitments.
        let mut h = message_hash.clone();
        h.update(alpha_g.compress().as_bytes());
        h.update(alpha_hp.compress().as_bytes());

        let c_plus_1 = Scalar::from_hash(h);

        let mut current_challenge = c_plus_1;
        let mut c_0 = if secret_index == n - 1 {
            c_plus_1
        } else {
            Scalar::ZERO
        };

        #[cfg(feature = "optimized-msm")]
        {
            let ki_table = VartimeRistrettoPrecomputation::new([key_image]);

            for (i, ring_member) in ring_members
                .iter()
                .enumerate()
                .cycle()
                .skip(secret_index + 1)
                .take(n - 1)
            {
                let next_challenge = engine::hash_ring_member_optimized::<H>(
                    &message_hash,
                    rs[i],
                    current_challenge,
                    *ring_member,
                    &ki_table,
                    precomputed_data.map(|d| d.hashed_points()[i]),
                );

                current_challenge = next_challenge;

                if i == n - 1 {
                    c_0 = current_challenge;
                }
            }
        }

        #[cfg(not(feature = "optimized-msm"))]
        {
            for (i, ring_member) in ring_members
                .iter()
                .enumerate()
                .cycle()
                .skip(secret_index + 1)
                .take(n - 1)
            {
                let next_challenge = engine::hash_ring_member_components::<H>(
                    &message_hash,
                    rs[i],
                    current_challenge,
                    *ring_member,
                    key_image,
                    precomputed_data.map(|d| d.hashed_points()[i]),
                );

                current_challenge = next_challenge;

                if i == n - 1 {
                    c_0 = current_challenge;
                }
            }
        }

        // Close the ring for the signer's slot.
        rs[secret_index] = alpha.0 - (current_challenge * secret_key.0);

        Ok(BLSAG {
            challenge: c_0,
            responses: rs,
            key_image,
        })
    }

    /// Signs a message with progress reporting via callback.
    ///
    /// Identical to [`sign_with_rng`](BLSAG::sign_with_rng) but fires `progress`
    /// approximately every 10% of ring members (minimum every member for small rings).
    /// The callback receives `(completed_members, total_members)`.
    ///
    /// # WASM adaptation
    ///
    /// For wasm-bindgen targets, wrap the Rust closure in a `wasm_bindgen::closure::Closure`
    /// and pass it from JS. Keep in mind that each call crosses the JS/WASM boundary,
    /// so the chunked firing (not per-iteration) is intentional for performance.
    #[cfg(feature = "progress-callback")]
    pub fn sign_with_rng_and_progress<
        H: Digest<OutputSize = U64> + Clone + Default,
        R: CryptoRng + RngCore,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
        rng: &mut R,
        mut progress: impl FnMut(usize, usize),
    ) -> Result<BLSAG, SignatureError> {
        Self::sign_inner::<H, R>(k, ring, precomputed_data, message, rng, Some(&mut progress))
    }

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
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
        mut progress: impl FnMut(usize, usize),
    ) -> bool {
        if !ring.is_decompressed() {
            return false;
        }
        let mut reconstructed_c: Scalar = signature.challenge;
        let message_hash = H::default().chain_update(message);
        let ring_members = ring.members();

        let n = ring_members.len();
        if signature.responses.len() != n {
            return false;
        }
        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash() {
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

    /// Generates a fake BLSAG signature for testing purposes.
    ///
    /// The generated signature is structurally valid (contains valid points and scalars)
    /// but is cryptographically invalid. Use this to test robustness against DOS attacks
    /// or other scenarios where large numbers of invalid signatures are needed efficiently.
    ///
    /// # Performance
    /// This method performs `n + 1` RNG calls (where `n` is ring size) and 1 RistrettoPoint generation.
    /// It avoids expensive multiscalar multiplications required for real signing.
    pub fn generate_fake<CSPRNG: CryptoRng + RngCore + Default>(ring: &Ring) -> Self {
        let mut csprng = CSPRNG::default();
        let n = ring.len();

        let challenge = Scalar::random(&mut csprng);
        let responses: ResponseVec = (0..n).map(|_| Scalar::random(&mut csprng)).collect();
        let key_image = RistrettoPoint::random(&mut csprng);

        BLSAG {
            challenge,
            responses,
            key_image,
        }
    }
}

impl KeyImageGen<Scalar, RistrettoPoint> for BLSAG {
    /// Some signature schemes require the key images to be signed as well.
    /// Use this method to generate them
    fn generate_key_image<H: Digest<OutputSize = U64> + Clone + Default>(
        k: Scalar,
    ) -> RistrettoPoint {
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let key_image: RistrettoPoint =
            k * RistrettoPoint::from_hash(H::default().chain_update(k_point.compress().as_bytes()));

        key_image
    }
}

impl SignRef<Scalar> for BLSAG {
    /// To sign you need `k` your private key, and `ring` which is the public keys of everyone
    /// except you. You are signing the `message`
    fn sign<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
    ) -> Result<BLSAG, SignatureError> {
        let mut csprng = CSPRNG::default();
        BLSAG::sign_with_rng::<H, CSPRNG>(k, ring, precomputed_data, message, &mut csprng)
    }
}

impl VerifyRef for BLSAG {
    /// To verify a `signature` you need the `message` too
    fn verify<H: Digest<OutputSize = U64> + Clone + Default>(
        signature: &BLSAG,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing>,
        message: &[u8],
    ) -> bool {
        if !ring.is_decompressed() {
            return false;
        }
        let mut reconstructed_c: Scalar = signature.challenge;
        let message_hash = H::default().chain_update(message);
        let ring_members = ring.members();

        // Length guards: never index untrusted inputs without validating sizes first.
        let n = ring_members.len();
        if signature.responses.len() != n {
            return false;
        }
        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash() {
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

impl LinkRef for BLSAG {
    /// This is for linking two signatures and checking if they are signed by the same person
    fn link(signature_1: &BLSAG, signature_2: &BLSAG) -> bool {
        signature_1.key_image() == signature_2.key_image()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests;
