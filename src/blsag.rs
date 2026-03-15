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

use crate::prelude::*;
use crate::ring::{PreparedRing, Ring, RingContext, RingHash};
use crate::traits::{KeyImageGen, LinkRef, SignRef, VerifyRef};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::ristretto::VartimeRistrettoPrecomputation;
use curve25519_dalek::scalar::Scalar;
#[cfg(any(not(feature = "optimized-msm"), test))]
use curve25519_dalek::traits::VartimeMultiscalarMul;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde-derive")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

                BLSAG::verify::<H>(&self.signature, ring, precomputed_data, message)
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
    responses: Vec<Scalar>,
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
    responses: Vec<Scalar>,
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
        responses: Vec<Scalar>,
        key_image: RistrettoPoint,
    ) -> Self {
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
        if !ring.is_decompressed() {
            return Err(SignatureError::CompressedRing);
        }
        let ring_members = ring.members();

        // Provers public key
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

        let a: Scalar = Scalar::random(rng);

        let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();

        // Hash of message is shared by all challenges H_n(m, ....)
        let mut message_hash = H::default();
        message_hash.update(message);

        let mut h = message_hash.clone();
        h.update(
            (a * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        h.update(
            (a * RistrettoPoint::from_hash(
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
                let next_challenge = hash_ring_member_optimized::<H>(
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
                let next_challenge = hash_ring_member_components::<H>(
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

        // After the loop, `current_challenge` holds the challenge for the signer (c_{secret_index}).
        rs[secret_index] = a - (current_challenge * k);

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

        let responses: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();

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
                let next_challenge = hash_ring_member_optimized::<H>(
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
                let next_challenge = hash_ring_member_components::<H>(
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
        if !ring.is_decompressed() {
            return Err(SignatureError::CompressedRing);
        }
        let ring_members = ring.members();

        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let secret_index = ring_members
            .binary_search_by_key(&k_point.compress().to_bytes(), |p| p.compress().to_bytes())
            .map_err(|_| SignatureError::SignerNotFound)?;

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k);

        let n = ring_members.len();

        if let Some(d) = precomputed_data {
            if d.ring_hash() != ring.canonical_hash() {
                return Err(SignatureError::RingMismatch);
            }
            if d.hashed_points().len() != n {
                return Err(SignatureError::InvalidPrecomputedData);
            }
        }

        let a: Scalar = Scalar::random(rng);
        let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();

        let mut message_hash = H::default();
        message_hash.update(message);

        let mut h = message_hash.clone();
        h.update(
            (a * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        h.update(
            (a * RistrettoPoint::from_hash(
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

        // Progress reporting: fire approximately every 10% of ring members.
        let loop_len = n - 1;
        let chunk = progress_chunk_size(loop_len);

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
                let next_challenge = hash_ring_member_optimized::<H>(
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

                if (step + 1) % chunk == 0 || step + 1 == loop_len {
                    progress(step + 1, loop_len);
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
                let next_challenge = hash_ring_member_components::<H>(
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

                if (step + 1) % chunk == 0 || step + 1 == loop_len {
                    progress(step + 1, loop_len);
                }
            }
        }

        rs[secret_index] = a - (current_challenge * k);

        Ok(BLSAG {
            challenge: c_0,
            responses: rs,
            key_image,
        })
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

        let chunk = progress_chunk_size(n);

        #[cfg(feature = "optimized-msm")]
        {
            let ki_table = VartimeRistrettoPrecomputation::new([signature.key_image]);

            for (j, ring_member) in ring_members.iter().enumerate() {
                reconstructed_c = hash_ring_member_optimized::<H>(
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
                reconstructed_c = hash_ring_member_components::<H>(
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
        let responses: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();
        let key_image = RistrettoPoint::random(&mut csprng);

        BLSAG {
            challenge,
            responses,
            key_image,
        }
    }
}

/// Private helper function to perform the core cryptographic hashing used in both
/// signing and verification. This prevents code duplication.
#[cfg(any(not(feature = "optimized-msm"), test))]
fn hash_ring_member_components<H: Digest<OutputSize = U64> + Clone + Default>(
    message_hash: &H,
    response: Scalar,
    challenge: Scalar,
    public_key: RistrettoPoint,
    key_image: RistrettoPoint,
    precomputed_pk_hash: Option<RistrettoPoint>,
) -> Scalar {
    let mut h = message_hash.clone();
    h.update(
        RistrettoPoint::vartime_multiscalar_mul(
            &[response, challenge],
            &[constants::RISTRETTO_BASEPOINT_POINT, public_key],
        )
        .compress()
        .as_bytes(),
    );

    let pk_hash = precomputed_pk_hash.unwrap_or_else(|| {
        RistrettoPoint::from_hash(H::default().chain_update(public_key.compress().as_bytes()))
    });

    h.update(
        RistrettoPoint::vartime_multiscalar_mul(&[response, challenge], &[pk_hash, key_image])
            .compress()
            .as_bytes(),
    );
    Scalar::from_hash(h)
}

/// Optimized hash helper using specialized MSM routines.
///
/// For L: uses `vartime_double_scalar_mul_basepoint` (2-scalar with known basepoint).
/// For R: uses precomputed key_image table with `vartime_mixed_multiscalar_mul`.
#[cfg(feature = "optimized-msm")]
fn hash_ring_member_optimized<H: Digest<OutputSize = U64> + Clone + Default>(
    message_hash: &H,
    response: Scalar,
    challenge: Scalar,
    public_key: RistrettoPoint,
    key_image_table: &VartimeRistrettoPrecomputation,
    precomputed_pk_hash: Option<RistrettoPoint>,
) -> Scalar {
    let mut h = message_hash.clone();

    // L = response * G + challenge * public_key
    // vartime_double_scalar_mul_basepoint(a, A, b) = a*A + b*G
    h.update(
        RistrettoPoint::vartime_double_scalar_mul_basepoint(&challenge, &public_key, &response)
            .compress()
            .as_bytes(),
    );

    let pk_hash = precomputed_pk_hash.unwrap_or_else(|| {
        RistrettoPoint::from_hash(H::default().chain_update(public_key.compress().as_bytes()))
    });

    // R = response * H_p(P) + challenge * key_image
    // vartime_mixed_multiscalar_mul(static_scalars, dynamic_scalars, dynamic_points)
    // where static_scalars correspond to the precomputed points (key_image),
    // and dynamic_scalars/points are for non-precomputed points (pk_hash).
    h.update(
        key_image_table
            .vartime_mixed_multiscalar_mul(&[challenge], &[response], &[pk_hash])
            .compress()
            .as_bytes(),
    );
    Scalar::from_hash(h)
}

/// Compute the chunk size for progress callbacks: ~10% of total, minimum 1.
#[cfg(feature = "progress-callback")]
fn progress_chunk_size(total: usize) -> usize {
    (total / 10).max(1)
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
                reconstructed_c = hash_ring_member_optimized::<H>(
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
                reconstructed_c = hash_ring_member_components::<H>(
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
mod test {
    extern crate blake2;
    extern crate rand;
    extern crate rand_chacha;
    extern crate sha2;
    extern crate sha3;

    use super::*;
    use blake2::Blake2b512;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use sha3::Keccak512;

    #[test]
    fn blsag() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = 2;
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);
        let message: Vec<u8> = b"This is the message".iter().cloned().collect();

        {
            let signature = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, &message).unwrap();
            let result = BLSAG::verify::<Sha512>(&signature, &ring, None, &message);
            assert!(result);
        }

        {
            let signature = BLSAG::sign::<Keccak512, OsRng>(k, &ring, None, &message).unwrap();
            let result = BLSAG::verify::<Keccak512>(&signature, &ring, None, &message);
            assert!(result);
        }

        {
            let signature = BLSAG::sign::<Blake2b512, OsRng>(k, &ring, None, &message).unwrap();
            let result = BLSAG::verify::<Blake2b512>(&signature, &ring, None, &message);
            assert!(result);
        }

        let mut another_public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        another_public_keys.push(k_point);
        let another_ring = Ring::new(another_public_keys);
        let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
        let signature_1 =
            BLSAG::sign::<Blake2b512, OsRng>(k, &another_ring, None, &another_message).unwrap();
        let signature_2 = BLSAG::sign::<Blake2b512, OsRng>(k, &ring, None, &message).unwrap();
        let result = BLSAG::link(&signature_1, &signature_2);
        assert!(result);
    }

    #[test]
    fn blsag_debug() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = 2;
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);
        let message: Vec<u8> = b"This is the message".iter().cloned().collect();

        let signature = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, &message).unwrap();
        // The following line will fail to compile if Debug is not implemented for BLSAG.
        let _ = format!("{:?}", signature);
    }

    #[test]
    fn blsag_verify_rejects_mismatched_ring_len() {
        // Prepare basic materials
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = 3usize;

        // Build the ring used for signing (includes signer)
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);

        // Produce a signature
        let message: Vec<u8> = b"msg".to_vec();
        let signature = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, &message).unwrap();

        // Construct a larger ring (one extra unrelated public key)
        let mut bigger_members = ring.members().to_vec();
        bigger_members.push(RistrettoPoint::random(&mut csprng));
        let bigger_ring = Ring::new(bigger_members);

        // Verification should not panic; expect false
        let ok = BLSAG::verify::<Sha512>(&signature, &bigger_ring, None, &message);
        assert!(!ok);
    }

    #[test]
    fn blsag_sign_rejects_mismatched_precomputed_ring() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        // ring_a: smaller ring used to generate precomputation
        let mut public_keys_a: Vec<RistrettoPoint> = (0..2)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys_a.push(k_point);
        let ring_a = Ring::new(public_keys_a);

        // ring_b: larger ring used for signing (different members = different canonical hash)
        let mut public_keys_b: Vec<RistrettoPoint> = ring_a.members().to_vec();
        public_keys_b.push(RistrettoPoint::random(&mut csprng));
        let ring_b = Ring::new(public_keys_b);

        // Using precomputation from a different ring should return RingMismatch
        let precomp_small = ring_a.precompute::<Sha512>();
        let message = b"m".to_vec();
        let err = BLSAG::sign::<Sha512, OsRng>(k, &ring_b, Some(&precomp_small), &message)
            .expect_err("expected RingMismatch error");
        assert_eq!(err, SignatureError::RingMismatch);
    }

    /// Cross-validates that the optimized MSM path produces identical results
    /// to the generic `vartime_multiscalar_mul` path. Signs with a seeded RNG,
    /// then verifies that both hash helpers yield the same challenge chain.
    #[cfg(feature = "optimized-msm")]
    #[test]
    fn blsag_optimized_msm_cross_validation() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
        let k: Scalar = Scalar::random(&mut rng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let n = 5;
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);

        let message = b"cross-validation test message";

        // Sign with deterministic RNG
        let mut sign_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
        let signature =
            BLSAG::sign_with_rng::<Sha512, _>(k, &ring, None, message, &mut sign_rng).unwrap();

        // Standard verify (uses optimized path via the trait)
        let valid = BLSAG::verify::<Sha512>(&signature, &ring, None, message);
        assert!(valid, "optimized MSM verify must accept valid signature");

        // Manually run the generic path and compare challenge chains
        let message_hash = Sha512::default().chain_update(message);
        let ring_members = ring.members();
        let ki_table = VartimeRistrettoPrecomputation::new([signature.key_image]);

        let mut c_generic = signature.challenge;
        let mut c_optimized = signature.challenge;

        for (j, ring_member) in ring_members.iter().enumerate() {
            c_generic = hash_ring_member_components::<Sha512>(
                &message_hash,
                signature.responses[j],
                c_generic,
                *ring_member,
                signature.key_image,
                None,
            );
            c_optimized = hash_ring_member_optimized::<Sha512>(
                &message_hash,
                signature.responses[j],
                c_optimized,
                *ring_member,
                &ki_table,
                None,
            );
            assert_eq!(
                c_generic, c_optimized,
                "challenge mismatch at ring index {j}"
            );
        }

        assert_eq!(
            c_generic, signature.challenge,
            "generic path must close the ring"
        );
        assert_eq!(
            c_optimized, signature.challenge,
            "optimized path must close the ring"
        );
    }

    #[test]
    fn blsag_verify_rejects_mismatched_precomputed_len() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        // ring_sign: used for signing
        let mut public_keys_sign: Vec<RistrettoPoint> = (0..2)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys_sign.push(k_point);
        let ring_sign = Ring::new(public_keys_sign);
        let message = b"m".to_vec();
        let sig = BLSAG::sign::<Sha512, OsRng>(k, &ring_sign, None, &message).unwrap();

        // ring_other: used to create mismatched-length precomputation
        let mut public_keys_other = ring_sign.members().to_vec();
        public_keys_other.push(RistrettoPoint::random(&mut csprng));
        let ring_other = Ring::new(public_keys_other);
        let precomp_other = ring_other.precompute::<Sha512>();

        // Verification should not panic; expect false
        let ok = BLSAG::verify::<Sha512>(&sig, &ring_sign, Some(&precomp_other), &message);
        assert!(!ok);
    }

    #[test]
    fn blsag_precomputed_sign_verify_roundtrip() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = 5;
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);
        let message = b"precomputed signing test";

        let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut csprng).unwrap();
        let signature = BLSAG::sign_precomputed::<Sha512>(precomp, &ring, None, message).unwrap();

        assert!(BLSAG::verify::<Sha512>(&signature, &ring, None, message));
    }

    #[test]
    fn blsag_precomputed_with_ring_data() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = 4;
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);
        let precomputed_ring = ring.precompute::<Sha512>();
        let message = b"precomputed signing with ring data";

        let precomp =
            BLSAG::precompute_signing::<Sha512, _>(k, &ring, Some(&precomputed_ring), &mut csprng)
                .unwrap();
        let signature =
            BLSAG::sign_precomputed::<Sha512>(precomp, &ring, Some(&precomputed_ring), message)
                .unwrap();

        assert!(BLSAG::verify::<Sha512>(
            &signature,
            &ring,
            Some(&precomputed_ring),
            message,
        ));
    }

    #[test]
    fn blsag_precomputed_rejects_ring_mismatch() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        // Ring A: used for precomputation
        let mut public_keys_a: Vec<RistrettoPoint> = (0..3)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys_a.push(k_point);
        let ring_a = Ring::new(public_keys_a);

        // Ring B: different ring used at sign time
        let mut public_keys_b: Vec<RistrettoPoint> = (0..3)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys_b.push(k_point);
        let ring_b = Ring::new(public_keys_b);

        let precomp =
            BLSAG::precompute_signing::<Sha512, _>(k, &ring_a, None, &mut csprng).unwrap();

        let err = BLSAG::sign_precomputed::<Sha512>(precomp, &ring_b, None, b"msg")
            .expect_err("expected RingMismatch");
        assert_eq!(err, SignatureError::RingMismatch);
    }

    #[test]
    fn blsag_precomputed_linkability() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        // Two different rings, same signer
        let mut pks_1: Vec<RistrettoPoint> = (0..3)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        pks_1.push(k_point);
        let ring_1 = Ring::new(pks_1);

        let mut pks_2: Vec<RistrettoPoint> = (0..4)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        pks_2.push(k_point);
        let ring_2 = Ring::new(pks_2);

        let precomp_1 =
            BLSAG::precompute_signing::<Sha512, _>(k, &ring_1, None, &mut csprng).unwrap();
        let sig_1 = BLSAG::sign_precomputed::<Sha512>(precomp_1, &ring_1, None, b"msg1").unwrap();

        let precomp_2 =
            BLSAG::precompute_signing::<Sha512, _>(k, &ring_2, None, &mut csprng).unwrap();
        let sig_2 = BLSAG::sign_precomputed::<Sha512>(precomp_2, &ring_2, None, b"msg2").unwrap();

        assert!(BLSAG::link(&sig_1, &sig_2));
    }

    #[cfg(feature = "progress-callback")]
    #[test]
    fn blsag_progress_callback_fires_during_sign_and_verify() {
        use core::cell::Cell;

        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;
        let n = 20;
        let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);
        let ring = Ring::new(public_keys);
        let message = b"progress callback test";

        // Track sign progress calls
        let sign_calls = Cell::new(0usize);
        let sign_last_current = Cell::new(0usize);
        let sign_last_total = Cell::new(0usize);

        let signature = BLSAG::sign_with_rng_and_progress::<Sha512, _>(
            k,
            &ring,
            None,
            message,
            &mut csprng,
            |current, total| {
                sign_calls.set(sign_calls.get() + 1);
                sign_last_current.set(current);
                sign_last_total.set(total);
            },
        )
        .unwrap();

        assert!(
            sign_calls.get() > 0,
            "sign progress must fire at least once"
        );
        // The last call must report completion (current == total).
        assert_eq!(sign_last_current.get(), sign_last_total.get());

        // Track verify progress calls
        let verify_calls = Cell::new(0usize);
        let verify_last_current = Cell::new(0usize);
        let verify_last_total = Cell::new(0usize);

        let valid = BLSAG::verify_with_progress::<Sha512>(
            &signature,
            &ring,
            None,
            message,
            |current, total| {
                verify_calls.set(verify_calls.get() + 1);
                verify_last_current.set(current);
                verify_last_total.set(total);
            },
        );

        assert!(valid, "signature must verify correctly");
        assert!(
            verify_calls.get() > 0,
            "verify progress must fire at least once"
        );
        assert_eq!(verify_last_current.get(), verify_last_total.get());
    }

    #[test]
    fn blsag_sign_rejects_compressed_ring() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let mut public_keys: Vec<RistrettoPoint> = (0..3)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);

        let compressed_keys: Vec<_> = public_keys.iter().map(|p| p.compress()).collect();
        let compressed_ring = Ring::from_compressed(compressed_keys);

        let message = b"compressed ring test";
        let err = BLSAG::sign::<Sha512, OsRng>(k, &compressed_ring, None, message)
            .expect_err("expected CompressedRing error");
        assert_eq!(err, SignatureError::CompressedRing);
    }

    #[test]
    fn blsag_verify_rejects_compressed_ring() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let mut public_keys: Vec<RistrettoPoint> = (0..3)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);

        let ring = Ring::new(public_keys.clone());
        let message = b"compressed ring verify test";
        let signature = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, message).unwrap();

        // Build a compressed ring (same members) and try to verify
        let compressed_keys: Vec<_> = public_keys.iter().map(|p| p.compress()).collect();
        let compressed_ring = Ring::from_compressed(compressed_keys);

        let result = BLSAG::verify::<Sha512>(&signature, &compressed_ring, None, message);
        assert!(!result, "verify must return false for compressed ring");
    }

    #[test]
    fn blsag_precompute_signing_rejects_compressed_ring() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let mut public_keys: Vec<RistrettoPoint> = (0..2)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys.push(k_point);

        let compressed_keys: Vec<_> = public_keys.iter().map(|p| p.compress()).collect();
        let compressed_ring = Ring::from_compressed(compressed_keys);

        let result = BLSAG::precompute_signing::<Sha512, _>(k, &compressed_ring, None, &mut csprng);
        match result {
            Err(e) => assert_eq!(e, SignatureError::CompressedRing),
            Ok(_) => panic!("expected CompressedRing error"),
        }
    }
}
