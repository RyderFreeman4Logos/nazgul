use super::engine;
use super::precompute::SecretScalar;
use super::{ResponseVec, SigningPrecomputation, BLSAG};
use crate::prelude::*;
use crate::ring::{PreparedRing, Ring};
use crate::traits::{KeyImageGen, SignRef};
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

impl BLSAG {
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
        // Wrap the secret key for zeroization on scope exit.
        let k = SecretScalar(k);

        if !ring.is_decompressed() {
            return Err(SignatureError::CompressedRing);
        }
        let ring_members = ring.members();

        // Prover's public key
        let k_point: RistrettoPoint = k.0 * constants::RISTRETTO_BASEPOINT_POINT;

        let secret_index = ring_members
            .binary_search_by_key(&k_point.compress().to_bytes(), |p| p.compress().to_bytes())
            .map_err(|_| SignatureError::SignerNotFound)?;

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k.0);

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
        rs[secret_index] = a.0 - (current_challenge * k.0);

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
        // Wrap the secret key for zeroization on scope exit.
        let k = SecretScalar(k);

        if !ring.is_decompressed() {
            return Err(SignatureError::CompressedRing);
        }
        let ring_members = ring.members();
        let k_point: RistrettoPoint = k.0 * constants::RISTRETTO_BASEPOINT_POINT;

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

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k.0);

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
            secret_key: k,
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
