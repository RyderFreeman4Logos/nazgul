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
use crate::ring::{PrecomputedRingData, Ring, RingContext, RingHash};
use crate::traits::{KeyImageGen, LinkRef, SignRef, VerifyRef};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde-derive")]
use serde::{Deserialize, Serialize};

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
    /// Signs a message and stores only the Ring's hash (Compact mode).
    ///
    /// Use this when you expect the verifier to have access to the Ring definition.
    pub fn sign_compact<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
    ) -> Result<Self, SignatureError> {
        let signature = BLSAG::sign::<H, CSPRNG>(k, ring, precomputed_data, message)?;
        // Compute the hash using the same algorithm H used for signing (or a standard one).
        // Here we use the generic D for consensus hash if we could, but Ring::consensus_hash is generic.
        // For ContextualBLSAG, we need a convention. The `RingContext::consensus_hash` method
        // allows generating the hash later. But `RingContext::Compact` needs a pre-calculated hash.
        // We will use the provided `H` for the consensus hash to maintain consistency,
        // assuming H is suitable for consensus (e.g. Sha3).
        // Note: The Digest trait bound for sign is OutputSize=U64 (64 bytes), but RingHash is 32 bytes.
        // We need to truncate or assume the user provides a suitable hash.
        // To be safe and standard, we will just calculate the hash using H and truncate/pad to 32 bytes.
        let stored_hash = RingHash::from_output::<H>(ring.consensus_hash::<H>());

        Ok(Self {
            signature,
            context: RingContext::Compact(stored_hash),
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
        precomputed_data: Option<&PrecomputedRingData>,
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
    pub fn generate_fake_compact<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        ring: &Ring,
    ) -> Self {
        let signature = BLSAG::generate_fake::<CSPRNG>(ring);
        let stored_hash = RingHash::from_output::<H>(ring.consensus_hash::<H>());

        Self {
            signature,
            context: RingContext::Compact(stored_hash),
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
    ///         The method checks if `external_ring.consensus_hash() == stored_hash` before verifying.
    ///     *   If `context` is `Archival`, this is **OPTIONAL**.
    ///         *   If provided, it checks if `external_ring` matches the stored ring.
    ///         *   It always uses the stored (internal) ring for the mathematical verification.
    pub fn verify<H: Digest<OutputSize = U64> + Clone + Default>(
        &self,
        external_ring: Option<&Ring>,
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
    ) -> bool {
        match &self.context {
            RingContext::Compact(stored_hash) => {
                // Must provide external ring to verify a compact signature
                let ring = match external_ring {
                    Some(r) => r,
                    None => return false,
                };

                // 1. Verify Hash
                let output = RingHash::from_output::<H>(ring.consensus_hash::<H>());

                if *stored_hash != output {
                    return false;
                }

                // 2. Verify Signature
                BLSAG::verify::<H>(&self.signature, ring, precomputed_data, message)
            }
            RingContext::Archival(internal_ring) => {
                // If external ring is provided, we can strictly enforce it matches.
                if let Some(external) = external_ring {
                    // Fast check: compare consensus hashes first
                    let output_int = internal_ring.consensus_hash::<H>();
                    let output_ext = external.consensus_hash::<H>();
                    if output_int != output_ext {
                        return false;
                    }
                }

                // Use internal ring for verification
                // Note: precomputed_data must match the internal ring.
                BLSAG::verify::<H>(&self.signature, internal_ring, precomputed_data, message)
            }
        }
    }
}

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
    pub fn key_image(&self) -> RistrettoPoint {
        self.key_image
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
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
        rng: &mut R,
    ) -> Result<BLSAG, SignatureError> {
        let ring_members = ring.members();

        // Provers public key
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let secret_index = ring_members
            .binary_search_by_key(&k_point.compress().to_bytes(), |p| p.compress().to_bytes())
            .map_err(|_| SignatureError::SignerNotFound)?;

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k);

        let n = ring_members.len();

        // If precomputed data is provided, ensure its length matches the ring size to prevent out-of-bounds access.
        if let Some(d) = precomputed_data {
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
        for (i, ring_member) in ring_members
            .iter()
            .enumerate()
            .cycle()
            .skip(secret_index + 1)
            .take(n - 1)
        {
            let next_challenge = hash_ring_member_components(
                &message_hash,
                rs[i],
                current_challenge,
                *ring_member,
                key_image,
                precomputed_data.map(|d| d.hashed_points()[i]),
            );

            current_challenge = next_challenge;

            // If we just computed the challenge for index 0, save it.
            // In the loop logic, `next_challenge` corresponds to c_{i+1}.
            // So if we are at index n-1, we just computed c_0.
            if i == n - 1 {
                c_0 = current_challenge;
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
        let n = ring.members().len();

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
        precomputed_data: Option<&PrecomputedRingData>,
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
        precomputed_data: Option<&PrecomputedRingData>,
        message: &[u8],
    ) -> bool {
        let mut reconstructed_c: Scalar = signature.challenge;
        let message_hash = H::default().chain_update(message);
        let ring_members = ring.members();

        // Length guards: never index untrusted inputs without validating sizes first.
        let n = ring_members.len();
        if signature.responses.len() != n {
            // If responses count does not match ring size, treat as invalid.
            return false;
        }
        if let Some(d) = precomputed_data {
            if d.hashed_points().len() != n {
                // If precomputed points count does not match ring size, treat as invalid.
                return false;
            }
        }

        for (j, ring_member) in ring_members.iter().enumerate() {
            reconstructed_c = hash_ring_member_components(
                &message_hash,
                signature.responses[j],
                reconstructed_c,
                *ring_member,
                signature.key_image,
                precomputed_data.map(|d| d.hashed_points()[j]),
            );
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
    fn blsag_sign_rejects_mismatched_precomputed_len() {
        let mut csprng = OsRng::default();
        let k: Scalar = Scalar::random(&mut csprng);
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        // ring_a: smaller ring used to generate precomputation
        let mut public_keys_a: Vec<RistrettoPoint> = (0..2)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        public_keys_a.push(k_point);
        let ring_a = Ring::new(public_keys_a);

        // ring_b: larger ring used for signing
        let mut public_keys_b: Vec<RistrettoPoint> = ring_a.members().to_vec();
        public_keys_b.push(RistrettoPoint::random(&mut csprng));
        let ring_b = Ring::new(public_keys_b);

        // Using smaller ring precomputation against a larger ring should return an error, not panic
        let precomp_small = ring_a.precompute::<Sha512>();
        let message = b"m".to_vec();
        let err = BLSAG::sign::<Sha512, OsRng>(k, &ring_b, Some(&precomp_small), &message)
            .expect_err("expected InvalidPrecomputedData error");
        assert_eq!(err, SignatureError::InvalidPrecomputedData);
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
}
