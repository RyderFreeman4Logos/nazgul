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
//!     *signer_keypair.secret(),
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
use crate::ring::{PrecomputedRingData, Ring};
use crate::traits::{KeyImageGen, LinkRef, SignRef, VerifyRef};
#[cfg(feature = "std")]
use crate::keypair::KeyPair;
#[cfg(feature = "std")]
use rand::rngs::OsRng;
#[cfg(feature = "std")]
use sha3::Keccak512;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(feature = "serde-derive")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
#[cfg_attr(feature = "serde-derive", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct VerificationTimeModel {
    pub nanos_per_member: u64,
    pub nanos_per_byte: u64,
    pub fixed_overhead_nanos: i64,
    /// The learning rate for the online update algorithm (SGD).
    #[cfg_attr(feature = "serde-derive", serde(default = "default_learning_rate"))]
    pub learning_rate: f64,
    /// The number of updates performed on this model.
    #[cfg_attr(feature = "serde-derive", serde(default))]
    pub updates: u64,
}

/// Serde helper to provide a default value for the learning rate.
fn default_learning_rate() -> f64 {
    1e-14 // A very small default learning rate is crucial for stability.
}

#[cfg(feature = "std")]
impl VerificationTimeModel {
    /// Generates a hardware-specific model by running an intensive benchmark.
    ///
    /// This function can take several minutes to complete as it performs
    /// real-time performance measurements across a wide range of parameters.
    /// It is recommended to run this once, save the resulting model to a file,
    /// and reload it for future use.
    ///
    /// # Returns
    ///
    /// A `VerificationTimeModel` instance with coefficients calibrated for the current machine.
    pub fn generate_heavy() -> Self {
        println!("Starting heavy performance model generation. This will take several minutes...");

        // --- 1. Isolate `nanos_per_byte` (c) ---
        // Keep ring size small and fixed, vary message size.
        let n_fixed = 2;
        let m_sizes = [1024, 131072]; // 1KB and 128KB
        let mut times_for_m = [0u128; 2];

        for (i, &m) in m_sizes.iter().enumerate() {
            let message: Vec<u8> = vec![0; m];
            times_for_m[i] = Self::run_benchmark(n_fixed, &message, 100);
        }

        let nanos_per_byte = ((times_for_m[1] - times_for_m[0]) as f64
            / (m_sizes[1] - m_sizes[0]) as f64)
            .round() as u64;
        println!(
            "  - Calculated nanos_per_byte (c): {}",
            nanos_per_byte
        );

        // --- 2. Isolate `nanos_per_member` (a) ---
        // Keep message size small and fixed, vary ring size.
        let m_fixed = 256;
        let message: Vec<u8> = vec![0; m_fixed];
        let n_sizes = [100, 1000];
        let mut times_for_n = [0u128; 2];

        for (i, &n) in n_sizes.iter().enumerate() {
            times_for_n[i] = Self::run_benchmark(n, &message, 50);
        }
        let nanos_per_member = ((times_for_n[1] - times_for_n[0]) as f64
            / (n_sizes[1] - n_sizes[0]) as f64)
            .round() as u64;
        println!(
            "  - Calculated nanos_per_member (a): {}",
            nanos_per_member
        );

        // --- 3. Calculate `fixed_overhead_nanos` (d) ---
        // Use the first measurement from the 'n' test.
        let t1 = times_for_n[0] as i64;
        let n1 = n_sizes[0] as i64;
        let m1 = m_fixed as i64;
        let a = nanos_per_member as i64;
        let c = nanos_per_byte as i64;

        let fixed_overhead_nanos = t1 - a * n1 - c * m1;
        println!(
            "  - Calculated fixed_overhead_nanos (d): {}",
            fixed_overhead_nanos
        );

        println!("Performance model generation complete.");

        Self {
            nanos_per_member,
            nanos_per_byte,
            fixed_overhead_nanos,
            learning_rate: default_learning_rate(),
            updates: 0,
        }
    }

    /// Predicts the verification time using this model's coefficients.
    ///
    /// # Arguments
    ///
    /// * `ring_size`: The number of members in the ring.
    /// * `message_size`: The size of the message in bytes.
    ///
    /// # Returns
    ///
    /// * An estimated `Duration` for the verification.
    pub fn predict(&self, ring_size: usize, message_size: usize) -> Duration {
        if ring_size == 0 {
            return Duration::from_nanos(0);
        }

        let term_n = (self.nanos_per_member as i64) * (ring_size as i64);
        let term_m = (self.nanos_per_byte as i64) * (message_size as i64);

        let estimated_nanos = term_n + term_m + self.fixed_overhead_nanos;

        if estimated_nanos > 0 {
            Duration::from_nanos(estimated_nanos as u64)
        } else {
            Duration::from_nanos(0)
        }
    }

    /// Helper function to run a benchmark for a given n and message.
    fn run_benchmark(n: usize, message: &[u8], iterations: u32) -> u128 {
        let mut csprng = OsRng;
        let signer_keypair = KeyPair::generate(&mut csprng);

        let mut public_keys: Vec<_> = (0..(n - 1))
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        public_keys.push(*signer_keypair.public());
        let ring = Ring::new(public_keys);

        let signature =
            BLSAG::sign::<Keccak512, OsRng>(*signer_keypair.secret(), &ring, None, message).unwrap();

        let mut total_duration = Duration::new(0, 0);
        for _ in 0..iterations {
            let start = Instant::now();
            let is_valid = BLSAG::verify::<Keccak512>(&signature, &ring, None, message);
            // Prevent the compiler from optimizing away the call by using a black box.
            let _ = std::hint::black_box(is_valid);
            total_duration += start.elapsed();
        }
        total_duration.as_nanos() / iterations as u128
    }

    /// Updates the model coefficients based on a new, real-world measurement.
    ///
    /// This method uses a single step of Stochastic Gradient Descent (SGD) to refine the model.
    /// It should be called with a pure execution time measurement, excluding any queueing delay.
    ///
    /// # Arguments
    ///
    /// * `ring_size`: The ring size of the verified signature.
    /// * `message_size`: The message size of the verified signature.
    /// * `actual_time`: The actual, pure execution time for the `verify` operation.
    pub fn update(&mut self, ring_size: usize, message_size: usize, actual_time: Duration) {
        let t_actual = actual_time.as_nanos() as f64;

        // Use f64 for calculations to allow for fractional adjustments.
        let mut a = self.nanos_per_member as f64;
        let mut c = self.nanos_per_byte as f64;
        let mut d = self.fixed_overhead_nanos as f64;

        // 1. Predict using the current model.
        let t_pred = a * (ring_size as f64) + c * (message_size as f64) + d;

        // 2. Calculate the error.
        let error = t_actual - t_pred;

        // 3. Update coefficients based on the error and learning rate.
        // The update is proportional to the error and the value of the corresponding variable.
        a += self.learning_rate * error * (ring_size as f64);
        c += self.learning_rate * error * (message_size as f64);
        d += self.learning_rate * error; // The variable for the intercept is always 1.

        // 4. Store the updated, rounded coefficients.
        self.nanos_per_member = a.round().max(0.0) as u64;
        self.nanos_per_byte = c.round().max(0.0) as u64;
        self.fixed_overhead_nanos = d.round() as i64;
        self.updates += 1;
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
        let ring_members = ring.members();

        // Provers public key
        let k_point: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        let secret_index = ring_members
            .binary_search_by_key(&k_point.compress().to_bytes(), |p| p.compress().to_bytes())
            .map_err(|_| SignatureError::SignerNotFound)?;

        let key_image: RistrettoPoint = BLSAG::generate_key_image::<H>(k);

        let n = ring_members.len();

        let a: Scalar = Scalar::random(&mut csprng);

        let mut rs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut csprng)).collect();

        let mut cs: Vec<Scalar> = (0..n).map(|_| Scalar::ZERO).collect();

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
        cs[(secret_index + 1) % n] = Scalar::from_hash(h);

        let mut i = (secret_index + 1) % n;

        loop {
            cs[(i + 1) % n] = hash_ring_member_components(
                &message_hash,
                rs[i % n],
                cs[i % n],
                ring_members[i % n],
                key_image,
                precomputed_data.map(|d| d.hashed_points()[i % n]),
            );

            if (secret_index >= 1 && i % n == (secret_index - 1) % n)
                || (secret_index == 0 && i % n == n - 1)
            {
                break;
            } else {
                i = (i + 1) % n;
            }
        }

        rs[secret_index] = a - (cs[secret_index] * k);

        Ok(BLSAG {
            challenge: cs[0],
            responses: rs,
            key_image,
        })
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
    #[cfg(feature = "serde-derive")]
    fn verification_time_model_test() {
        // Manually create a model with some hypothetical coefficients.
        let model = VerificationTimeModel {
            nanos_per_member: 70_000,
            nanos_per_byte: 10,
            fixed_overhead_nanos: -150_000,
            learning_rate: 1e-12, // A typical small learning rate
            updates: 0,
        };

        // Test prediction.
        let ring_size = 100;
        let message_size = 8000; // 8 KB
        let prediction = model.predict(ring_size, message_size);

        // Expected: (70000 * 100) + (10 * 8000) - 150000 = 7,000,000 + 80,000 - 150,000 = 6,930,000 ns
        assert_eq!(prediction.as_nanos(), 6_930_000);

        // Test serialization and deserialization.
        let serialized = serde_json::to_string(&model).unwrap();
        let deserialized: VerificationTimeModel = serde_json::from_str(&serialized).unwrap();

        assert_eq!(model.nanos_per_member, deserialized.nanos_per_member);
        assert_eq!(model.nanos_per_byte, deserialized.nanos_per_byte);
        assert_eq!(
            model.fixed_overhead_nanos,
            deserialized.fixed_overhead_nanos
        );

        // Test that the deserialized model gives the same prediction.
        let prediction2 = deserialized.predict(ring_size, message_size);
        assert_eq!(prediction, prediction2);
    }

    #[test]
    fn verification_time_model_update_test() {
        let mut model = VerificationTimeModel {
            nanos_per_member: 70_000,
            nanos_per_byte: 10,
            fixed_overhead_nanos: -150_000,
            learning_rate: 1e-7, // Use a larger rate for test visibility
            updates: 0,
        };

        let ring_size = 1000;
        let message_size = 16000;

        // Predict, then "observe" a time that is significantly longer than predicted.
        let prediction = model.predict(ring_size, message_size);
        let actual_time = prediction + Duration::from_millis(10); // 10ms longer

        model.update(ring_size, message_size, actual_time);

        // Check that the coefficients have increased, as the actual time was > predicted time.
        assert!(model.nanos_per_member > 70_000);
        assert!(model.nanos_per_byte > 10);
        assert!(model.fixed_overhead_nanos > -150_000);
        assert_eq!(model.updates, 1);
    }
}
