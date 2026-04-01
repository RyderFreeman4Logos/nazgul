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

mod contextual;
mod engine;
mod precompute;
mod sign;
mod strategy;
pub mod streaming;
mod streaming_wrappers;
mod verify;

pub use contextual::{ContextualBLSAG, ContextualBlsagParts};
pub use precompute::SigningPrecomputation;
pub use strategy::MemoryStrategy;
pub use streaming::{
    StepOutput, StreamingBlsagSigner, StreamingBlsagVerifier, StreamingError, VerifyStepOutput,
};

#[cfg(not(feature = "smallvec-responses"))]
use crate::prelude::*;
use crate::ring::Ring;
use crate::traits::LinkRef;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde-derive")]
use serde::{Deserialize, Serialize};

/// Response vector type: uses `SmallVec<[Scalar; 16]>` when the `smallvec-responses`
/// feature is enabled (inline storage for rings up to 16 members), otherwise
/// falls back to `Vec<Scalar>`.
#[cfg(feature = "smallvec-responses")]
pub(crate) type ResponseVec = smallvec::SmallVec<[Scalar; 16]>;

#[cfg(not(feature = "smallvec-responses"))]
pub(crate) type ResponseVec = Vec<Scalar>;

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

    /// Generates a fake BLSAG signature using an externally provided RNG.
    ///
    /// The generated signature is structurally valid (contains valid points and scalars)
    /// but is cryptographically invalid. Use this to test robustness against DOS attacks
    /// or other scenarios where large numbers of invalid signatures are needed efficiently.
    ///
    /// # Performance
    /// This method performs `n + 1` RNG calls (where `n` is ring size) and 1 RistrettoPoint generation.
    /// It avoids expensive multiscalar multiplications required for real signing.
    pub fn generate_fake_with_rng<R: CryptoRng + RngCore>(ring: &Ring, rng: &mut R) -> Self {
        let n = ring.len();

        let challenge = Scalar::random(rng);
        let responses: ResponseVec = (0..n).map(|_| Scalar::random(rng)).collect();
        let key_image = RistrettoPoint::random(rng);

        BLSAG {
            challenge,
            responses,
            key_image,
        }
    }

    /// Generates a fake BLSAG signature for testing purposes.
    ///
    /// Convenience wrapper that creates a CSPRNG via `Default` and delegates to
    /// [`generate_fake_with_rng`](Self::generate_fake_with_rng).
    pub fn generate_fake<CSPRNG: CryptoRng + RngCore + Default>(ring: &Ring) -> Self {
        let mut csprng = CSPRNG::default();
        Self::generate_fake_with_rng(ring, &mut csprng)
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
