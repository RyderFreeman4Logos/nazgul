//! Convenience wrappers that drive the streaming state machines internally.
//!
//! These functions provide the same API ergonomics as the one-shot
//! [`BLSAG::sign`](super::BLSAG::sign) / [`BLSAG::verify`](super::BLSAG::verify)
//! but use [`StreamingBlsagSigner`] and [`StreamingBlsagVerifier`] under the
//! hood, achieving O(1) peak memory for the signature computation.
//!
//! The output is mathematically identical to the one-shot path and verifies
//! with either verification method.

use super::streaming::{
    StepOutput, StreamingBlsagSigner, StreamingBlsagVerifier, StreamingError, VerifyStepOutput,
};
use super::{ResponseVec, BLSAG};
use crate::prelude::*;
use crate::ring::Ring;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};

/// Maps a streaming protocol error to the appropriate `SignatureError` variant.
fn map_streaming_err(e: StreamingError) -> SignatureError {
    match e {
        StreamingError::InvalidPoint => SignatureError::DecompressionFailed,
        StreamingError::IdentityMismatch => SignatureError::SignerNotFound,
        _ => SignatureError::StreamingProtocol,
    }
}

impl BLSAG {
    /// Signs a message using the streaming state machine (O(1) peak memory)
    /// with an externally provided RNG.
    ///
    /// Functionally equivalent to [`BLSAG::sign_with_rng`] but internally
    /// drives [`StreamingBlsagSigner`] through both phases — ring members are
    /// fed one at a time instead of requiring the full ring in memory
    /// simultaneously during the cryptographic computation.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::SignerNotFound`] if `k * G` is not in `ring`.
    /// Returns [`SignatureError::DecompressionFailed`] if any ring member
    /// fails Ristretto decompression.
    /// Returns [`SignatureError::StreamingProtocol`] if the streaming state
    /// machine encounters an unexpected condition (e.g., ring-switch detected).
    pub fn sign_streaming_with_rng<
        H: Digest<OutputSize = U64> + Clone + Default,
        R: CryptoRng + RngCore,
    >(
        k: Scalar,
        ring: &Ring,
        message: &[u8],
        rng: R,
    ) -> Result<BLSAG, SignatureError> {
        let compressed = ring.compressed_members();
        let n = ring.len();
        let ring_hash = ring.canonical_hash_with::<H>();

        // Find the signer's index in the sorted ring.
        let signer_pk = (k * RISTRETTO_BASEPOINT_POINT).compress();
        let signer_index = compressed
            .iter()
            .position(|c| c.as_bytes() == signer_pk.as_bytes())
            .ok_or(SignatureError::SignerNotFound)?;

        let mut signer = StreamingBlsagSigner::<H, R>::new(rng);

        // Phase 1: Validation — feed members in canonical order 0..N-1.
        signer
            .init_validation(n, ring_hash)
            .map_err(map_streaming_err)?;

        for (i, member) in compressed.iter().enumerate() {
            signer
                .validate_member(i, member)
                .map_err(map_streaming_err)?;
        }

        // Phase 2: Signing — feed members in signing order (pi+1 .. pi).
        signer
            .init_signing(signer_index, k, &signer_pk, message)
            .map_err(map_streaming_err)?;

        let mut responses: ResponseVec = core::iter::repeat_n(Scalar::ZERO, n).collect();
        let mut c_0 = Scalar::ZERO;
        let mut key_image = RISTRETTO_BASEPOINT_POINT; // placeholder

        for step in 0..n {
            let idx = (signer_index + 1 + step) % n;
            let result = signer
                .sign_member(idx, &compressed[idx])
                .map_err(map_streaming_err)?;

            match result {
                StepOutput::ScalarResponse { index, s_i } => {
                    responses[index] = s_i;
                }
                StepOutput::Complete {
                    c_0: c0,
                    key_image: ki,
                    signer_s,
                    signer_index: si,
                } => {
                    c_0 = c0;
                    key_image = ki;
                    responses[si] = signer_s;
                }
                StepOutput::Ack => {
                    // Should never happen during signing phase.
                    return Err(SignatureError::StreamingProtocol);
                }
            }
        }

        Ok(BLSAG {
            challenge: c_0,
            responses,
            key_image,
        })
    }

    /// Signs a message using the streaming state machine (O(1) peak memory).
    ///
    /// Convenience wrapper that creates a CSPRNG via `Default` and delegates to
    /// [`sign_streaming_with_rng`](BLSAG::sign_streaming_with_rng).
    pub fn sign_streaming<
        H: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Scalar,
        ring: &Ring,
        message: &[u8],
    ) -> Result<BLSAG, SignatureError> {
        let csprng = CSPRNG::default();
        Self::sign_streaming_with_rng::<H, CSPRNG>(k, ring, message, csprng)
    }

    /// Verifies a BLSAG signature using the streaming state machine (O(1) peak memory).
    ///
    /// Functionally equivalent to [`BLSAG::verify`](crate::traits::VerifyRef::verify)
    /// but internally drives [`StreamingBlsagVerifier`] — ring members are
    /// processed one at a time.
    ///
    /// Returns `true` if the signature is valid for the given `ring` and `message`.
    pub fn verify_streaming<H: Digest<OutputSize = U64> + Clone + Default>(
        signature: &BLSAG,
        ring: &Ring,
        message: &[u8],
    ) -> bool {
        let compressed = ring.compressed_members();
        let n = ring.len();

        if signature.responses().len() != n {
            return false;
        }

        let mut verifier = StreamingBlsagVerifier::<H>::new();

        let ki_compressed = signature.key_image().compress();
        if verifier
            .init(signature.challenge, &ki_compressed, message, n)
            .is_err()
        {
            return false;
        }

        for (i, (member, &s_i)) in compressed.iter().zip(signature.responses()).enumerate() {
            match verifier.verify_member(i, member, s_i) {
                Ok(VerifyStepOutput::Ack) => {}
                Ok(VerifyStepOutput::Complete { valid }) => return valid,
                Err(_) => return false,
            }
        }

        // Should not reach here if ring_len > 0.
        false
    }
}
