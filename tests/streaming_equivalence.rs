//! Streaming vs standard BLSAG mathematical equivalence tests.
//!
//! Verifies that `StreamingBlsagSigner` and `ContextualBLSAG::sign_compact_with_rng`
//! produce signatures that:
//! 1. Both verify against the standard `BLSAG::verify`.
//! 2. Produce identical key images (same secret key + same Hp = same image).
//!
//! RNG consumption order differs between the two paths, so byte-level signature
//! identity is NOT expected — only mathematical equivalence (both valid, same key image).

#![cfg(feature = "std")]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use nazgul::blsag::streaming::{StepOutput, StreamingBlsagSigner};
use nazgul::blsag::{ContextualBLSAG, BLSAG};
use nazgul::ring::Ring;
use nazgul::traits::VerifyRef;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::Sha512;
use sha3::Sha3_512;

#[cfg(feature = "blake3")]
use nazgul::blake3_compat::Blake3_512;

/// Generate a deterministic keypair from a seed byte.
fn keypair_from_seed(seed: u8) -> (Scalar, curve25519_dalek::ristretto::RistrettoPoint) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sk = Scalar::random(&mut rng);
    let pk = sk * RISTRETTO_BASEPOINT_POINT;
    (sk, pk)
}

/// Run the full streaming-vs-standard equivalence check for a given ring size.
fn assert_streaming_math_equivalence<H: Digest<OutputSize = U64> + Clone + Default>(
    ring_size: usize,
) {
    // Generate deterministic keypairs. Signer is the first keypair.
    let keypairs: Vec<_> = (0..ring_size)
        .map(|i| keypair_from_seed(i as u8 + 1))
        .collect();
    let (secret_key, _) = keypairs[0];

    // Build the ring (Ring::new sorts by compressed bytes).
    let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
    let ring = Ring::new(public_keys);
    let ring_hash = ring.canonical_hash_with::<H>();

    // Find signer's index in the sorted ring.
    let signer_pk = secret_key * RISTRETTO_BASEPOINT_POINT;
    let signer_index = ring
        .members()
        .iter()
        .position(|p| p.compress() == signer_pk.compress())
        .expect("signer must be in ring");

    let message = b"streaming equivalence test message";

    // --- Path A: Standard ContextualBLSAG ---
    let mut rng_standard = ChaCha20Rng::from_seed([0xAA; 32]);
    let ctx_sig = ContextualBLSAG::sign_compact_with_rng::<H, _>(
        secret_key,
        &ring,
        None,
        message,
        &mut rng_standard,
    )
    .expect("standard signing must succeed");
    let standard_sig = &ctx_sig.signature;

    // --- Path B: Streaming signer (different RNG seed) ---
    let streaming_rng = ChaCha20Rng::from_seed([0xBB; 32]);
    let mut signer = StreamingBlsagSigner::<H, _>::new(streaming_rng);

    // Phase 1: Validation
    signer
        .init_validation(ring.len(), ring_hash)
        .expect("init_validation");
    let compressed_members = ring.compressed_members();
    for (i, compressed_member) in compressed_members.iter().enumerate() {
        let result = signer
            .validate_member(i, compressed_member)
            .expect("validate_member");
        assert!(matches!(result, StepOutput::Ack));
    }

    // Phase 2: Signing
    signer
        .init_signing(signer_index, secret_key, &signer_pk.compress(), message)
        .expect("init_signing");

    let n = ring.len();
    let mut responses = vec![Scalar::ZERO; n];
    let mut streaming_c0 = Scalar::ZERO;
    let mut streaming_key_image = RISTRETTO_BASEPOINT_POINT; // placeholder

    for step in 0..n {
        let idx = (signer_index + 1 + step) % n;
        let result = signer
            .sign_member(idx, &ring.members()[idx].compress())
            .expect("sign_member");

        match result {
            StepOutput::ScalarResponse { index, s_i } => {
                responses[index] = s_i;
            }
            StepOutput::Complete {
                c_0,
                key_image,
                signer_s,
                signer_index: si,
            } => {
                streaming_c0 = c_0;
                streaming_key_image = key_image;
                responses[si] = signer_s;
            }
            StepOutput::Ack => panic!("unexpected Ack during signing"),
        }
    }

    let streaming_sig = BLSAG::from_parts(streaming_c0, responses, streaming_key_image);

    // --- Verification: both signatures must be valid ---
    assert!(
        BLSAG::verify::<H>(standard_sig, &ring, None, message),
        "standard signature must verify (ring_size={ring_size})"
    );
    assert!(
        BLSAG::verify::<H>(&streaming_sig, &ring, None, message),
        "streaming signature must verify (ring_size={ring_size})"
    );

    // --- Key image equivalence: same secret key + same Hp => identical key image ---
    assert_eq!(
        standard_sig.key_image().compress(),
        streaming_key_image.compress(),
        "key images must be identical (ring_size={ring_size})"
    );

    // --- Sanity: both valid for the same message ---
    // (Already verified above, but also confirm wrong message fails for both.)
    let wrong_message = b"wrong message";
    assert!(
        !BLSAG::verify::<H>(standard_sig, &ring, None, wrong_message),
        "standard sig must reject wrong message"
    );
    assert!(
        !BLSAG::verify::<H>(&streaming_sig, &ring, None, wrong_message),
        "streaming sig must reject wrong message"
    );
}

#[test]
fn test_streaming_math_equivalence_1() {
    assert_streaming_math_equivalence::<Sha3_512>(1);
}

#[test]
fn test_streaming_math_equivalence_10() {
    assert_streaming_math_equivalence::<Sha3_512>(10);
}

#[test]
fn test_streaming_math_equivalence_100() {
    assert_streaming_math_equivalence::<Sha3_512>(100);
}

#[test]
fn test_streaming_math_equivalence_sha512() {
    assert_streaming_math_equivalence::<Sha512>(10);
}

#[cfg(feature = "blake3")]
#[test]
fn test_streaming_math_equivalence_blake3() {
    assert_streaming_math_equivalence::<Blake3_512>(10);
}

// ---------------------------------------------------------------------------
// Convenience wrapper equivalence tests
// ---------------------------------------------------------------------------

/// Verify that `BLSAG::sign_streaming_with_rng` produces a valid signature
/// and that `BLSAG::verify_streaming` accepts it.
fn assert_convenience_wrapper_equivalence<H: Digest<OutputSize = U64> + Clone + Default>(
    ring_size: usize,
) {
    let keypairs: Vec<_> = (0..ring_size)
        .map(|i| keypair_from_seed(i as u8 + 1))
        .collect();
    let (secret_key, _) = keypairs[0];

    let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
    let ring = Ring::new(public_keys);

    let message = b"convenience wrapper equivalence test";

    // --- Path A: Standard one-shot sign + verify ---
    let mut rng_standard = ChaCha20Rng::from_seed([0xCC; 32]);
    let standard_sig =
        BLSAG::sign_with_rng::<H, _>(secret_key, &ring, None, message, &mut rng_standard)
            .expect("standard sign");
    assert!(
        BLSAG::verify::<H>(&standard_sig, &ring, None, message),
        "standard verify (ring_size={ring_size})"
    );

    // --- Path B: Streaming convenience sign + verify ---
    let rng_streaming = ChaCha20Rng::from_seed([0xDD; 32]);
    let streaming_sig =
        BLSAG::sign_streaming_with_rng::<H, _>(secret_key, &ring, message, rng_streaming)
            .expect("streaming convenience sign");

    // Streaming signature verifies with both standard and streaming verifiers.
    assert!(
        BLSAG::verify::<H>(&streaming_sig, &ring, None, message),
        "streaming sig → standard verify (ring_size={ring_size})"
    );
    assert!(
        BLSAG::verify_streaming::<H>(&streaming_sig, &ring, message),
        "streaming sig → streaming verify (ring_size={ring_size})"
    );

    // Standard signature verifies with streaming verifier.
    assert!(
        BLSAG::verify_streaming::<H>(&standard_sig, &ring, message),
        "standard sig → streaming verify (ring_size={ring_size})"
    );

    // Key images must match (same secret key → same key image).
    assert_eq!(
        standard_sig.key_image().compress(),
        streaming_sig.key_image().compress(),
        "key images must match (ring_size={ring_size})"
    );

    // Wrong message must fail both verifiers.
    let wrong = b"wrong message";
    assert!(!BLSAG::verify::<H>(&streaming_sig, &ring, None, wrong));
    assert!(!BLSAG::verify_streaming::<H>(&streaming_sig, &ring, wrong));
}

#[test]
fn test_convenience_wrapper_equivalence_1() {
    assert_convenience_wrapper_equivalence::<Sha3_512>(1);
}

#[test]
fn test_convenience_wrapper_equivalence_10() {
    assert_convenience_wrapper_equivalence::<Sha3_512>(10);
}

#[test]
fn test_convenience_wrapper_equivalence_100() {
    assert_convenience_wrapper_equivalence::<Sha3_512>(100);
}

#[test]
fn test_convenience_wrapper_equivalence_sha512() {
    assert_convenience_wrapper_equivalence::<Sha512>(10);
}

#[cfg(feature = "blake3")]
#[test]
fn test_convenience_wrapper_equivalence_blake3() {
    assert_convenience_wrapper_equivalence::<Blake3_512>(10);
}

#[test]
fn test_streaming_validation_rejects_hash_suite_mismatch() {
    let keypairs: Vec<_> = (0..10).map(|i| keypair_from_seed(i as u8 + 1)).collect();
    let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
    let ring = Ring::new(public_keys);
    let mismatched_hash = ring.canonical_hash_with::<Sha3_512>();
    let mut signer = StreamingBlsagSigner::<Sha512, _>::new(ChaCha20Rng::from_seed([0xEE; 32]));

    signer
        .init_validation(ring.len(), mismatched_hash)
        .expect("init_validation");

    for (index, compressed) in ring.compressed_members().iter().enumerate() {
        let result = signer.validate_member(index, compressed);
        if index + 1 == ring.len() {
            assert!(matches!(
                result,
                Err(nazgul::blsag::streaming::StreamingError::RingHashMismatch)
            ));
        } else {
            assert!(matches!(result, Ok(StepOutput::Ack)));
        }
    }
}
