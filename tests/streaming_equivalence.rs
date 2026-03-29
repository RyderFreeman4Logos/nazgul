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
use nazgul::blsag::streaming::{StepOutput, StreamingBlsagSigner};
use nazgul::blsag::{ContextualBLSAG, BLSAG};
use nazgul::ring::Ring;
use nazgul::traits::VerifyRef;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::Sha3_512;

/// Generate a deterministic keypair from a seed byte.
fn keypair_from_seed(seed: u8) -> (Scalar, curve25519_dalek::ristretto::RistrettoPoint) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sk = Scalar::random(&mut rng);
    let pk = sk * RISTRETTO_BASEPOINT_POINT;
    (sk, pk)
}

/// Run the full streaming-vs-standard equivalence check for a given ring size.
fn assert_streaming_math_equivalence(ring_size: usize) {
    // Generate deterministic keypairs. Signer is the first keypair.
    let keypairs: Vec<_> = (0..ring_size)
        .map(|i| keypair_from_seed(i as u8 + 1))
        .collect();
    let (secret_key, _) = keypairs[0];

    // Build the ring (Ring::new sorts by compressed bytes).
    let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
    let ring = Ring::new(public_keys);
    let ring_hash = ring.canonical_hash();

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
    let ctx_sig = ContextualBLSAG::sign_compact_with_rng::<Sha3_512, _>(
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
    let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(streaming_rng);

    // Phase 1: Validation
    signer
        .init_validation(ring.len(), ring_hash)
        .expect("init_validation");
    let compressed_members = ring.compressed_members();
    for i in 0..ring.len() {
        let result = signer
            .validate_member(i, &compressed_members[i])
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
        BLSAG::verify::<Sha3_512>(standard_sig, &ring, None, message),
        "standard signature must verify (ring_size={ring_size})"
    );
    assert!(
        BLSAG::verify::<Sha3_512>(&streaming_sig, &ring, None, message),
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
        !BLSAG::verify::<Sha3_512>(standard_sig, &ring, None, wrong_message),
        "standard sig must reject wrong message"
    );
    assert!(
        !BLSAG::verify::<Sha3_512>(&streaming_sig, &ring, None, wrong_message),
        "streaming sig must reject wrong message"
    );
}

#[test]
fn test_streaming_math_equivalence_1() {
    assert_streaming_math_equivalence(1);
}

#[test]
fn test_streaming_math_equivalence_10() {
    assert_streaming_math_equivalence(10);
}

#[test]
fn test_streaming_math_equivalence_100() {
    assert_streaming_math_equivalence(100);
}
