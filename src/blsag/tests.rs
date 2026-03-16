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

    let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring_a, None, &mut csprng).unwrap();

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

    let precomp_1 = BLSAG::precompute_signing::<Sha512, _>(k, &ring_1, None, &mut csprng).unwrap();
    let sig_1 = BLSAG::sign_precomputed::<Sha512>(precomp_1, &ring_1, None, b"msg1").unwrap();

    let precomp_2 = BLSAG::precompute_signing::<Sha512, _>(k, &ring_2, None, &mut csprng).unwrap();
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
