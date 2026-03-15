use nazgul::blsag::BLSAG;
use nazgul::error::SignatureError;
use nazgul::keypair::KeyPair;
use nazgul::ring::Ring;
use nazgul::traits::{LinkRef, SignRef, VerifyRef};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha512;

// ==============
// HELPER FUNCTIONS
// ==============

// Generates a ring of random public keys.
fn generate_ring<R: RngCore + CryptoRng>(csprng: &mut R, num_decoys: usize) -> Vec<RistrettoPoint> {
    (0..num_decoys)
        .map(|_| RistrettoPoint::random(csprng))
        .collect()
}

const MESSAGE: &[u8] = b"The owls are not what they seem.";

// ==============
// CORE FUNCTIONALITY TESTS
// ==============

#[test]
fn sign_and_verify_succeeds() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();
    let num_decoys = 10;

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);

    let signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring, None, MESSAGE).unwrap();

    assert!(BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE));
}

#[test]
fn link_succeeds_for_same_signer() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();
    let num_decoys = 4;

    let mut public_keys1 = generate_ring(&mut csprng, num_decoys);
    public_keys1.push(signer_public_key);
    let ring1 = Ring::new(public_keys1);

    let mut public_keys2 = generate_ring(&mut csprng, num_decoys);
    public_keys2.push(signer_public_key);
    let ring2 = Ring::new(public_keys2);

    let message2: &[u8] = b"A different message for the second signature.";

    let signature1 =
        BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring1, None, MESSAGE).unwrap();
    let signature2 =
        BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring2, None, message2).unwrap();

    assert!(BLSAG::link(&signature1, &signature2));
}

#[test]
fn link_fails_for_different_signers() {
    let mut csprng = OsRng;

    // Signer 1
    let (private_key1, public_key1) = KeyPair::generate(&mut csprng).into_keys();
    let private_key1 = private_key1.unwrap();
    let mut public_keys1 = generate_ring(&mut csprng, 5);
    public_keys1.push(public_key1);
    let ring1 = Ring::new(public_keys1);
    let signature1 = BLSAG::sign::<Sha512, OsRng>(private_key1, &ring1, None, MESSAGE).unwrap();

    // Signer 2
    let (private_key2, public_key2) = KeyPair::generate(&mut csprng).into_keys();
    let private_key2 = private_key2.unwrap();
    let mut public_keys2 = generate_ring(&mut csprng, 5);
    public_keys2.push(public_key2);
    let ring2 = Ring::new(public_keys2);
    let signature2 = BLSAG::sign::<Sha512, OsRng>(private_key2, &ring2, None, MESSAGE).unwrap();

    assert!(!BLSAG::link(&signature1, &signature2));
}

// ==============
// FAILURE PATH TESTS
// ==============

#[test]
fn verify_fails_with_wrong_message() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();
    let num_decoys = 7;

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);

    let signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring, None, MESSAGE).unwrap();

    let wrong_message: &[u8] = b"This is not the message you are looking for.";
    assert!(!BLSAG::verify::<Sha512>(
        &signature,
        &ring,
        None,
        wrong_message
    ));
}

// ==============
// SECURITY PROPERTY TESTS
// ==============

#[test]
fn sign_fails_if_signer_not_in_ring() {
    // Unforgeability Test: An attacker without a valid private key from the ring
    // should not be able to create a signature.
    let mut csprng = OsRng;
    let (attacker_private_key, _) = KeyPair::generate(&mut csprng).into_keys();
    let attacker_private_key = attacker_private_key.unwrap();
    let num_decoys = 10;

    // The ring is composed entirely of decoys; the attacker's public key is not included.
    let decoys = generate_ring(&mut csprng, num_decoys);
    let ring = Ring::new(decoys);

    // This call should fail because the public key corresponding to the private key
    // is not present in the ring.
    let result = BLSAG::sign::<Sha512, OsRng>(attacker_private_key, &ring, None, MESSAGE);
    assert!(matches!(result, Err(SignatureError::SignerNotFound)));
}

#[test]
fn verify_succeeds_for_every_ring_member() {
    // Anonymity Test: A signature should be valid regardless of the signer's
    // position in the ring, demonstrating signer ambiguity.
    let mut csprng = OsRng;
    let num_members = 5;

    // Create a set of keypairs for the ring members.
    let keypairs: Vec<KeyPair> = (0..num_members)
        .map(|_| KeyPair::generate(&mut csprng))
        .collect();

    let public_keys: Vec<RistrettoPoint> =
        keypairs.iter().map(|keypair| *keypair.public()).collect();
    let ring = Ring::new(public_keys);

    // Iterate through each member, have them sign, and verify the signature.
    for keypair in keypairs.iter() {
        let signature =
            BLSAG::sign::<Sha512, OsRng>(*keypair.secret().unwrap(), &ring, None, MESSAGE).unwrap();
        assert!(
            BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE),
            "Verification failed for a valid signer from the ring"
        );
    }
}

#[test]
fn link_succeeds_for_same_signer_with_different_rings() {
    // Linkability Test: Two signatures from the same signer must be linkable,
    // even if the decoy sets (rings) are completely different.
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();

    // Create two different rings, but both contain the signer's public key.
    let mut public_keys1 = generate_ring(&mut csprng, 7);
    public_keys1.push(signer_public_key);
    let ring1 = Ring::new(public_keys1);

    let mut public_keys2 = generate_ring(&mut csprng, 10);
    public_keys2.push(signer_public_key);
    let ring2 = Ring::new(public_keys2);

    let message1: &[u8] = b"First message.";
    let message2: &[u8] = b"Second message.";

    let signature1 =
        BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring1, None, message1).unwrap();
    let signature2 =
        BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring2, None, message2).unwrap();

    assert!(
        BLSAG::link(&signature1, &signature2),
        "Linking failed for the same signer with different decoy rings."
    );
}

#[test]
fn sign_and_verify_with_precomputation_succeeds() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();
    let num_decoys = 50; // Use a slightly larger ring to make precomputation more meaningful

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);

    // 1. Generate and verify the precomputed data
    let precomputed_data = ring.precompute::<Sha512>();
    assert!(precomputed_data.verify::<Sha512>(&ring));

    // 2. Sign using the precomputed data
    let signature =
        BLSAG::sign::<Sha512, OsRng>(signer_private_key, &ring, Some(&precomputed_data), MESSAGE)
            .unwrap();

    // 3. Verify the signature using the precomputed data
    assert!(
        BLSAG::verify::<Sha512>(&signature, &ring, Some(&precomputed_data), MESSAGE),
        "Verification with precomputation failed"
    );

    // 4. Verify the same signature WITHOUT the precomputed data
    assert!(
        BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE),
        "Verification without precomputation failed for a signature created with it"
    );

    // 5. Verify that incorrect precomputed data fails
    let other_ring = Ring::new(generate_ring(&mut csprng, num_decoys + 1));
    let bad_precomputed_data = other_ring.precompute::<Sha512>();
    assert!(
        !precomputed_data.verify::<Sha512>(&other_ring),
        "Verification of precomputed data should fail for the wrong ring"
    );
    assert!(
        !BLSAG::verify::<Sha512>(&signature, &ring, Some(&bad_precomputed_data), MESSAGE),
        "Verification should fail with incorrect precomputed data"
    );
}

#[test]
fn fake_signature_fails_verification() {
    let mut csprng = OsRng;
    let num_decoys = 10;
    // Note: We don't need a signer key here, just a ring of random keys.
    let public_keys = generate_ring(&mut csprng, num_decoys);
    let ring = Ring::new(public_keys);

    let signature = BLSAG::generate_fake::<OsRng>(&ring);

    // Verify should fail
    assert!(!BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE));
}

// Helper: create a deterministic ring + signer from a seeded RNG.
// Returns (signer_private_key, ring, rng) with the RNG ready for signing.
fn deterministic_ring_and_signer() -> (Scalar, Ring, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut rng).into_keys();
    let signer_private_key = signer_private_key.unwrap();
    let num_decoys = 3;
    let mut public_keys = generate_ring(&mut rng, num_decoys);
    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);
    (signer_private_key, ring, rng)
}

// ==============
// GOLDEN VECTOR TEST
// ==============

#[test]
fn golden_vector_deterministic_signature() {
    let (signer_private_key, ring, mut rng) = deterministic_ring_and_signer();

    let signature = BLSAG::sign_with_rng::<Sha512, ChaCha20Rng>(
        signer_private_key,
        &ring,
        None,
        MESSAGE,
        &mut rng,
    )
    .unwrap();

    assert!(BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE));

    // Frozen golden values from ChaCha20Rng(seed=42)
    let expected_challenge: [u8; 32] = [
        7, 210, 88, 111, 130, 146, 45, 246, 211, 249, 40, 71, 53, 255, 91, 141, 79, 148, 106, 53,
        238, 53, 9, 63, 66, 86, 237, 24, 199, 162, 47, 15,
    ];
    let expected_key_image: [u8; 32] = [
        178, 28, 233, 188, 154, 108, 58, 91, 230, 6, 43, 125, 204, 142, 66, 74, 121, 72, 176, 86,
        16, 7, 21, 82, 34, 60, 78, 48, 9, 48, 15, 109,
    ];
    let expected_responses: [[u8; 32]; 4] = [
        [
            207, 25, 112, 51, 255, 76, 31, 216, 57, 64, 239, 87, 223, 48, 163, 58, 166, 132, 169,
            203, 71, 179, 61, 170, 12, 34, 148, 228, 14, 131, 210, 2,
        ],
        [
            11, 183, 251, 74, 78, 113, 169, 51, 185, 156, 193, 133, 46, 205, 72, 100, 152, 12, 199,
            37, 111, 224, 84, 115, 66, 99, 216, 152, 103, 77, 82, 3,
        ],
        [
            150, 87, 253, 166, 65, 77, 200, 50, 202, 215, 12, 63, 176, 82, 150, 200, 206, 202, 59,
            217, 77, 30, 174, 199, 140, 202, 83, 180, 162, 190, 128, 13,
        ],
        [
            163, 94, 190, 155, 113, 219, 56, 147, 136, 36, 111, 76, 55, 72, 80, 191, 24, 224, 159,
            239, 227, 248, 180, 57, 229, 36, 0, 52, 165, 242, 223, 3,
        ],
    ];

    assert_eq!(
        signature.challenge().as_bytes(),
        &expected_challenge,
        "Challenge mismatch: golden vector regression"
    );
    assert_eq!(
        signature.key_image().compress().as_bytes(),
        &expected_key_image,
        "Key image mismatch: golden vector regression"
    );
    assert_eq!(signature.responses().len(), 4);
    for (i, r) in signature.responses().iter().enumerate() {
        assert_eq!(
            r.as_bytes(),
            &expected_responses[i],
            "Response[{i}] mismatch: golden vector regression"
        );
    }
}

// ==============
// TAMPER REJECTION TESTS
// ==============

#[test]
fn verify_fails_with_tampered_challenge() {
    let (signer_private_key, ring, mut rng) = deterministic_ring_and_signer();

    let signature = BLSAG::sign_with_rng::<Sha512, ChaCha20Rng>(
        signer_private_key,
        &ring,
        None,
        MESSAGE,
        &mut rng,
    )
    .unwrap();

    // Tamper: add Scalar::ONE to the challenge
    let tampered = BLSAG::from_parts(
        signature.challenge() + Scalar::ONE,
        signature.responses().to_vec(),
        *signature.key_image(),
    );

    assert!(
        !BLSAG::verify::<Sha512>(&tampered, &ring, None, MESSAGE),
        "Verification must fail when challenge is tampered"
    );
}

#[test]
fn verify_fails_with_tampered_response() {
    let (signer_private_key, ring, mut rng) = deterministic_ring_and_signer();

    let signature = BLSAG::sign_with_rng::<Sha512, ChaCha20Rng>(
        signer_private_key,
        &ring,
        None,
        MESSAGE,
        &mut rng,
    )
    .unwrap();

    // Tamper: mutate one response scalar
    let mut tampered_responses = signature.responses().to_vec();
    tampered_responses[1] = tampered_responses[1] + Scalar::ONE;

    let tampered = BLSAG::from_parts(
        *signature.challenge(),
        tampered_responses,
        *signature.key_image(),
    );

    assert!(
        !BLSAG::verify::<Sha512>(&tampered, &ring, None, MESSAGE),
        "Verification must fail when a response is tampered"
    );
}

#[test]
fn verify_fails_with_swapped_ring_member() {
    let (signer_private_key, ring, mut rng) = deterministic_ring_and_signer();

    let signature = BLSAG::sign_with_rng::<Sha512, ChaCha20Rng>(
        signer_private_key,
        &ring,
        None,
        MESSAGE,
        &mut rng,
    )
    .unwrap();

    // Create a different ring: replace the first decoy with a random point
    let mut tampered_members = ring.members().to_vec();
    let replacement = RistrettoPoint::random(&mut rng);
    tampered_members[0] = replacement;
    let tampered_ring = Ring::new(tampered_members);

    assert!(
        !BLSAG::verify::<Sha512>(&signature, &tampered_ring, None, MESSAGE),
        "Verification must fail when a ring member is swapped"
    );
}

#[test]
fn verify_fails_with_wrong_key_image() {
    let (signer_private_key, ring, mut rng) = deterministic_ring_and_signer();

    let signature = BLSAG::sign_with_rng::<Sha512, ChaCha20Rng>(
        signer_private_key,
        &ring,
        None,
        MESSAGE,
        &mut rng,
    )
    .unwrap();

    // Tamper: use a random point as key image
    let wrong_key_image = RistrettoPoint::random(&mut rng);

    let tampered = BLSAG::from_parts(
        *signature.challenge(),
        signature.responses().to_vec(),
        wrong_key_image,
    );

    assert!(
        !BLSAG::verify::<Sha512>(&tampered, &ring, None, MESSAGE),
        "Verification must fail with a wrong key image"
    );
}

// ==============
// SIGNING PRECOMPUTATION TESTS
// ==============

#[test]
fn precomputed_signing_cross_validates_with_standard_verify() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();
    let num_decoys = 10;

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);

    // Phase 1: precompute (message-independent)
    let precomp =
        BLSAG::precompute_signing::<Sha512, _>(signer_private_key, &ring, None, &mut csprng)
            .unwrap();

    // Phase 2: sign with message
    let signature = BLSAG::sign_precomputed::<Sha512>(precomp, &ring, None, MESSAGE).unwrap();

    // Phase 3: standard verify must accept the signature
    assert!(
        BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE),
        "Standard verify must accept a signature produced via precomputed signing"
    );

    // Also verify with precomputed ring data
    let ring_data = ring.precompute::<Sha512>();
    assert!(
        BLSAG::verify::<Sha512>(&signature, &ring, Some(&ring_data), MESSAGE),
        "Verify with precomputed ring data must also accept the signature"
    );
}

#[test]
fn precomputed_signing_rejects_ring_mismatch() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();

    // Ring A: used for precomputation
    let mut public_keys_a = generate_ring(&mut csprng, 5);
    public_keys_a.push(signer_public_key);
    let ring_a = Ring::new(public_keys_a);

    // Ring B: different ring (signer is still present, but different decoys)
    let mut public_keys_b = generate_ring(&mut csprng, 5);
    public_keys_b.push(signer_public_key);
    let ring_b = Ring::new(public_keys_b);

    // Precompute with ring A
    let precomp =
        BLSAG::precompute_signing::<Sha512, _>(signer_private_key, &ring_a, None, &mut csprng)
            .unwrap();

    // Attempt to sign with ring B -> must fail with RingMismatch
    let err = BLSAG::sign_precomputed::<Sha512>(precomp, &ring_b, None, MESSAGE)
        .expect_err("sign_precomputed must reject a ring that differs from precomputation");
    assert_eq!(err, SignatureError::RingMismatch);
}

#[test]
fn precomputed_signing_with_ring_data_cross_validates() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();
    let num_decoys = 8;

    let mut public_keys = generate_ring(&mut csprng, num_decoys);
    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);
    let ring_data = ring.precompute::<Sha512>();

    // Precompute with ring data
    let precomp = BLSAG::precompute_signing::<Sha512, _>(
        signer_private_key,
        &ring,
        Some(&ring_data),
        &mut csprng,
    )
    .unwrap();

    // Sign with ring data
    let signature =
        BLSAG::sign_precomputed::<Sha512>(precomp, &ring, Some(&ring_data), MESSAGE).unwrap();

    // Verify without ring data (most strict cross-validation)
    assert!(
        BLSAG::verify::<Sha512>(&signature, &ring, None, MESSAGE),
        "Signature from precomputed path with ring data must verify without ring data"
    );
}

#[test]
fn precomputed_signing_linkability() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = KeyPair::generate(&mut csprng).into_keys();
    let signer_private_key = signer_private_key.unwrap();

    // Two different rings, same signer
    let mut pks_1 = generate_ring(&mut csprng, 4);
    pks_1.push(signer_public_key);
    let ring_1 = Ring::new(pks_1);

    let mut pks_2 = generate_ring(&mut csprng, 6);
    pks_2.push(signer_public_key);
    let ring_2 = Ring::new(pks_2);

    let precomp_1 =
        BLSAG::precompute_signing::<Sha512, _>(signer_private_key, &ring_1, None, &mut csprng)
            .unwrap();
    let sig_1 = BLSAG::sign_precomputed::<Sha512>(precomp_1, &ring_1, None, b"message 1").unwrap();

    let precomp_2 =
        BLSAG::precompute_signing::<Sha512, _>(signer_private_key, &ring_2, None, &mut csprng)
            .unwrap();
    let sig_2 = BLSAG::sign_precomputed::<Sha512>(precomp_2, &ring_2, None, b"message 2").unwrap();

    assert!(
        BLSAG::link(&sig_1, &sig_2),
        "Precomputed signatures from the same signer must be linkable"
    );
}
