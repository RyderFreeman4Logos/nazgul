
use nazgul::blsag::BLSAG;
use nazgul::traits::{Link, Sign, Verify};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore, OsRng};
use sha2::Sha512;

// ==============
// HELPER FUNCTIONS
// ==============

// Generates a random private key and its corresponding public key.
fn generate_keypair<R: RngCore + CryptoRng>(csprng: &mut R) -> (Scalar, RistrettoPoint) {
    let private_key = Scalar::random(csprng);
    let public_key = private_key * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    (private_key, public_key)
}

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
    let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
    let secret_index = 3;
    let num_decoys = 10;

    let mut ring = generate_ring(&mut csprng, num_decoys);
    ring.insert(secret_index, signer_public_key);

    // We have to clone the private key because `sign` consumes it.
    let signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

    assert!(BLSAG::verify::<Sha512>(signature, MESSAGE));
}

#[test]
fn link_succeeds_for_same_signer() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
    let secret_index = 2;
    let num_decoys = 4;

    let mut ring1 = generate_ring(&mut csprng, num_decoys);
    ring1.insert(secret_index, signer_public_key);

    let mut ring2 = generate_ring(&mut csprng, num_decoys);
    ring2.insert(secret_index, signer_public_key);

    let message2: &[u8] = b"A different message for the second signature.";

    let signature1 = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring1, secret_index, MESSAGE);
    let signature2 = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring2, secret_index, message2);

    assert!(BLSAG::link(signature1, signature2));
}

#[test]
fn link_fails_for_different_signers() {
    let mut csprng = OsRng;

    // Signer 1
    let (private_key1, public_key1) = generate_keypair(&mut csprng);
    let mut ring1 = generate_ring(&mut csprng, 5);
    ring1.insert(1, public_key1);
    let signature1 = BLSAG::sign::<Sha512, OsRng>(private_key1.clone(), ring1, 1, MESSAGE);

    // Signer 2
    let (private_key2, public_key2) = generate_keypair(&mut csprng);
    let mut ring2 = generate_ring(&mut csprng, 5);
    ring2.insert(4, public_key2);
    let signature2 = BLSAG::sign::<Sha512, OsRng>(private_key2.clone(), ring2, 4, MESSAGE);

    assert!(!BLSAG::link(signature1, signature2));
}

// ==============
// FAILURE PATH TESTS
// ==============

#[test]
fn verify_fails_with_wrong_message() {
    let mut csprng = OsRng;
    let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
    let secret_index = 0;
    let mut ring = generate_ring(&mut csprng, 7);
    ring.insert(secret_index, signer_public_key);

    let signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

    let wrong_message: &[u8] = b"This is not the message you are looking for.";
    assert!(!BLSAG::verify::<Sha512>(signature, wrong_message));
}

// #[test]
// fn verify_fails_with_tampered_challenge() {
//     let mut csprng = OsRng;
//     let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
//     let secret_index = 1;
//     let mut ring = generate_ring(&mut csprng, 3);
//     ring.insert(secret_index, signer_public_key);

//     let mut signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

//     // Tamper with the challenge
//     signature.challenge = signature.challenge + Scalar::ONE;

//     assert!(!BLSAG::verify::<Sha512>(signature, MESSAGE));
// }

// #[test]
// fn verify_fails_with_tampered_response() {
//     let mut csprng = OsRng;
//     let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
//     let secret_index = 4;
//     let mut ring = generate_ring(&mut csprng, 5);
//     ring.insert(secret_index, signer_public_key);

//     let mut signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

//     // Tamper with one of the responses
//     signature.responses[2] = signature.responses[2] + Scalar::ONE;

//     assert!(!BLSAG::verify::<Sha512>(signature, MESSAGE));
// }

// #[test]
// fn verify_fails_with_different_ring() {
//     let mut csprng = OsRng;
//     let (signer_private_key, signer_public_key) = generate_keypair(&mut csprng);
//     let secret_index = 2;
//     let mut ring = generate_ring(&mut csprng, 6);
//     ring.insert(secret_index, signer_public_key);

//     let mut signature = BLSAG::sign::<Sha512, OsRng>(signer_private_key.clone(), ring, secret_index, MESSAGE);

//     // Create a completely different ring for verification
//     let mut different_ring = generate_ring(&mut csprng, 6);
//     different_ring.insert(secret_index, signer_public_key);
//     signature.ring = different_ring;

//     assert!(!BLSAG::verify::<Sha512>(signature, MESSAGE));
// }
