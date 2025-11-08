#![no_std]
#![cfg(feature = "no_std")]

extern crate alloc;

use alloc::vec::Vec;
use nazgul::blsag::BLSAG;
use nazgul::ring::Ring;
use nazgul::sag::SAG;
use nazgul::traits::{Link, LinkRef, Sign, SignRef, Verify, VerifyRef};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::Sha512;

#[test]
fn test_sag_no_std() {
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let secret_index = 1;
    let n = 2;
    let ring: Vec<RistrettoPoint> = (0..(n - 1))
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = SAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);
    let result = SAG::verify::<Sha512>(signature, &message);
    assert!(result);
}

#[test]
fn test_blsag_no_std() {
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let k_point: RistrettoPoint = k * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let n = 2;
    let mut public_keys: Vec<RistrettoPoint> = (0..(n - 1))
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();
    public_keys.push(k_point);
    let ring = Ring::new(public_keys);
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, &message).unwrap();
    let result = BLSAG::verify::<Sha512>(&signature, &ring, None, &message);
    assert!(result);

    // Test linking
    let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
    let signature2 = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, &another_message).unwrap();
    let link_result = BLSAG::link(&signature, &signature2);
    assert!(link_result);
}
