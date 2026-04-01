use alloc::vec::Vec;

use crate::blsag::BLSAG;
use crate::clsag::CLSAG;
use crate::keypair::KeyPair;
use crate::mlsag::MLSAG;
use crate::ring::Ring;
use crate::sag::SAG;
use crate::traits::{Link, LinkRef, LocalByteConvertible, Sign, SignRef, Verify, VerifyRef};
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

    let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
    let signature2 = BLSAG::sign::<Sha512, OsRng>(k, &ring, None, &another_message).unwrap();
    let link_result = BLSAG::link(&signature, &signature2);
    assert!(link_result);
}

#[test]
fn test_clsag_no_std() {
    let mut csprng = OsRng;
    let secret_index = 1;
    let nr = 2;
    let nc = 2;
    let ks: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();
    let ring: Vec<Vec<RistrettoPoint>> = (0..(nr - 1))
        .map(|_| {
            (0..nc)
                .map(|_| RistrettoPoint::random(&mut csprng))
                .collect()
        })
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = CLSAG::sign::<Sha512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
    let result = CLSAG::verify::<Sha512>(signature.clone(), &message);
    assert!(result);

    let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
    let signature2 = CLSAG::sign::<Sha512, OsRng>(ks, ring.clone(), secret_index, &another_message);
    let link_result = CLSAG::link(signature, signature2);
    assert!(link_result);
}

#[test]
fn test_mlsag_no_std() {
    let mut csprng = OsRng;
    let secret_index = 1;
    let nr = 2;
    let nc = 2;
    let ks: Vec<Scalar> = (0..nc).map(|_| Scalar::random(&mut csprng)).collect();
    let ring: Vec<Vec<RistrettoPoint>> = (0..(nr - 1))
        .map(|_| {
            (0..nc)
                .map(|_| RistrettoPoint::random(&mut csprng))
                .collect()
        })
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = MLSAG::sign::<Sha512, OsRng>(ks.clone(), ring.clone(), secret_index, &message);
    let result = MLSAG::verify::<Sha512>(signature.clone(), &message);
    assert!(result);

    let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
    let signature2 = MLSAG::sign::<Sha512, OsRng>(ks, ring.clone(), secret_index, &another_message);
    let link_result = MLSAG::link(signature, signature2);
    assert!(link_result);
}

#[test]
fn test_scalar_roundtrip_no_std() {
    let mut csprng = OsRng;
    let original_scalar = Scalar::random(&mut csprng);
    let original_point = RistrettoPoint::random(&mut csprng);

    let scalar_bytes = original_scalar.to_bytes();
    let scalar_roundtrip = Scalar::from_bytes(&scalar_bytes).unwrap();
    assert_eq!(original_scalar, scalar_roundtrip);

    let scalar_base58 = original_scalar.to_base58();
    let scalar_base58_roundtrip = Scalar::from_base58(scalar_base58).unwrap();
    assert_eq!(original_scalar, scalar_base58_roundtrip);

    let point_bytes = original_point.to_bytes();
    let point_roundtrip = RistrettoPoint::from_bytes(&point_bytes).unwrap();
    assert_eq!(original_point, point_roundtrip);

    let point_base58 = original_point.to_base58();
    let point_base58_roundtrip = RistrettoPoint::from_base58(point_base58).unwrap();
    assert_eq!(original_point, point_base58_roundtrip);

    assert!(Scalar::from_bytes(&[0u8; 31]).is_err());
    assert!(RistrettoPoint::from_bytes(&[255u8; 32]).is_err());
}

#[test]
fn test_keypair_roundtrip_no_std() {
    let mut csprng = OsRng;
    let original_keypair = KeyPair::generate(&mut csprng);

    let bytes = original_keypair.to_bytes();
    let from_bytes = KeyPair::from_bytes(&bytes).unwrap();
    assert_eq!(original_keypair.to_bytes(), from_bytes.to_bytes());

    let base58 = original_keypair.to_base58();
    let from_base58 = KeyPair::from_base58(base58).unwrap();
    assert_eq!(original_keypair.to_bytes(), from_base58.to_bytes());

    assert!(KeyPair::from_bytes(&[0u8; 31]).is_err());
}

#[test]
fn test_ring_canonical_hash_no_std() {
    let mut csprng = OsRng;
    let points: Vec<RistrettoPoint> = (0..4)
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();

    let full_ring = Ring::new(points);
    let compressed_ring = Ring::from_compressed(full_ring.compressed_members().to_vec());

    assert_eq!(full_ring.canonical_hash(), compressed_ring.canonical_hash());
    assert_eq!(
        full_ring.canonical_hash_with::<Sha512>(),
        compressed_ring.canonical_hash_with::<Sha512>()
    );
}
