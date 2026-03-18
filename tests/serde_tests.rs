#![cfg(feature = "serde-derive")]

use nazgul::blsag::{ContextualBLSAG, BLSAG};
use nazgul::clsag::CLSAG;
use nazgul::keypair::KeyPair;
use nazgul::mlsag::MLSAG;
use nazgul::ring::{Ring, RingContext};
use nazgul::sag::SAG;
use nazgul::traits::{Sign, SignRef, Verify, VerifyRef};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::Sha512;

#[test]
fn test_sag_serde() {
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let secret_index = 1;
    let n = 2;
    let ring: Vec<RistrettoPoint> = (0..(n - 1))
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();
    let message: Vec<u8> = b"This is the message".iter().cloned().collect();

    let signature = SAG::sign::<Sha512, OsRng>(k, ring.clone(), secret_index, &message);

    // Serialize to JSON
    let serialized = serde_json::to_string(&signature).unwrap();

    // Deserialize from JSON
    let deserialized: SAG = serde_json::from_str(&serialized).unwrap();

    // Verify the deserialized signature works
    let result = SAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_blsag_serde() {
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

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: BLSAG = serde_json::from_str(&serialized).unwrap();

    let result = BLSAG::verify::<Sha512>(&deserialized, &ring, None, &message);
    assert!(result);
}

#[test]
fn test_clsag_serde() {
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

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: CLSAG = serde_json::from_str(&serialized).unwrap();

    let result = CLSAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_mlsag_serde() {
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

    let serialized = serde_json::to_string(&signature).unwrap();
    let deserialized: MLSAG = serde_json::from_str(&serialized).unwrap();

    let result = MLSAG::verify::<Sha512>(deserialized, &message);
    assert!(result);
}

#[test]
fn test_ring_serde_compressed_roundtrip() {
    let mut csprng = OsRng;
    let n = 5;
    let public_keys: Vec<RistrettoPoint> = (0..n)
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();

    let ring = Ring::new(public_keys.clone());
    let original_hash = ring.canonical_hash();

    // Serialize (always outputs compressed format)
    let serialized = serde_json::to_string(&ring).expect("Failed to serialize ring");

    // Deserialize produces Compressed variant
    let deserialized_ring: Ring =
        serde_json::from_str(&serialized).expect("Failed to deserialize ring");

    // Deserialized ring is auto-decompressed to Full state
    assert!(
        deserialized_ring.is_decompressed(),
        "Deserialized ring should be auto-decompressed to Full state"
    );

    // Canonical hash is preserved
    assert_eq!(
        original_hash,
        deserialized_ring.canonical_hash(),
        "Hash mismatch after serde roundtrip"
    );

    // Members match the original
    assert_eq!(
        ring.members(),
        deserialized_ring.members(),
        "Members mismatch after serde roundtrip"
    );
}

#[test]
fn test_ring_serde_consensus_hash_determinism() {
    let mut csprng = OsRng;
    let n = 5;
    let public_keys: Vec<RistrettoPoint> = (0..n)
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();

    let ring = Ring::new(public_keys.clone());
    let original_hash = ring.canonical_hash();

    // Different order input produces the same hash
    let mut shuffled_keys = public_keys;
    shuffled_keys.swap(0, 1);
    let ring_shuffled = Ring::new(shuffled_keys);

    assert_eq!(
        original_hash,
        ring_shuffled.canonical_hash(),
        "Consensus hash should be deterministic regardless of input order"
    );
}

#[test]
fn contextual_blsag_archival_verify_after_serde_roundtrip() {
    let mut csprng = OsRng;
    let signer = KeyPair::generate(&mut csprng);
    let mut public_keys: Vec<RistrettoPoint> = (0..4)
        .map(|_| *KeyPair::generate(&mut csprng).public())
        .collect();
    public_keys.push(*signer.public());
    let ring = Ring::new(public_keys);
    let message = b"Archival auto-decompress after serde";

    // Sign in Archival mode (stores full ring)
    let sig = ContextualBLSAG::sign_archival::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();

    // Serde roundtrip — ring inside Archival context becomes Compressed
    let json = serde_json::to_string(&sig).unwrap();
    let deserialized: ContextualBLSAG = serde_json::from_str(&json).unwrap();

    // Internal ring is auto-decompressed by serde Deserialize
    match &deserialized.context {
        RingContext::Archival(r) => assert!(
            r.is_decompressed(),
            "Internal ring should be auto-decompressed after serde roundtrip"
        ),
        _ => panic!("Expected Archival context after deserialization"),
    }

    // verify() should auto-decompress and succeed without caller intervention
    assert!(
        deserialized.verify::<Sha512>(None, None, message),
        "Archival verify must auto-decompress after serde roundtrip"
    );
}

#[test]
fn contextual_blsag_compact_verify_after_serde_roundtrip() {
    let mut csprng = OsRng;
    let signer = KeyPair::generate(&mut csprng);
    let mut public_keys: Vec<RistrettoPoint> = (0..4)
        .map(|_| *KeyPair::generate(&mut csprng).public())
        .collect();
    public_keys.push(*signer.public());
    let ring = Ring::new(public_keys);
    let message = b"Compact auto-decompress after serde";

    // Sign in Compact mode (stores only hash)
    let sig = ContextualBLSAG::sign_compact::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();

    // Serde roundtrip for the signature
    let sig_json = serde_json::to_string(&sig).unwrap();
    let deserialized_sig: ContextualBLSAG = serde_json::from_str(&sig_json).unwrap();

    // Serde roundtrip for the external ring — auto-decompressed
    let ring_json = serde_json::to_string(&ring).unwrap();
    let deserialized_ring: Ring = serde_json::from_str(&ring_json).unwrap();
    assert!(
        deserialized_ring.is_decompressed(),
        "External ring should be auto-decompressed after serde roundtrip"
    );

    // verify() should auto-decompress the external ring and succeed
    assert!(
        deserialized_sig.verify::<Sha512>(Some(&deserialized_ring), None, message),
        "Compact verify must auto-decompress external ring after serde roundtrip"
    );
}
