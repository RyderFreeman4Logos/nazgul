#![cfg(feature = "std")]
use nazgul::blsag::ContextualBLSAG;
use nazgul::keypair::KeyPair;
use nazgul::ring::{Ring, RingContext};

use curve25519_dalek::ristretto::RistrettoPoint;
use rand_core::OsRng;
use sha2::Sha512;
use sha3::Sha3_512;

fn setup_ring(n: usize) -> (Ring, KeyPair) {
    let mut csprng = OsRng;
    let signer_keypair = KeyPair::generate(&mut csprng);
    let mut public_keys: Vec<RistrettoPoint> = (0..n - 1)
        .map(|_| *KeyPair::generate(&mut csprng).public())
        .collect();
    public_keys.push(*signer_keypair.public());
    let ring = Ring::new(public_keys);
    (ring, signer_keypair)
}

#[test]
fn test_contextual_compact_workflow() {
    let (ring, signer) = setup_ring(5);
    let message = b"Compact Mode Test";

    // 1. Sign in Compact mode
    let sig = ContextualBLSAG::sign_compact::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();

    // Ensure it stored a Hash
    match sig.context {
        RingContext::Compact(_) => {}
        _ => panic!("Expected Compact context"),
    }

    // 2. Verify with correct external ring -> Should Pass
    assert!(sig.verify::<Sha512>(Some(&ring), None, message));

    // 3. Verify without external ring -> Should Fail
    assert!(!sig.verify::<Sha512>(None, None, message));

    // 4. Verify with WRONG external ring -> Should Fail
    let (wrong_ring, _) = setup_ring(5);
    assert!(!sig.verify::<Sha512>(Some(&wrong_ring), None, message));
}

#[test]
fn test_contextual_archival_workflow() {
    let (ring, signer) = setup_ring(5);
    let message = b"Archival Mode Test";

    // 1. Sign in Archival mode
    let sig = ContextualBLSAG::sign_archival::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();

    // Ensure it stored a Ring
    match sig.context {
        RingContext::Archival(_) => {}
        _ => panic!("Expected Archival context"),
    }

    // 2. Verify without external ring -> Should Pass (Self-contained)
    assert!(sig.verify::<Sha512>(None, None, message));

    // 3. Verify with matching external ring -> Should Pass
    assert!(sig.verify::<Sha512>(Some(&ring), None, message));

    // 4. Verify with mismatching external ring -> Should Fail (Enforced check)
    let (wrong_ring, _) = setup_ring(5);
    assert!(!sig.verify::<Sha512>(Some(&wrong_ring), None, message));
}

#[test]
fn test_contextual_compact_rejects_hash_suite_mismatch() {
    let (ring, signer) = setup_ring(5);
    let message = b"Compact Hash Suite Mismatch";

    let sig = ContextualBLSAG::sign_compact::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();

    assert!(
        sig.verify::<Sha512>(Some(&ring), None, message),
        "matching hash suite must verify"
    );
    assert!(
        !sig.verify::<Sha3_512>(Some(&ring), None, message),
        "mismatched hash suite must be rejected"
    );
}

#[test]
fn test_contextual_canonical_hash_is_representation_invariant() {
    let (ring, signer) = setup_ring(5);
    let message = b"Context Canonical Hash Stability";

    let compact = ContextualBLSAG::sign_compact::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();
    let archival = ContextualBLSAG::sign_archival::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();

    assert_eq!(
        compact.context().canonical_hash(),
        archival.context().canonical_hash(),
        "default canonical hash must be stable across compact and archival contexts"
    );
    assert_eq!(
        compact.context().canonical_hash_with::<Sha512>(),
        archival.context().canonical_hash_with::<Sha512>(),
        "context view must expose the selected suite hash consistently"
    );
    assert_eq!(
        compact.context().selected_compact_hash(),
        Some(archival.context().canonical_hash_with::<Sha512>()),
        "compact metadata must retain the selected suite hash"
    );
}

#[cfg(feature = "serde-derive")]
#[test]
fn test_contextual_serde() {
    let (ring, signer) = setup_ring(3);
    let message = b"Serde Test";

    // Compact
    let compact_sig = ContextualBLSAG::sign_compact::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();
    let compact_json = serde_json::to_string(&compact_sig).unwrap();
    let compact_deserialized: ContextualBLSAG = serde_json::from_str(&compact_json).unwrap();
    assert!(compact_deserialized.verify::<Sha512>(Some(&ring), None, message));

    // Archival
    let archival_sig = ContextualBLSAG::sign_archival::<Sha512, OsRng>(
        *signer.secret().unwrap(),
        &ring,
        None,
        message,
    )
    .unwrap();
    let archival_json = serde_json::to_string(&archival_sig).unwrap();
    let archival_deserialized: ContextualBLSAG = serde_json::from_str(&archival_json).unwrap();
    // Verify self-contained
    assert!(archival_deserialized.verify::<Sha512>(None, None, message));
}
