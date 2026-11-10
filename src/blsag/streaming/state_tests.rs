use super::*;
use crate::ring::Ring;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::Sha512;
use std::cell::Cell;

std::thread_local! {
    static SECRET_DROPS: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn observe_zeroized_secret(scalar: &Scalar) {
    SECRET_DROPS.with(|count| {
        if let Some(previous) = count.get() {
            assert_eq!(*scalar, Scalar::ZERO, "secret must be erased before drop");
            count.set(Some(previous + 1));
        }
    });
}

struct DropWatch;

impl DropWatch {
    fn start() -> Self {
        SECRET_DROPS.with(|count| count.set(Some(0)));
        Self
    }

    fn count(&self) -> usize {
        SECRET_DROPS.with(|count| count.get().expect("watch is active"))
    }
}

impl Drop for DropWatch {
    fn drop(&mut self) {
        SECRET_DROPS.with(|count| count.set(None));
    }
}

type Signer = StreamingBlsagSigner<Sha512, ChaCha20Rng>;

fn ready_signer() -> (Signer, Ring, usize) {
    let public = constants::RISTRETTO_BASEPOINT_POINT;
    let ring = Ring::new(std::vec![public, Scalar::from(2u64) * public]);
    let index = ring
        .compressed_members()
        .iter()
        .position(|p| *p == public.compress())
        .unwrap();
    let mut signer = Signer::new(ChaCha20Rng::from_seed([17; 32]));
    signer
        .init_validation(ring.len(), ring.canonical_hash_with::<Sha512>())
        .unwrap();
    for (i, point) in ring.compressed_members().iter().enumerate() {
        signer.validate_member(i, point).unwrap();
    }
    signer
        .init_signing(index, Scalar::ONE, &public.compress(), b"state lifecycle")
        .unwrap();
    (signer, ring, index)
}

#[test]
fn completed_state_erases_both_secrets_and_releases_digest() {
    let (mut signer, ring, index) = ready_signer();
    let watch = DropWatch::start();
    let first = (index + 1) % ring.len();
    signer
        .sign_member(first, &ring.compressed_members()[first])
        .unwrap();
    assert_eq!(watch.count(), 0, "recoverable active state retains secrets");
    let output = signer
        .sign_member(index, &ring.compressed_members()[index])
        .unwrap();
    assert!(matches!(output, StepOutput::Complete { .. }));
    assert!(matches!(signer.state, State::Done));
    assert_eq!(watch.count(), 2);
    drop(signer);
    assert_eq!(
        watch.count(),
        2,
        "completed state retains no secret payload"
    );
}

#[test]
fn poisoned_state_erases_both_secrets_and_cannot_resume() {
    let (mut signer, ring, index) = ready_signer();
    let watch = DropWatch::start();
    let first = (index + 1) % ring.len();
    let replacement = (Scalar::from(3u64) * constants::RISTRETTO_BASEPOINT_POINT).compress();
    signer.sign_member(first, &replacement).unwrap();
    assert_eq!(watch.count(), 0);
    assert!(matches!(
        signer.sign_member(index, &ring.compressed_members()[index]),
        Err(StreamingError::RingSwitchDetected)
    ));
    assert!(matches!(signer.state, State::Poisoned));
    assert_eq!(watch.count(), 2);
    assert!(matches!(
        signer.init_validation(2, ring.canonical_hash_with::<Sha512>()),
        Err(StreamingError::InvalidState)
    ));
    drop(signer);
    assert_eq!(watch.count(), 2);
}

#[test]
fn dropping_active_state_erases_both_secrets() {
    let (signer, _, _) = ready_signer();
    let watch = DropWatch::start();
    drop(signer);
    assert_eq!(watch.count(), 2);
}

#[test]
fn recoverable_error_preserves_state_until_successful_retry() {
    let (mut signer, ring, index) = ready_signer();
    let watch = DropWatch::start();
    assert!(matches!(
        signer.sign_member(index, &ring.compressed_members()[index]),
        Err(StreamingError::OutOfOrder { .. })
    ));
    assert!(matches!(signer.state, State::Signing(_)));
    assert_eq!(watch.count(), 0);
    let first = (index + 1) % ring.len();
    signer
        .sign_member(first, &ring.compressed_members()[first])
        .unwrap();
    signer
        .sign_member(index, &ring.compressed_members()[index])
        .unwrap();
    assert_eq!(watch.count(), 2);
}
