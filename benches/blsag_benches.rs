use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use nazgul::blsag::BLSAG;
use nazgul::ring::Ring;
use nazgul::traits::{SignRef, VerifyRef};
use rand_core::OsRng;
use sha2::Sha512;
use std::time::Duration;

const RING_SIZES: &[usize] = &[2, 8, 32, 128, 512, 2_000];

/// Build a ring with `ring_size` members and return the signer's private key.
fn setup_ring(ring_size: usize) -> (Scalar, Ring) {
    let mut csprng = OsRng;
    let signer_private_key = Scalar::random(&mut csprng);
    let signer_public_key =
        signer_private_key * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    let mut public_keys: Vec<RistrettoPoint> = (0..ring_size - 1)
        .map(|_| RistrettoPoint::random(&mut csprng))
        .collect();

    public_keys.push(signer_public_key);
    let ring = Ring::new(public_keys);

    (signer_private_key, ring)
}

fn blsag_sign_benchmark(c: &mut Criterion) {
    let message: &[u8] = b"This is a benchmark message.";

    let mut group = c.benchmark_group("blsag_sign");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    for &size in RING_SIZES {
        let (private_key, ring) = setup_ring(size);

        group.bench_with_input(BenchmarkId::new("no_precomp", size), &ring, |b, r| {
            b.iter(|| BLSAG::sign::<Sha512, OsRng>(private_key, r, None, message).unwrap());
        });

        let precomputed = ring.precompute::<Sha512>();
        group.bench_with_input(BenchmarkId::new("precomp", size), &ring, |b, r| {
            b.iter(|| {
                BLSAG::sign::<Sha512, OsRng>(private_key, r, Some(&precomputed), message).unwrap()
            });
        });
    }

    group.finish();
}

fn blsag_verify_benchmark(c: &mut Criterion) {
    let message: &[u8] = b"This is a benchmark message.";

    let mut group = c.benchmark_group("blsag_verify");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    for &size in RING_SIZES {
        let (private_key, ring) = setup_ring(size);
        let signature = BLSAG::sign::<Sha512, OsRng>(private_key, &ring, None, message).unwrap();

        group.bench_with_input(BenchmarkId::new("no_precomp", size), &ring, |b, r| {
            b.iter(|| BLSAG::verify::<Sha512>(&signature, r, None, message));
        });

        let precomputed = ring.precompute::<Sha512>();
        group.bench_with_input(BenchmarkId::new("precomp", size), &ring, |b, r| {
            b.iter(|| BLSAG::verify::<Sha512>(&signature, r, Some(&precomputed), message));
        });
    }

    group.finish();
}

criterion_group!(benches, blsag_sign_benchmark, blsag_verify_benchmark);
criterion_main!(benches);
