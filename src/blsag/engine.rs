//! Shared cryptographic helper functions used by both sign and verify paths.

#[cfg(any(not(feature = "optimized-msm"), test))]
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::ristretto::VartimeRistrettoPrecomputation;
use curve25519_dalek::scalar::Scalar;
#[cfg(any(not(feature = "optimized-msm"), test))]
use curve25519_dalek::traits::VartimeMultiscalarMul;
#[cfg(feature = "optimized-msm")]
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;

/// Private helper function to perform the core cryptographic hashing used in both
/// signing and verification. This prevents code duplication.
#[cfg(any(not(feature = "optimized-msm"), test))]
pub(super) fn hash_ring_member_components<H: Digest<OutputSize = U64> + Clone + Default>(
    message_hash: &H,
    response: Scalar,
    challenge: Scalar,
    public_key: RistrettoPoint,
    key_image: RistrettoPoint,
    precomputed_pk_hash: Option<RistrettoPoint>,
) -> Scalar {
    let mut h = message_hash.clone();
    h.update(
        RistrettoPoint::vartime_multiscalar_mul(
            &[response, challenge],
            &[constants::RISTRETTO_BASEPOINT_POINT, public_key],
        )
        .compress()
        .as_bytes(),
    );

    let pk_hash = precomputed_pk_hash.unwrap_or_else(|| {
        RistrettoPoint::from_hash(
            H::default()
                .chain_update(b"nazgul-H_p-v3")
                .chain_update(public_key.compress().as_bytes()),
        )
    });

    h.update(
        RistrettoPoint::vartime_multiscalar_mul(&[response, challenge], &[pk_hash, key_image])
            .compress()
            .as_bytes(),
    );
    Scalar::from_hash(h)
}

/// Optimized hash helper using specialized MSM routines.
///
/// For L: uses `vartime_double_scalar_mul_basepoint` (2-scalar with known basepoint).
/// For R: uses precomputed key_image table with `vartime_mixed_multiscalar_mul`.
#[cfg(feature = "optimized-msm")]
pub(super) fn hash_ring_member_optimized<H: Digest<OutputSize = U64> + Clone + Default>(
    message_hash: &H,
    response: Scalar,
    challenge: Scalar,
    public_key: RistrettoPoint,
    key_image_table: &VartimeRistrettoPrecomputation,
    precomputed_pk_hash: Option<RistrettoPoint>,
) -> Scalar {
    let mut h = message_hash.clone();

    // L = response * G + challenge * public_key
    // vartime_double_scalar_mul_basepoint(a, A, b) = a*A + b*G
    h.update(
        RistrettoPoint::vartime_double_scalar_mul_basepoint(&challenge, &public_key, &response)
            .compress()
            .as_bytes(),
    );

    let pk_hash = precomputed_pk_hash.unwrap_or_else(|| {
        RistrettoPoint::from_hash(
            H::default()
                .chain_update(b"nazgul-H_p-v3")
                .chain_update(public_key.compress().as_bytes()),
        )
    });

    // R = response * H_p(P) + challenge * key_image
    // vartime_mixed_multiscalar_mul(static_scalars, dynamic_scalars, dynamic_points)
    // where static_scalars correspond to the precomputed points (key_image),
    // and dynamic_scalars/points are for non-precomputed points (pk_hash).
    h.update(
        key_image_table
            .vartime_mixed_multiscalar_mul(&[challenge], &[response], &[pk_hash])
            .compress()
            .as_bytes(),
    );
    Scalar::from_hash(h)
}

///// Compute the chunk size for progress callbacks: ~10% of total, minimum 1.
pub(super) fn progress_chunk_size(total: usize) -> usize {
    (total / 10).max(1)
}
