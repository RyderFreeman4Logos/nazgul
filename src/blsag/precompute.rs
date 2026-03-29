//! Signing precomputation types for BLSAG.
//!
//! This module contains [`SigningPrecomputation`] and [`SecretScalar`], which
//! manage secret-bearing state and ring-binding security checks for the
//! message-independent precomputation workflow.

use super::ResponseVec;
use crate::ring::RingHash;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Message-independent precomputation for BLSAG signing.
///
/// Captures all nonce-derived values (`alpha`, `alpha*G`, `alpha*H_p`) and random
/// responses so that the actual signing step only needs the message. The struct is
/// move-consumed by [`sign_precomputed`](super::BLSAG::sign_precomputed) and the secret nonce `alpha` is
/// zeroized on drop.
///
/// # Security properties
///
/// * **Not `Clone`/`Copy`**: prevents nonce reuse.
/// * **Not `Debug`/`Serialize`/`Deserialize`**: prevents accidental leakage.
/// * **`ZeroizeOnDrop`**: secret scalars `alpha` and `secret_key` are erased
///   from memory when this value is dropped.
/// * **Ring binding**: stores a `RingHash` that is checked against the ring
///   supplied to `sign_precomputed` to prevent ring-switching attacks.
///
/// # Compile-time security constraints
///
/// `SigningPrecomputation` intentionally does **not** implement `Clone`, `Copy`,
/// or `Debug`. These doc-tests verify that as a compile-time guarantee.
///
/// ## Not `Clone`
///
/// Cloning would allow nonce reuse, which breaks the security of the scheme.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// let _copy = precomp.clone(); // ERROR: Clone is not implemented
/// ```
///
/// ## Not `Copy`
///
/// Copy semantics would defeat move-consumption and allow nonce reuse.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// fn takes_by_value(_p: SigningPrecomputation) {}
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// takes_by_value(precomp);
/// takes_by_value(precomp); // ERROR: use of moved value
/// ```
///
/// ## Not `Debug`
///
/// Debug formatting would risk leaking secret nonce material.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// println!("{:?}", precomp); // ERROR: Debug is not implemented
/// ```
///
/// ## Not `Serialize`
///
/// Serialization would allow persisting secret nonce material, enabling nonce
/// reuse across sessions.
///
/// ```compile_fail
/// use nazgul::blsag::{BLSAG, SigningPrecomputation};
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// fn requires_serialize<T: serde::Serialize>(_v: &T) {}
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// requires_serialize(&precomp); // ERROR: Serialize is not implemented
/// ```
///
/// ## Not `Deserialize`
///
/// Deserialization would allow reconstructing secret nonce material from
/// untrusted input, enabling nonce reuse.
///
/// ```compile_fail
/// use nazgul::blsag::SigningPrecomputation;
///
/// fn requires_deserialize<'de, T: serde::Deserialize<'de>>() {}
///
/// requires_deserialize::<SigningPrecomputation>(); // ERROR: Deserialize is not implemented
/// ```
///
/// ## Move-consumed by `sign_precomputed`
///
/// After calling `sign_precomputed`, the precomputation is consumed and cannot
/// be reused, preventing nonce reuse at the type-system level.
///
/// ```compile_fail
/// use nazgul::blsag::BLSAG;
/// use nazgul::keypair::KeyPair;
/// use nazgul::ring::Ring;
/// use rand_core::OsRng;
/// use sha2::Sha512;
///
/// let mut rng = OsRng;
/// let kp = KeyPair::generate(&mut rng);
/// let k = *kp.secret().unwrap();
/// let ring = Ring::new(vec![*kp.public()]);
/// let precomp = BLSAG::precompute_signing::<Sha512, _>(k, &ring, None, &mut rng).unwrap();
/// let _sig1 = BLSAG::sign_precomputed::<Sha512>(precomp, &ring, None, b"msg1");
/// let _sig2 = BLSAG::sign_precomputed::<Sha512>(precomp, &ring, None, b"msg2"); // ERROR: use of moved value
/// ```
pub struct SigningPrecomputation {
    /// Secret nonce (zeroized on drop via `SecretScalar`).
    pub(super) alpha: SecretScalar,
    /// `alpha * G` — the nonce commitment on the base point.
    pub(super) alpha_g: RistrettoPoint,
    /// `alpha * H_p(signer_pubkey)` — the nonce commitment on the hash-to-point.
    pub(super) alpha_hp: RistrettoPoint,
    /// Canonical hash of the ring used during precomputation.
    pub(super) ring_hash: RingHash,
    /// Position of the signer's public key in the sorted ring.
    pub(super) signer_index: usize,
    /// Key image (`k * H_p(K)`).
    pub(super) key_image: RistrettoPoint,
    /// Pre-generated random responses for every ring member.
    pub(super) responses: ResponseVec,
    /// The signer's secret key (zeroized on drop via `SecretScalar`).
    pub(super) secret_key: SecretScalar,
}

/// Wrapper around `Scalar` that zeroizes on drop.
///
/// `curve25519-dalek::Scalar` implements `Zeroize` when the `zeroize` feature
/// is enabled, so we delegate directly. The wrapper provides `Drop`-based
/// automatic zeroization without requiring the parent struct to implement
/// `Drop` (which would prevent field moves).
pub(super) struct SecretScalar(pub(super) Scalar);

impl Zeroize for SecretScalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretScalar {}
