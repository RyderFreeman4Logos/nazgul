//! Allocator-free streaming BLSAG signer for memory-constrained devices.
//!
//! [`StreamingBlsagSigner`] implements a two-phase protocol that receives ring members
//! one at a time, producing signature components incrementally with O(1) memory.
//!
//! # Two-phase protocol
//!
//! **Phase 1 — Validation**: Ring members are fed in canonical order (0..N-1) to
//! compute a running ring hash. After all members are submitted, the hash is compared
//! against the expected value provided at initialization.
//!
//! **Phase 2 — Signing**: Ring members are fed in signing order (pi+1, pi+2, ..., N-1,
//! 0, 1, ..., pi). Each non-signer member produces a response scalar `s_i` immediately.
//! The final member (the signer at index pi) produces the closing challenge `c_0`, the
//! key image, and the signer's response scalar.
//!
//! # Algorithm compatibility
//!
//! The output is mathematically identical to [`BLSAG::sign_with_rng`](super::BLSAG::sign_with_rng)
//! and verifies with the standard `BLSAG` verification path.

use crate::ring::RingHash;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use sha3::Sha3_512;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Errors specific to the streaming signing protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingError {
    /// A member was submitted at an unexpected index.
    OutOfOrder { expected: usize, got: usize },
    /// A compressed point failed Ristretto decompression (not on curve).
    InvalidPoint,
    /// The ring hash computed during validation does not match the expected value.
    RingHashMismatch,
    /// Attempted to start signing before validation completed.
    ValidationNotComplete,
    /// The state machine is in an unexpected state for the requested operation.
    InvalidState,
    /// Ring length must be at least 1.
    EmptyRing,
    /// The secret key does not correspond to the ring member at the signer index.
    IdentityMismatch,
    /// Phase 2 ring members do not match Phase 1 validated ring (ring-switch detected).
    RingSwitchDetected,
}

impl core::fmt::Display for StreamingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StreamingError::OutOfOrder { expected, got } => {
                write!(
                    f,
                    "out-of-order member: expected index {expected}, got {got}"
                )
            }
            StreamingError::InvalidPoint => write!(f, "compressed point failed decompression"),
            StreamingError::RingHashMismatch => write!(f, "ring hash mismatch after validation"),
            StreamingError::ValidationNotComplete => {
                write!(f, "signing requires completed validation")
            }
            StreamingError::InvalidState => write!(f, "operation not valid in current state"),
            StreamingError::EmptyRing => write!(f, "ring length must be at least 1"),
            StreamingError::IdentityMismatch => {
                write!(f, "secret key does not match ring member at signer index")
            }
            StreamingError::RingSwitchDetected => {
                write!(f, "phase 2 ring does not match phase 1 validated ring")
            }
        }
    }
}

/// Output produced by each step of the streaming signing protocol.
#[derive(Debug, Clone)]
pub enum StepOutput {
    /// Acknowledgement that a validation-phase member was accepted.
    Ack,
    /// A response scalar produced for a non-signer ring member during signing.
    ScalarResponse {
        /// The ring index this response belongs to.
        index: usize,
        /// The random response scalar `s_i`.
        s_i: Scalar,
    },
    /// The final output completing the ring signature.
    Complete {
        /// The initial challenge scalar `c_0`.
        c_0: Scalar,
        /// The signer's key image `I`.
        key_image: RistrettoPoint,
        /// The signer's response scalar `s_{pi}`.
        signer_s: Scalar,
        /// The signer's ring index.
        signer_index: usize,
    },
}

/// Secret scalar wrapper with zeroize on drop (matches existing pattern in sign.rs).
struct SecretScalar(Scalar);

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Order-independent ring binding for streaming anti-switch detection.
///
/// Uses a 512-bit XOR accumulator of indexed per-member SHA3-512 hashes.
/// Each ring member contributes the full 64-byte output of
/// `SHA3-512("nazgul-ring-bind-v2" || index_le64 || compressed)` via XOR.
///
/// # Why this is separate from [`RingHash`]
///
/// [`RingHash`] is the canonical, public ring identity — a sequential
/// `SHA3-512(m_0 || m_1 || … || m_{N-1})` truncated to 32 bytes. Its
/// collision resistance (~2^128) is independent of ring size.
///
/// This binding serves a different purpose: detecting ring-switch attacks
/// between Phase 1 (canonical order) and Phase 2 (signing order) of the
/// streaming protocol. Because Phase 2 delivers members in a different
/// order, an order-*independent* accumulator is required. XOR-of-hashes
/// is the simplest O(1)-memory scheme that achieves this.
///
/// Using 512 bits (the full SHA3-512 output) provides GBP resistance of
/// `2^{512 / (1 + ⌊log₂ k⌋)}` where k is the number of attacker-controlled
/// positions — ≥ 2^128 for rings up to 16 members, ≥ 2^73 for rings
/// up to 64 members.
///
/// [`RingHash`]: crate::ring::RingHash
#[derive(Clone, Copy, PartialEq, Eq)]
struct RingBinding([u8; 64]);

impl RingBinding {
    fn new() -> Self {
        RingBinding([0u8; 64])
    }

    /// Absorb a ring member at position `index` into the accumulator.
    fn accumulate(&mut self, index: usize, compressed: &CompressedRistretto) {
        let hash = Sha3_512::new()
            .chain_update(b"nazgul-ring-bind-v2")
            .chain_update((index as u64).to_le_bytes())
            .chain_update(compressed.as_bytes())
            .finalize();
        for (acc, h) in self.0.iter_mut().zip(hash.iter()) {
            *acc ^= h;
        }
    }
}

// ---------------------------------------------------------------------------
// State machine internals
// ---------------------------------------------------------------------------

/// Validation-phase state: accumulates ring hash from members in order 0..N-1.
struct Validating {
    ring_len: usize,
    expected_ring_hash: RingHash,
    hasher: Sha3_512,
    members_seen: usize,
    /// Order-independent accumulator binding Phase 1 ring to Phase 2.
    ring_binding: RingBinding,
}

/// State after validation is complete and ring hash verified.
struct Validated {
    ring_len: usize,
    /// Order-independent binding computed during Phase 1.
    ring_binding: RingBinding,
}

/// State after key image and initial nonce commitment are computed.
/// Ready to receive ring members in signing order.
struct Signing<H: Digest<OutputSize = U64> + Clone + Default> {
    ring_len: usize,
    signer_index: usize,
    message_hash: H,
    key_image: RistrettoPoint,
    /// Current challenge being chained through the ring.
    c_current: Scalar,
    /// The challenge `c_0` is captured when index N-1 is processed.
    c_0: Scalar,
    /// Alpha nonce (secret, zeroized on drop).
    alpha: SecretScalar,
    /// Secret key (zeroized on drop).
    secret_key: SecretScalar,
    /// Derived signer public key (secret_key * G), stored for ring-membership
    /// verification during Phase 2.
    derived_signer_compressed: CompressedRistretto,
    /// How many signing members have been submitted.
    sign_step: usize,
    /// Phase 1 ring binding (expected).
    expected_ring_binding: RingBinding,
    /// Phase 2 ring binding (accumulated from streamed members).
    ring_binding: RingBinding,
}

enum State<H: Digest<OutputSize = U64> + Clone + Default> {
    Idle,
    Validating(Validating),
    Validated(Validated),
    Signing(Signing<H>),
    Done,
    /// Poisoned state after an error or move.
    Poisoned,
}

/// Allocator-free streaming BLSAG signer.
///
/// Generic over `H` (hash function, e.g. `Sha3_512`) and `R` (RNG source).
/// The RNG is used to generate the nonce `alpha` and the random response
/// scalars for non-signer members.
pub struct StreamingBlsagSigner<
    H: Digest<OutputSize = U64> + Clone + Default,
    R: CryptoRng + RngCore,
> {
    state: State<H>,
    rng: R,
}

impl<H: Digest<OutputSize = U64> + Clone + Default, R: CryptoRng + RngCore>
    StreamingBlsagSigner<H, R>
{
    /// Creates a new streaming signer in the Idle state.
    pub fn new(rng: R) -> Self {
        Self {
            state: State::Idle,
            rng,
        }
    }

    /// Phase 1, Step 1: Initialize the validation pass.
    ///
    /// `ring_len` is the total number of ring members. `expected_ring_hash` is the
    /// canonical ring hash that the running computation must match after all members
    /// are submitted.
    pub fn init_validation(
        &mut self,
        ring_len: usize,
        expected_ring_hash: RingHash,
    ) -> Result<(), StreamingError> {
        if !matches!(self.state, State::Idle) {
            return Err(StreamingError::InvalidState);
        }
        if ring_len == 0 {
            return Err(StreamingError::EmptyRing);
        }

        self.state = State::Validating(Validating {
            ring_len,
            expected_ring_hash,
            hasher: Sha3_512::default(),
            members_seen: 0,
            ring_binding: RingBinding::new(),
        });

        Ok(())
    }

    /// Phase 1, Step 2: Submit a ring member for validation.
    ///
    /// Members must be submitted in canonical sorted order (index 0, 1, ..., N-1).
    /// Each compressed point is validated by attempting Ristretto decompression.
    pub fn validate_member(
        &mut self,
        index: usize,
        compressed: &CompressedRistretto,
    ) -> Result<StepOutput, StreamingError> {
        let validating = match &mut self.state {
            State::Validating(v) => v,
            _ => return Err(StreamingError::InvalidState),
        };

        // Enforce sequential order.
        if index != validating.members_seen {
            return Err(StreamingError::OutOfOrder {
                expected: validating.members_seen,
                got: index,
            });
        }

        // Duplicate check: if index < members_seen, it's a duplicate.
        // (Covered by the order check above since index must equal members_seen.)

        // Validate point is on the Ristretto curve.
        if compressed.decompress().is_none() {
            return Err(StreamingError::InvalidPoint);
        }

        // Feed compressed bytes into the running ring hash (SHA3-512, same as Ring::canonical_hash).
        validating.hasher.update(compressed.as_bytes());

        // Accumulate into order-independent ring binding (Phase 1→Phase 2 anti-switch).
        validating.ring_binding.accumulate(index, compressed);

        validating.members_seen += 1;

        // Check if validation is complete.
        if validating.members_seen == validating.ring_len {
            // Finalize the ring hash.
            // We need to take ownership of the validating state to finalize the hasher.
            let old_state = core::mem::replace(&mut self.state, State::Poisoned);
            let validating = match old_state {
                State::Validating(v) => v,
                _ => unreachable!(),
            };

            let output = validating.hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&output[..32]);
            let computed_hash = RingHash(hash_bytes);

            if computed_hash != validating.expected_ring_hash {
                self.state = State::Idle;
                return Err(StreamingError::RingHashMismatch);
            }

            self.state = State::Validated(Validated {
                ring_len: validating.ring_len,
                ring_binding: validating.ring_binding,
            });
        }

        Ok(StepOutput::Ack)
    }

    /// Phase 2, Step 1: Initialize the signing pass.
    ///
    /// `signer_index` is the position of the signer's public key in the sorted ring (0-based).
    /// `secret_key` is the signer's private scalar.
    /// `signer_pubkey_compressed` is the signer's public key (must match `secret_key * G`).
    /// `message` is the message being signed.
    ///
    /// This computes the key image `I`, the nonce `alpha`, and the initial challenge
    /// `c_{pi+1}` from the nonce commitments.
    pub fn init_signing(
        &mut self,
        signer_index: usize,
        secret_key: Scalar,
        signer_pubkey_compressed: &CompressedRistretto,
        message: &[u8],
    ) -> Result<(), StreamingError> {
        let validated = match &self.state {
            State::Validated(v) => v,
            State::Idle | State::Validating(_) => {
                return Err(StreamingError::ValidationNotComplete)
            }
            _ => return Err(StreamingError::InvalidState),
        };

        if signer_index >= validated.ring_len {
            return Err(StreamingError::OutOfOrder {
                expected: validated.ring_len.saturating_sub(1),
                got: signer_index,
            });
        }

        // Verify the secret key corresponds to the claimed signer public key.
        // This mirrors the SignerNotFound check in the one-shot BLSAG::sign.
        let derived_pubkey = (secret_key * constants::RISTRETTO_BASEPOINT_POINT).compress();
        if derived_pubkey.as_bytes().ct_eq(signer_pubkey_compressed.as_bytes()).unwrap_u8() == 0 {
            return Err(StreamingError::IdentityMismatch);
        }

        let ring_len = validated.ring_len;
        let expected_ring_binding = validated.ring_binding;

        // Decompress the signer's public key for Hp computation.
        let signer_pubkey = signer_pubkey_compressed
            .decompress()
            .ok_or(StreamingError::InvalidPoint)?;

        let k = SecretScalar(secret_key);

        // Key image: I = k * Hp(P_pi)
        let hp_signer = RistrettoPoint::from_hash(
            H::default()
                .chain_update(b"nazgul-H_p-v3")
                .chain_update(signer_pubkey.compress().as_bytes()),
        );
        let key_image = k.0 * hp_signer;

        // Generate nonce alpha.
        let alpha = SecretScalar(Scalar::random(&mut self.rng));

        // Compute nonce commitments: alpha*G and alpha*Hp(P_pi).
        let alpha_g = alpha.0 * constants::RISTRETTO_BASEPOINT_POINT;
        let alpha_hp = alpha.0 * hp_signer;

        // Message hash prefix (shared by all challenge computations).
        let mut message_hash = H::default();
        message_hash.update(b"nazgul-chal-v3");
        message_hash.update(message);

        // Compute c_{pi+1} = H(message_hash || alpha*G || alpha*Hp(P_pi))
        let mut h = message_hash.clone();
        h.update(alpha_g.compress().as_bytes());
        h.update(alpha_hp.compress().as_bytes());
        let c_plus_1 = Scalar::from_hash(h);

        // If signer is the last member (pi == N-1), then c_0 = c_{pi+1}.
        let c_0 = if signer_index == ring_len - 1 {
            c_plus_1
        } else {
            Scalar::ZERO
        };

        self.state = State::Signing(Signing {
            ring_len,
            signer_index,
            message_hash,
            key_image,
            c_current: c_plus_1,
            c_0,
            alpha,
            secret_key: k,
            derived_signer_compressed: derived_pubkey,
            sign_step: 0,
            expected_ring_binding,
            ring_binding: RingBinding::new(),
        });

        Ok(())
    }

    /// Phase 2, Step 2: Submit a ring member for signing.
    ///
    /// Members must be submitted in signing order: starting from index `(pi+1) % N`,
    /// wrapping around, and ending at index `pi` (the signer).
    ///
    /// For non-signer members, returns `StepOutput::ScalarResponse` with the generated `s_i`.
    /// For the final member (the signer), returns `StepOutput::Complete`.
    pub fn sign_member(
        &mut self,
        index: usize,
        compressed: &CompressedRistretto,
    ) -> Result<StepOutput, StreamingError> {
        // We need mutable access to the signing state.
        let signing = match &mut self.state {
            State::Signing(s) => s,
            _ => return Err(StreamingError::InvalidState),
        };

        let ring_len = signing.ring_len;
        let signer_index = signing.signer_index;
        let total_steps = ring_len; // N total members to process (N-1 non-signer + 1 signer)

        // Expected index in the signing order: (pi+1+step) % N
        let expected_index = (signer_index + 1 + signing.sign_step) % ring_len;
        if index != expected_index {
            return Err(StreamingError::OutOfOrder {
                expected: expected_index,
                got: index,
            });
        }

        // Validate the point.
        let point = compressed
            .decompress()
            .ok_or(StreamingError::InvalidPoint)?;

        // Accumulate into Phase 2 ring binding (order-independent).
        signing.ring_binding.accumulate(index, compressed);

        let is_signer_step = signing.sign_step == total_steps - 1;

        if is_signer_step {
            // Verify Phase 2 ring matches Phase 1 validated ring (anti-switch).
            // All N members have now been accumulated — compare the XOR accumulators.
            if signing.ring_binding != signing.expected_ring_binding {
                self.state = State::Poisoned;
                return Err(StreamingError::RingSwitchDetected);
            }

            // Verify the ring member at signer_index matches the derived pubkey.
            // This closes the gap between init_signing (which verified sk*G == claimed pk)
            // and the actual ring: the member delivered here during Phase 2 MUST equal
            // the pubkey we derived from the secret key.
            if compressed
                .as_bytes()
                .ct_eq(signing.derived_signer_compressed.as_bytes())
                .unwrap_u8()
                == 0
            {
                self.state = State::Poisoned;
                return Err(StreamingError::IdentityMismatch);
            }

            // This is the signer's own slot (index == pi).
            // Compute s_pi = alpha - c_current * k.
            let s_pi = signing.alpha.0 - (signing.c_current * signing.secret_key.0);

            let c_0 = signing.c_0;
            let key_image = signing.key_image;

            // Transition to Done.
            self.state = State::Done;

            Ok(StepOutput::Complete {
                c_0,
                key_image,
                signer_s: s_pi,
                signer_index,
            })
        } else {
            // Non-signer member: generate random s_i, compute next challenge.
            let s_i = Scalar::random(&mut self.rng);

            // Compute the next challenge inline (same math as engine::hash_ring_member_components).
            // L = s_i * G + c_current * P_i
            let l_point = RistrettoPoint::vartime_double_scalar_mul_basepoint(
                &signing.c_current,
                &point,
                &s_i,
            );

            // Hp(P_i) — hash-to-point for this member.
            let hp_i = RistrettoPoint::from_hash(
                H::default()
                    .chain_update(b"nazgul-H_p-v3")
                    .chain_update(point.compress().as_bytes()),
            );

            // R = s_i * Hp(P_i) + c_current * I
            let r_point = s_i * hp_i + signing.c_current * signing.key_image;

            let mut h = signing.message_hash.clone();
            h.update(l_point.compress().as_bytes());
            h.update(r_point.compress().as_bytes());
            let next_challenge = Scalar::from_hash(h);

            signing.c_current = next_challenge;
            signing.sign_step += 1;

            // Capture c_0 when we process index N-1.
            if index == ring_len - 1 {
                signing.c_0 = signing.c_current;
            }

            Ok(StepOutput::ScalarResponse { index, s_i })
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming BLSAG Verifier
// ---------------------------------------------------------------------------

/// Output produced by each step of the streaming verification protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStepOutput {
    /// Acknowledgement that an intermediate ring member was processed.
    Ack,
    /// Final result after the last ring member has been processed.
    Complete {
        /// Whether the reconstructed challenge matches `c_0`.
        valid: bool,
    },
}

/// State tag for the streaming verifier (no data, avoids large-enum-variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifierPhase {
    Idle,
    Verifying,
    Done,
}

/// Allocator-free streaming BLSAG verifier.
///
/// Receives ring members one at a time alongside their response scalars,
/// recomputing the challenge chain incrementally with O(1) memory. After
/// the final member, reports whether the signature is valid.
///
/// # Algorithm
///
/// Given signature `(c_0, s_0..s_{n-1}, key_image I)`, message `m`,
/// ring `{P_0..P_{n-1}}`:
///
/// ```text
/// For i = 0 to n-1:
///   L_i = s_i * G + c_i * P_i
///   R_i = s_i * Hp(P_i) + c_i * I
///   c_{i+1} = H(m || L_i || R_i)
/// Verify: c_n == c_0
/// ```
pub struct StreamingBlsagVerifier<H: Digest<OutputSize = U64> + Clone + Default> {
    phase: VerifierPhase,
    ring_len: usize,
    /// The original `c_0` to check against after traversing the full ring.
    c_0: Scalar,
    /// The current challenge being chained through the ring.
    c_current: Scalar,
    /// Key image point (decompressed once at init).
    key_image: RistrettoPoint,
    /// Precomputed message hash prefix: `H("nazgul-chal-v3" || message)`.
    message_hash: H,
    /// Number of members processed so far.
    members_verified: usize,
}

impl<H: Digest<OutputSize = U64> + Clone + Default> StreamingBlsagVerifier<H> {
    /// Creates a new streaming verifier in the Idle state.
    pub fn new() -> Self {
        Self {
            phase: VerifierPhase::Idle,
            ring_len: 0,
            c_0: Scalar::ZERO,
            c_current: Scalar::ZERO,
            key_image: constants::RISTRETTO_BASEPOINT_POINT,
            message_hash: H::default(),
            members_verified: 0,
        }
    }

    /// Initialize the verification pass.
    ///
    /// - `c_0`: the initial challenge from the signature.
    /// - `key_image`: the compressed key image from the signature.
    /// - `message`: the signed message.
    /// - `ring_len`: number of ring members.
    ///
    /// Returns `Err` if `key_image` fails decompression or `ring_len` is zero.
    pub fn init(
        &mut self,
        c_0: Scalar,
        key_image: &CompressedRistretto,
        message: &[u8],
        ring_len: usize,
    ) -> Result<(), StreamingError> {
        if self.phase != VerifierPhase::Idle {
            return Err(StreamingError::InvalidState);
        }
        if ring_len == 0 {
            return Err(StreamingError::EmptyRing);
        }
        let ki = key_image.decompress().ok_or(StreamingError::InvalidPoint)?;

        self.ring_len = ring_len;
        self.c_0 = c_0;
        self.c_current = c_0;
        self.key_image = ki;
        self.message_hash = H::default()
            .chain_update(b"nazgul-chal-v3")
            .chain_update(message);
        self.members_verified = 0;
        self.phase = VerifierPhase::Verifying;

        Ok(())
    }

    /// Submit a ring member with its response scalar for verification.
    ///
    /// Members must be submitted in order: index 0, 1, ..., N-1.
    ///
    /// For intermediate members (i < N-1), returns `VerifyStepOutput::Ack`.
    /// For the final member (i == N-1), returns `VerifyStepOutput::Complete { valid }`.
    pub fn verify_member(
        &mut self,
        index: usize,
        member: &CompressedRistretto,
        s_i: Scalar,
    ) -> Result<VerifyStepOutput, StreamingError> {
        if self.phase != VerifierPhase::Verifying {
            return Err(StreamingError::InvalidState);
        }

        // Enforce sequential order.
        if index != self.members_verified {
            return Err(StreamingError::OutOfOrder {
                expected: self.members_verified,
                got: index,
            });
        }

        // Decompress the ring member point.
        let point = member.decompress().ok_or(StreamingError::InvalidPoint)?;

        // L_i = s_i * G + c_i * P_i
        let l_point =
            RistrettoPoint::vartime_double_scalar_mul_basepoint(&self.c_current, &point, &s_i);

        // Hp(P_i) = hash-to-point
        let hp_i = RistrettoPoint::from_hash(
            H::default()
                .chain_update(b"nazgul-H_p-v3")
                .chain_update(member.as_bytes()),
        );

        // R_i = s_i * Hp(P_i) + c_i * I
        let r_point = s_i * hp_i + self.c_current * self.key_image;

        // c_{i+1} = H(message_hash || L_i || R_i)
        let mut h = self.message_hash.clone();
        h.update(l_point.compress().as_bytes());
        h.update(r_point.compress().as_bytes());
        let next_challenge = Scalar::from_hash(h);

        self.c_current = next_challenge;
        self.members_verified += 1;

        // Check if this was the last member.
        if self.members_verified == self.ring_len {
            let valid = self.c_current == self.c_0;
            self.phase = VerifierPhase::Done;
            Ok(VerifyStepOutput::Complete { valid })
        } else {
            Ok(VerifyStepOutput::Ack)
        }
    }
}

impl<H: Digest<OutputSize = U64> + Clone + Default> Default for StreamingBlsagVerifier<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::blsag::BLSAG;
    use crate::ring::Ring;
    use crate::traits::{SignRef, VerifyRef};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sha3::Sha3_512;

    /// Helper: generate a deterministic keypair from a seed byte.
    fn keypair_from_seed(seed: u8) -> (Scalar, RistrettoPoint) {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let sk = Scalar::random(&mut rng);
        let pk = sk * RISTRETTO_BASEPOINT_POINT;
        (sk, pk)
    }

    /// Run the streaming signer and verify the result against standard BLSAG verification.
    fn streaming_sign_and_verify(ring_size: usize) {
        // Generate keypairs.
        let keypairs: Vec<(Scalar, RistrettoPoint)> = (0..ring_size)
            .map(|i| keypair_from_seed(i as u8 + 1))
            .collect();

        let signer_idx_in_keypairs = 0; // First keypair is the signer.
        let (secret_key, _signer_pk) = keypairs[signer_idx_in_keypairs];

        // Build the ring (sorted).
        let public_keys: Vec<RistrettoPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let ring = Ring::new(public_keys);
        let ring_hash = ring.canonical_hash();

        // Find the signer's index in the sorted ring.
        let signer_pk: RistrettoPoint = secret_key * RISTRETTO_BASEPOINT_POINT;
        let signer_index = ring
            .members()
            .iter()
            .position(|p| p.compress() == signer_pk.compress())
            .expect("signer must be in ring");

        let message = b"streaming test message";

        // --- Streaming signer ---
        let streaming_rng = ChaCha20Rng::from_seed([0xBB; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(streaming_rng);

        // Phase 1: Validation.
        signer
            .init_validation(ring.len(), ring_hash)
            .expect("init_validation");

        let compressed_members = ring.compressed_members();
        for i in 0..ring.len() {
            let result = signer
                .validate_member(i, &compressed_members[i])
                .expect("validate_member");
            assert!(matches!(result, StepOutput::Ack));
        }

        // Phase 2: Signing.
        signer
            .init_signing(signer_index, secret_key, &signer_pk.compress(), message)
            .expect("init_signing");

        let n = ring.len();
        let mut responses = vec![Scalar::ZERO; n];
        let mut final_c0 = Scalar::ZERO;
        let mut final_key_image = RISTRETTO_BASEPOINT_POINT; // placeholder
        let ring_members = ring.members();

        for step in 0..n {
            let idx = (signer_index + 1 + step) % n;
            let result = signer
                .sign_member(idx, &ring_members[idx].compress())
                .expect("sign_member");

            match result {
                StepOutput::ScalarResponse { index, s_i } => {
                    responses[index] = s_i;
                }
                StepOutput::Complete {
                    c_0,
                    key_image,
                    signer_s,
                    signer_index: si,
                } => {
                    final_c0 = c_0;
                    final_key_image = key_image;
                    responses[si] = signer_s;
                }
                StepOutput::Ack => panic!("unexpected Ack during signing"),
            }
        }

        // Construct the BLSAG signature from streaming outputs.
        let signature = BLSAG::from_parts(final_c0, responses, final_key_image);

        // Verify using standard verification.
        let valid = BLSAG::verify::<Sha3_512>(&signature, &ring, None, message);
        assert!(
            valid,
            "streaming signature must verify with standard BLSAG verifier"
        );
    }

    #[test]
    fn test_streaming_ring_size_1() {
        streaming_sign_and_verify(1);
    }

    #[test]
    fn test_streaming_ring_size_2() {
        streaming_sign_and_verify(2);
    }

    #[test]
    fn test_streaming_ring_size_3() {
        streaming_sign_and_verify(3);
    }

    #[test]
    fn test_streaming_ring_size_10() {
        streaming_sign_and_verify(10);
    }

    #[test]
    fn test_error_out_of_order_validation() {
        let ring_rng = ChaCha20Rng::from_seed([0xCC; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(ring_rng);

        let keypairs: Vec<(Scalar, RistrettoPoint)> =
            (0..3).map(|i| keypair_from_seed(i + 10)).collect();
        let public_keys: Vec<RistrettoPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let ring = Ring::new(public_keys);
        let ring_hash = ring.canonical_hash();

        signer.init_validation(3, ring_hash).unwrap();

        let compressed = ring.compressed_members();
        // Submit index 0 correctly.
        signer.validate_member(0, &compressed[0]).unwrap();
        // Skip index 1, submit index 2 — should fail.
        let err = signer.validate_member(2, &compressed[2]).unwrap_err();
        assert_eq!(
            err,
            StreamingError::OutOfOrder {
                expected: 1,
                got: 2
            }
        );
    }

    #[test]
    fn test_error_invalid_compressed_point() {
        let rng = ChaCha20Rng::from_seed([0xDD; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        signer.init_validation(1, RingHash([0u8; 32])).unwrap();

        // All 0xFF bytes is not a valid Ristretto point.
        let invalid = CompressedRistretto::from_slice(&[0xFF; 32]).unwrap();
        let err = signer.validate_member(0, &invalid).unwrap_err();
        assert_eq!(err, StreamingError::InvalidPoint);
    }

    #[test]
    fn test_error_duplicate_index_validation() {
        let rng = ChaCha20Rng::from_seed([0xEE; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        let (_, pk) = keypair_from_seed(42);
        let ring = Ring::new(vec![pk]);
        let ring_hash = ring.canonical_hash();

        signer.init_validation(1, ring_hash).unwrap();

        let compressed = ring.compressed_members();
        signer.validate_member(0, &compressed[0]).unwrap();

        // Submitting index 0 again — but state already transitioned to Validated,
        // so this is an InvalidState.
        let err = signer.validate_member(0, &compressed[0]).unwrap_err();
        assert_eq!(err, StreamingError::InvalidState);
    }

    #[test]
    fn test_error_ring_hash_mismatch() {
        let rng = ChaCha20Rng::from_seed([0xFF; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        let (_, pk) = keypair_from_seed(50);
        let ring = Ring::new(vec![pk]);

        // Use a wrong expected hash.
        let wrong_hash = RingHash([0x42; 32]);
        signer.init_validation(1, wrong_hash).unwrap();

        let compressed = ring.compressed_members();
        let err = signer.validate_member(0, &compressed[0]).unwrap_err();
        assert_eq!(err, StreamingError::RingHashMismatch);
    }

    #[test]
    fn test_error_signing_before_validation() {
        let rng = ChaCha20Rng::from_seed([0x11; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        let (sk, pk) = keypair_from_seed(60);
        let err = signer
            .init_signing(0, sk, &pk.compress(), b"msg")
            .unwrap_err();
        assert_eq!(err, StreamingError::ValidationNotComplete);
    }

    #[test]
    fn test_error_out_of_order_signing() {
        let keypairs: Vec<(Scalar, RistrettoPoint)> =
            (0..3).map(|i| keypair_from_seed(i + 70)).collect();
        let public_keys: Vec<RistrettoPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let ring = Ring::new(public_keys);
        let ring_hash = ring.canonical_hash();
        let compressed = ring.compressed_members();
        let members = ring.members();

        let (secret_key, _) = keypairs[0];
        let signer_pk: RistrettoPoint = secret_key * RISTRETTO_BASEPOINT_POINT;
        let signer_index = members
            .iter()
            .position(|p| p.compress() == signer_pk.compress())
            .unwrap();

        let rng = ChaCha20Rng::from_seed([0x22; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        signer.init_validation(3, ring_hash).unwrap();
        for i in 0..3 {
            signer.validate_member(i, &compressed[i]).unwrap();
        }

        signer
            .init_signing(signer_index, secret_key, &signer_pk.compress(), b"test")
            .unwrap();

        // First expected index is (signer_index + 1) % 3.
        let expected_first = (signer_index + 1) % 3;
        // Submit a wrong index.
        let wrong_index = (signer_index + 2) % 3;
        if wrong_index != expected_first {
            let err = signer
                .sign_member(wrong_index, &members[wrong_index].compress())
                .unwrap_err();
            assert!(
                matches!(err, StreamingError::OutOfOrder { .. }),
                "expected OutOfOrder, got {:?}",
                err
            );
        }
    }

    #[test]
    fn test_error_empty_ring() {
        let rng = ChaCha20Rng::from_seed([0x33; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        let err = signer.init_validation(0, RingHash([0u8; 32])).unwrap_err();
        assert_eq!(err, StreamingError::EmptyRing);
    }

    #[test]
    fn test_signing_invalid_point_during_signing() {
        // Set up a valid ring and complete validation, then pass an invalid point during signing.
        let (sk, pk) = keypair_from_seed(80);
        let ring = Ring::new(vec![pk, keypair_from_seed(81).1]);
        let ring_hash = ring.canonical_hash();
        let compressed = ring.compressed_members();
        let members = ring.members();

        let signer_pk = sk * RISTRETTO_BASEPOINT_POINT;
        let signer_index = members
            .iter()
            .position(|p| p.compress() == signer_pk.compress())
            .unwrap();

        let rng = ChaCha20Rng::from_seed([0x44; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        signer.init_validation(2, ring_hash).unwrap();
        for i in 0..2 {
            signer.validate_member(i, &compressed[i]).unwrap();
        }

        signer
            .init_signing(signer_index, sk, &signer_pk.compress(), b"test")
            .unwrap();

        let first_sign_idx = (signer_index + 1) % 2;
        let invalid = CompressedRistretto::from_slice(&[0xFF; 32]).unwrap();
        let err = signer.sign_member(first_sign_idx, &invalid).unwrap_err();
        assert_eq!(err, StreamingError::InvalidPoint);
    }

    // =======================================================================
    // StreamingBlsagVerifier tests
    // =======================================================================

    /// Helper: sign with the streaming signer, then verify with the streaming verifier.
    fn streaming_sign_then_streaming_verify(ring_size: usize) {
        let keypairs: Vec<(Scalar, RistrettoPoint)> = (0..ring_size)
            .map(|i| keypair_from_seed(i as u8 + 1))
            .collect();

        let signer_idx_in_keypairs = 0;
        let (secret_key, _) = keypairs[signer_idx_in_keypairs];

        let public_keys: Vec<RistrettoPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let ring = Ring::new(public_keys);
        let ring_hash = ring.canonical_hash();

        let signer_pk = secret_key * RISTRETTO_BASEPOINT_POINT;
        let signer_index = ring
            .members()
            .iter()
            .position(|p| p.compress() == signer_pk.compress())
            .expect("signer must be in ring");

        let message = b"streaming verifier test message";

        // --- Sign with streaming signer ---
        let streaming_rng = ChaCha20Rng::from_seed([0xAA; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(streaming_rng);

        signer
            .init_validation(ring.len(), ring_hash)
            .expect("init_validation");

        let compressed_members = ring.compressed_members();
        for i in 0..ring.len() {
            signer
                .validate_member(i, &compressed_members[i])
                .expect("validate_member");
        }

        signer
            .init_signing(signer_index, secret_key, &signer_pk.compress(), message)
            .expect("init_signing");

        let n = ring.len();
        let mut responses = vec![Scalar::ZERO; n];
        let mut final_c0 = Scalar::ZERO;
        let mut final_key_image = RISTRETTO_BASEPOINT_POINT;
        let ring_members = ring.members();

        for step in 0..n {
            let idx = (signer_index + 1 + step) % n;
            let result = signer
                .sign_member(idx, &ring_members[idx].compress())
                .expect("sign_member");

            match result {
                StepOutput::ScalarResponse { index, s_i } => {
                    responses[index] = s_i;
                }
                StepOutput::Complete {
                    c_0,
                    key_image,
                    signer_s,
                    signer_index: si,
                } => {
                    final_c0 = c_0;
                    final_key_image = key_image;
                    responses[si] = signer_s;
                }
                StepOutput::Ack => panic!("unexpected Ack during signing"),
            }
        }

        // --- Verify with streaming verifier ---
        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        verifier
            .init(final_c0, &final_key_image.compress(), message, n)
            .expect("init verifier");

        for i in 0..n {
            let result = verifier
                .verify_member(i, &compressed_members[i], responses[i])
                .expect("verify_member");

            if i < n - 1 {
                assert_eq!(result, VerifyStepOutput::Ack);
            } else {
                assert_eq!(
                    result,
                    VerifyStepOutput::Complete { valid: true },
                    "streaming verifier must report valid for ring size {ring_size}"
                );
            }
        }
    }

    #[test]
    fn test_streaming_verify_ring_size_1() {
        streaming_sign_then_streaming_verify(1);
    }

    #[test]
    fn test_streaming_verify_ring_size_10() {
        streaming_sign_then_streaming_verify(10);
    }

    #[test]
    fn test_streaming_verify_ring_size_100() {
        streaming_sign_then_streaming_verify(100);
    }

    /// Verify that standard BLSAG signatures also pass the streaming verifier.
    #[test]
    fn test_streaming_verify_standard_signature() {
        let keypairs: Vec<(Scalar, RistrettoPoint)> =
            (0..5).map(|i| keypair_from_seed(i + 100)).collect();
        let (secret_key, _) = keypairs[0];
        let public_keys: Vec<RistrettoPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let ring = Ring::new(public_keys);

        let message = b"standard sig streaming verify";
        let signature =
            BLSAG::sign::<Sha3_512, OsRng>(secret_key, &ring, None, message).expect("sign");

        let compressed_members = ring.compressed_members();
        let n = ring.len();

        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        verifier
            .init(
                *signature.challenge(),
                &signature.key_image().compress(),
                message,
                n,
            )
            .expect("init");

        for i in 0..n {
            let result = verifier
                .verify_member(i, &compressed_members[i], signature.responses()[i])
                .expect("verify_member");

            if i == n - 1 {
                assert_eq!(result, VerifyStepOutput::Complete { valid: true });
            }
        }
    }

    #[test]
    fn test_streaming_verify_wrong_message() {
        let keypairs: Vec<(Scalar, RistrettoPoint)> =
            (0..3).map(|i| keypair_from_seed(i + 110)).collect();
        let (secret_key, _) = keypairs[0];
        let public_keys: Vec<RistrettoPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let ring = Ring::new(public_keys);

        let message = b"correct message";
        let wrong_message = b"wrong message";
        let signature =
            BLSAG::sign::<Sha3_512, OsRng>(secret_key, &ring, None, message).expect("sign");

        let compressed_members = ring.compressed_members();
        let n = ring.len();

        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        verifier
            .init(
                *signature.challenge(),
                &signature.key_image().compress(),
                wrong_message,
                n,
            )
            .expect("init");

        let mut final_result = VerifyStepOutput::Ack;
        for i in 0..n {
            final_result = verifier
                .verify_member(i, &compressed_members[i], signature.responses()[i])
                .expect("verify_member");
        }
        assert_eq!(final_result, VerifyStepOutput::Complete { valid: false });
    }

    #[test]
    fn test_streaming_verify_tampered_response() {
        let keypairs: Vec<(Scalar, RistrettoPoint)> =
            (0..4).map(|i| keypair_from_seed(i + 120)).collect();
        let (secret_key, _) = keypairs[0];
        let public_keys: Vec<RistrettoPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let ring = Ring::new(public_keys);

        let message = b"tamper test";
        let signature =
            BLSAG::sign::<Sha3_512, OsRng>(secret_key, &ring, None, message).expect("sign");

        let compressed_members = ring.compressed_members();
        let n = ring.len();

        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        verifier
            .init(
                *signature.challenge(),
                &signature.key_image().compress(),
                message,
                n,
            )
            .expect("init");

        let mut final_result = VerifyStepOutput::Ack;
        for i in 0..n {
            // Tamper with response at index 1.
            let s_i = if i == 1 {
                signature.responses()[i] + Scalar::ONE
            } else {
                signature.responses()[i]
            };
            final_result = verifier
                .verify_member(i, &compressed_members[i], s_i)
                .expect("verify_member");
        }
        assert_eq!(final_result, VerifyStepOutput::Complete { valid: false });
    }

    #[test]
    fn test_streaming_verify_invalid_point() {
        let (sk, pk) = keypair_from_seed(130);
        let ring = Ring::new(vec![pk, keypair_from_seed(131).1]);
        let message = b"invalid point test";
        let signature = BLSAG::sign::<Sha3_512, OsRng>(sk, &ring, None, message).expect("sign");

        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        verifier
            .init(
                *signature.challenge(),
                &signature.key_image().compress(),
                message,
                ring.len(),
            )
            .expect("init");

        let invalid = CompressedRistretto::from_slice(&[0xFF; 32]).unwrap();
        let err = verifier
            .verify_member(0, &invalid, signature.responses()[0])
            .unwrap_err();
        assert_eq!(err, StreamingError::InvalidPoint);
    }

    #[test]
    fn test_streaming_verify_out_of_order() {
        let (sk, pk) = keypair_from_seed(140);
        let ring = Ring::new(vec![pk, keypair_from_seed(141).1, keypair_from_seed(142).1]);
        let message = b"order test";
        let signature = BLSAG::sign::<Sha3_512, OsRng>(sk, &ring, None, message).expect("sign");

        let compressed_members = ring.compressed_members();

        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        verifier
            .init(
                *signature.challenge(),
                &signature.key_image().compress(),
                message,
                ring.len(),
            )
            .expect("init");

        // Skip index 0, submit index 1 — should fail.
        let err = verifier
            .verify_member(1, &compressed_members[1], signature.responses()[1])
            .unwrap_err();
        assert_eq!(
            err,
            StreamingError::OutOfOrder {
                expected: 0,
                got: 1,
            }
        );
    }

    #[test]
    fn test_streaming_verify_empty_ring() {
        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        let key_image = (Scalar::ONE * RISTRETTO_BASEPOINT_POINT).compress();
        let err = verifier
            .init(Scalar::ONE, &key_image, b"msg", 0)
            .unwrap_err();
        assert_eq!(err, StreamingError::EmptyRing);
    }

    #[test]
    fn test_streaming_verify_invalid_key_image() {
        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        let invalid_ki = CompressedRistretto::from_slice(&[0xFF; 32]).unwrap();
        let err = verifier
            .init(Scalar::ONE, &invalid_ki, b"msg", 3)
            .unwrap_err();
        assert_eq!(err, StreamingError::InvalidPoint);
    }

    #[test]
    fn test_streaming_verify_call_after_done() {
        let (sk, pk) = keypair_from_seed(150);
        let ring = Ring::new(vec![pk]);
        let message = b"done test";
        let signature = BLSAG::sign::<Sha3_512, OsRng>(sk, &ring, None, message).expect("sign");

        let compressed = ring.compressed_members();
        let mut verifier = StreamingBlsagVerifier::<Sha3_512>::new();
        verifier
            .init(
                *signature.challenge(),
                &signature.key_image().compress(),
                message,
                1,
            )
            .expect("init");

        let result = verifier
            .verify_member(0, &compressed[0], signature.responses()[0])
            .expect("verify_member");
        assert!(matches!(result, VerifyStepOutput::Complete { valid: true }));

        // Calling again should fail with InvalidState.
        let err = verifier
            .verify_member(0, &compressed[0], signature.responses()[0])
            .unwrap_err();
        assert_eq!(err, StreamingError::InvalidState);
    }

    #[test]
    fn test_cannot_call_sign_member_after_done() {
        // Ring size 1: signing immediately completes.
        let (sk, pk) = keypair_from_seed(90);
        let ring = Ring::new(vec![pk]);
        let ring_hash = ring.canonical_hash();
        let compressed = ring.compressed_members();
        let members = ring.members();

        let signer_pk = sk * RISTRETTO_BASEPOINT_POINT;
        let signer_index = members
            .iter()
            .position(|p| p.compress() == signer_pk.compress())
            .unwrap();

        let rng = ChaCha20Rng::from_seed([0x55; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        signer.init_validation(1, ring_hash).unwrap();
        signer.validate_member(0, &compressed[0]).unwrap();

        signer
            .init_signing(signer_index, sk, &signer_pk.compress(), b"test")
            .unwrap();

        // The only member is the signer.
        let result = signer
            .sign_member(signer_index, &members[signer_index].compress())
            .unwrap();
        assert!(matches!(result, StepOutput::Complete { .. }));

        // Now trying to sign again should fail.
        let err = signer.sign_member(0, &members[0].compress()).unwrap_err();
        assert_eq!(err, StreamingError::InvalidState);
    }

    #[test]
    fn test_correct_signer_identity_passes() {
        let (sk, pk) = keypair_from_seed(200);
        let ring = Ring::new(vec![pk, keypair_from_seed(201).1]);
        let ring_hash = ring.canonical_hash();
        let compressed = ring.compressed_members();
        let members = ring.members();

        let signer_pk = sk * RISTRETTO_BASEPOINT_POINT;
        let signer_index = members
            .iter()
            .position(|p| p.compress() == signer_pk.compress())
            .unwrap();

        let rng = ChaCha20Rng::from_seed([0x66; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        signer.init_validation(ring.len(), ring_hash).unwrap();
        for i in 0..ring.len() {
            signer.validate_member(i, &compressed[i]).unwrap();
        }

        // Correct secret key for the signer at signer_index — should succeed.
        let result = signer.init_signing(signer_index, sk, &signer_pk.compress(), b"test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_wrong_secret_key_returns_identity_mismatch() {
        let (sk, pk) = keypair_from_seed(210);
        let (wrong_sk, _wrong_pk) = keypair_from_seed(211);
        let ring = Ring::new(vec![pk, keypair_from_seed(212).1]);
        let ring_hash = ring.canonical_hash();
        let compressed = ring.compressed_members();
        let members = ring.members();

        let signer_pk = sk * RISTRETTO_BASEPOINT_POINT;
        let signer_index = members
            .iter()
            .position(|p| p.compress() == signer_pk.compress())
            .unwrap();

        let rng = ChaCha20Rng::from_seed([0x77; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        signer.init_validation(ring.len(), ring_hash).unwrap();
        for i in 0..ring.len() {
            signer.validate_member(i, &compressed[i]).unwrap();
        }

        // Wrong secret key does not match the pubkey at signer_index.
        let err = signer
            .init_signing(signer_index, wrong_sk, &signer_pk.compress(), b"test")
            .unwrap_err();
        assert_eq!(err, StreamingError::IdentityMismatch);
    }

    /// Regression test for codex review P1: a self-consistent (sk, pk) pair that
    /// passes the init_signing check but whose pubkey is NOT the ring member at
    /// signer_index. The mismatch must be caught during Phase 2 sign_member.
    #[test]
    fn test_signer_not_in_ring_at_claimed_index() {
        // Create a ring of two members from seeds 220 and 221.
        let (_sk0, pk0) = keypair_from_seed(220);
        let (_sk1, pk1) = keypair_from_seed(221);
        let ring = Ring::new(vec![pk0, pk1]);
        let ring_hash = ring.canonical_hash();
        let compressed = ring.compressed_members();

        // Outsider: valid keypair that is NOT in the ring.
        let (outsider_sk, _outsider_pk) = keypair_from_seed(222);
        let outsider_derived = (outsider_sk * RISTRETTO_BASEPOINT_POINT).compress();

        // The outsider claims to be at index 0, passing a self-consistent
        // (secret_key, signer_pubkey_compressed) — init_signing should succeed
        // because sk*G == outsider_derived.
        let rng = ChaCha20Rng::from_seed([0x88; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        signer.init_validation(ring.len(), ring_hash).unwrap();
        for i in 0..ring.len() {
            signer.validate_member(i, &compressed[i]).unwrap();
        }

        // init_signing passes: sk*G matches the supplied compressed pubkey.
        signer
            .init_signing(0, outsider_sk, &outsider_derived, b"test")
            .unwrap();

        // Phase 2: when sign_member delivers the REAL ring member at index 0
        // (which differs from the outsider's pubkey), IdentityMismatch fires.
        // The signer is at index 0 with ring_len=2, so Phase 2 wraps:
        // processing order is (pi+1)%N = 1, then pi = 0.
        // First member (index 1) is a non-signer step — should succeed.
        let step1 = signer.sign_member(1, &compressed[1]);
        assert!(step1.is_ok());

        // Second member (index 0 = signer slot) — must detect mismatch.
        let err = signer.sign_member(0, &compressed[0]).unwrap_err();
        assert_eq!(err, StreamingError::IdentityMismatch);
    }

    /// Regression test for issue #38: validate ring A in Phase 1, then stream
    /// ring B (with the same signer pubkey at signer_index but different decoys)
    /// in Phase 2. The ring binding mismatch must be detected.
    #[test]
    fn test_ring_switch_detected() {
        // Ring A: signer + decoy_a
        let (signer_sk, signer_pk) = keypair_from_seed(200);
        let (_, decoy_a) = keypair_from_seed(201);
        let ring_a = Ring::new(vec![signer_pk, decoy_a]);
        let ring_a_hash = ring_a.canonical_hash();
        let compressed_a = ring_a.compressed_members();

        // Ring B: signer + decoy_b (different decoy, same signer at index 0)
        let (_, decoy_b) = keypair_from_seed(202);
        let ring_b = Ring::new(vec![signer_pk, decoy_b]);
        let compressed_b = ring_b.compressed_members();

        // Sanity: rings differ only in index 1.
        assert_eq!(compressed_a[0], compressed_b[0]);
        assert_ne!(compressed_a[1], compressed_b[1]);

        let rng = ChaCha20Rng::from_seed([0x99; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        // Phase 1: validate ring A.
        signer.init_validation(ring_a.len(), ring_a_hash).unwrap();
        for i in 0..ring_a.len() {
            signer.validate_member(i, &compressed_a[i]).unwrap();
        }

        // Phase 2: init signing with the real signer key (passes identity check).
        let signer_index = 0;
        signer
            .init_signing(
                signer_index,
                signer_sk,
                &signer_pk.compress(),
                b"ring-switch test",
            )
            .unwrap();

        // Stream ring B members in signing order: index 1 (non-signer), then 0 (signer).
        // Index 1: decoy_b instead of decoy_a — non-signer step succeeds (binding
        // is only checked at completion).
        let step = signer.sign_member(1, &compressed_b[1]);
        assert!(step.is_ok());

        // Index 0 (signer step): ring binding mismatch detected.
        let err = signer.sign_member(0, &compressed_b[0]).unwrap_err();
        assert_eq!(err, StreamingError::RingSwitchDetected);
    }

    /// Verify that an honest signing pass (same ring in Phase 1 and Phase 2) still succeeds.
    #[test]
    fn test_honest_ring_binding_passes() {
        let (signer_sk, signer_pk) = keypair_from_seed(230);
        let (_, decoy1) = keypair_from_seed(231);
        let (_, decoy2) = keypair_from_seed(232);
        let ring = Ring::new(vec![signer_pk, decoy1, decoy2]);
        let ring_hash = ring.canonical_hash();
        let compressed = ring.compressed_members();

        let rng = ChaCha20Rng::from_seed([0xAA; 32]);
        let mut signer = StreamingBlsagSigner::<Sha3_512, _>::new(rng);

        // Phase 1: validate ring.
        signer.init_validation(ring.len(), ring_hash).unwrap();
        for i in 0..ring.len() {
            signer.validate_member(i, &compressed[i]).unwrap();
        }

        // Phase 2: sign with the same ring.
        let signer_index = 0;
        signer
            .init_signing(signer_index, signer_sk, &signer_pk.compress(), b"honest test")
            .unwrap();

        // Signing order: 1, 2, 0
        for step in 0..ring.len() {
            let idx = (signer_index + 1 + step) % ring.len();
            let result = signer.sign_member(idx, &compressed[idx]);
            assert!(result.is_ok(), "sign_member({idx}) failed: {result:?}");
        }
    }
}
