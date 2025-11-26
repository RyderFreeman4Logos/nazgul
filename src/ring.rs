//! Module for the `Ring` structure, ensuring sorted public keys for efficient signing.

use crate::prelude::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use digest::{generic_array::typenum::U64, Digest};

/// A strongly-typed wrapper for a 32-byte consensus hash of a Ring.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RingHash(pub [u8; 32]);

impl core::fmt::Debug for RingHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RingHash(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl core::fmt::Display for RingHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for RingHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for RingHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Defines the context in which a ring signature is stored or verified.
///
/// *   `Compact`: Contains only the `RingHash`. This is ideal for network transmission
///     and storage when the Verifier is expected to have access to the Ring definition
///     (e.g., via a cache or database).
/// *   `Archival`: Contains the full `Ring` definition. This makes the signature
///     self-contained but significantly larger. Ideal for cold storage or sharing.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "data"))]
pub enum RingContext {
    Compact(RingHash),
    Archival(Ring),
}

impl RingContext {
    /// Returns the hash associated with this context.
    ///
    /// If `Compact`, returns the stored hash.
    /// If `Archival`, computes the hash of the stored ring.
    pub fn consensus_hash<D: Digest + Default>(&self) -> RingHash {
        match self {
            RingContext::Compact(h) => *h,
            RingContext::Archival(ring) => {
                let output = ring.consensus_hash::<D>();
                let mut bytes = [0u8; 32];
                // Ensure we only copy what fits. If the hash is larger, it truncates (unlikely with SHA3-256).
                // If smaller, it pads.
                let len = core::cmp::min(output.len(), 32);
                bytes[..len].copy_from_slice(&output[..len]);
                RingHash(bytes)
            }
        }
    }
}

/// Represents pre-computed data for a `Ring` to accelerate cryptographic operations.
///
/// This structure holds the results of hashing each public key in the ring onto the curve.
/// By performing this computationally expensive step once and caching the result, both
/// signing and verification can be significantly sped up.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrecomputedRingData {
    hashed_points: Vec<RistrettoPoint>,
}

impl PrecomputedRingData {
    /// Returns a slice of the pre-computed hashed points.
    pub fn hashed_points(&self) -> &[RistrettoPoint] {
        &self.hashed_points
    }

    /// Verifies that the pre-computed data is valid for the given `Ring`.
    ///
    /// This is a crucial security step. It re-calculates the expected hashed points
    /// from the ring's public keys and compares them against the points stored in this
    /// pre-computed object to ensure they match. A user should always run this check
    /// on any pre-computed data received from an untrusted source.
    pub fn verify<H: Digest<OutputSize = U64> + Clone + Default>(&self, ring: &Ring) -> bool {
        if self.hashed_points.len() != ring.members.len() {
            return false;
        }
        let expected_points: Vec<RistrettoPoint> = ring
            .members
            .iter()
            .map(|p| RistrettoPoint::from_hash(H::default().chain_update(p.compress().to_bytes())))
            .collect();

        self.hashed_points == expected_points
    }
}

/// Represents a ring of public keys for a ring signature.
///
/// The `Ring` struct guarantees that its internal list of public keys is always
/// sorted by their byte representation. This is a critical invariant that allows
/// for high-performance binary searching during the signing process, avoiding
/// a slow linear scan.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "Vec<RistrettoPoint>", into = "Vec<RistrettoPoint>")
)]
pub struct Ring {
    members: Vec<RistrettoPoint>,
}

// Implement TryFrom for safe deserialization that enforces sorting
impl From<Vec<RistrettoPoint>> for Ring {
    fn from(points: Vec<RistrettoPoint>) -> Self {
        Self::new(points)
    }
}

impl From<Ring> for Vec<RistrettoPoint> {
    fn from(ring: Ring) -> Self {
        ring.members
    }
}

impl Ring {
    /// Creates a new `Ring` from a vector of public keys.
    ///
    /// The constructor takes ownership of the vector and immediately sorts the
    /// public keys to enforce the struct's invariant.
    pub fn new(public_keys: Vec<RistrettoPoint>) -> Self {
        // Optimization: Pre-compute the compressed bytes to avoid re-calculating
        // them during the sort. `compress()` involves expensive field inversions.
        // This reduces the complexity from O(N log N * cost_of_compress) to
        // O(N * cost_of_compress + N log N * cost_of_byte_compare).
        let mut members_with_bytes: Vec<([u8; 32], RistrettoPoint)> = public_keys
            .into_iter()
            .map(|p| (p.compress().to_bytes(), p))
            .collect();

        members_with_bytes.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let members = members_with_bytes.into_iter().map(|(_, p)| p).collect();

        Self { members }
    }

    /// Returns a slice containing all the public key members of the ring, guaranteed
    /// to be in sorted order.
    pub fn members(&self) -> &[RistrettoPoint] {
        &self.members
    }

    /// Computes a deterministic "consensus hash" of the ring.
    ///
    /// This hash serves as a unique identifier (fingerprint) for the ring's content and ordering.
    /// Since `Ring` guarantees its members are sorted, this hash is deterministic regardless of
    /// the order in which the keys were originally provided to `Ring::new()`.
    ///
    /// This is useful for:
    /// 1.  **Caching**: Using the hash as a key to retrieve `PrecomputedRingData`.
    /// 2.  **Versioning**: Tracking changes to dynamic rings in an event-sourced system.
    /// 3.  **Integrity**: Verifying that a transmitted ring matches the expected definition.
    ///
    /// # Example
    /// ```
    /// # use nazgul::ring::Ring;
    /// # use curve25519_dalek::ristretto::RistrettoPoint;
    /// # use rand_core::OsRng;
    /// # use sha3::Sha3_256;
    /// # use digest::Digest;
    /// # fn main() {
    /// # let mut csprng = OsRng;
    /// let points = vec![
    ///     RistrettoPoint::random(&mut csprng),
    ///     RistrettoPoint::random(&mut csprng)
    /// ];
    /// let ring = Ring::new(points);
    /// let hash = ring.consensus_hash::<Sha3_256>();
    /// # }
    /// ```
    pub fn consensus_hash<D: Digest + Default>(&self) -> digest::Output<D> {
        let mut hasher = D::default();
        for member in &self.members {
            hasher.update(member.compress().as_bytes());
        }
        hasher.finalize()
    }

    /// Performs the pre-computation step for this ring.
    ///
    /// This iterates through all public keys in the ring, hashes them to a point on
    /// the curve, and returns a `PrecomputedRingData` object containing the results.
    /// This object can then be used to accelerate future signing and verification operations.
    pub fn precompute<H: Digest<OutputSize = U64> + Clone + Default>(&self) -> PrecomputedRingData {
        let hashed_points = self
            .members
            .iter()
            .map(|p| RistrettoPoint::from_hash(H::default().chain_update(p.compress().to_bytes())))
            .collect();
        PrecomputedRingData { hashed_points }
    }
}
