//! Module for the `Ring` structure, ensuring sorted public keys for efficient signing.

use crate::prelude::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use digest::{generic_array::typenum::U64, Digest};
use sha3::Sha3_512;

/// A strongly-typed wrapper for a 32-byte canonical hash of a Ring.
///
/// The hash is always computed using SHA3-512, truncated to 32 bytes.
/// This guarantees that the same set of sorted ring members always produces
/// the same `RingHash`, regardless of caller-chosen digest algorithms.
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

impl RingHash {
    /// Computes a canonical `RingHash` from a slice of compressed points.
    ///
    /// Uses SHA3-512 as the fixed digest algorithm, truncated to 32 bytes.
    /// The caller is responsible for ensuring members are sorted (as `Ring` guarantees).
    pub(crate) fn from_compressed_members(members: &[CompressedRistretto]) -> Self {
        let mut hasher = Sha3_512::default();
        for member in members {
            hasher.update(member.as_bytes());
        }
        let output = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&output[..32]);
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
    /// Returns the canonical hash associated with this context.
    ///
    /// If `Compact`, returns the stored hash.
    /// If `Archival`, computes the canonical hash of the stored ring.
    pub fn canonical_hash(&self) -> RingHash {
        match self {
            RingContext::Compact(h) => *h,
            RingContext::Archival(ring) => ring.canonical_hash(),
        }
    }
}

/// A prepared (pre-computed) form of a [`Ring`] that accelerates cryptographic operations.
///
/// This structure holds the results of hashing each public key in the ring onto the curve,
/// along with the canonical [`RingHash`] of the ring it was computed from. The `ring_hash`
/// is checked during signing and verification to ensure the prepared data matches
/// the ring being used.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreparedRing {
    ring_hash: RingHash,
    hashed_points: Vec<RistrettoPoint>,
}

impl PreparedRing {
    /// Returns a slice of the pre-computed hashed points.
    pub fn hashed_points(&self) -> &[RistrettoPoint] {
        &self.hashed_points
    }

    /// Returns the canonical hash of the ring this data was computed from.
    pub fn ring_hash(&self) -> RingHash {
        self.ring_hash
    }

    /// Returns `true` if this prepared data was computed from the given ring.
    ///
    /// This is a fast O(1) check that compares the stored `ring_hash` against
    /// the ring's current canonical hash. It does **not** re-derive the hashed
    /// points — use [`verify`](Self::verify) for a full cryptographic check.
    pub fn is_valid_for(&self, ring: &Ring) -> bool {
        self.ring_hash == ring.canonical_hash()
    }

    /// Verifies that the pre-computed data is valid for the given `Ring`.
    ///
    /// This is a crucial security step. It checks that the canonical ring hash matches,
    /// then re-calculates the expected hashed points from the ring's public keys and
    /// compares them against the points stored in this pre-computed object.
    ///
    /// # Panics
    ///
    /// Panics if the ring is in `Compressed` state. Call `decompress()` first.
    pub fn verify<H: Digest<OutputSize = U64> + Clone + Default>(&self, ring: &Ring) -> bool {
        if self.ring_hash != ring.canonical_hash() {
            return false;
        }
        let members = ring.members();
        if self.hashed_points.len() != members.len() {
            return false;
        }
        let expected_points: Vec<RistrettoPoint> = members
            .iter()
            .map(|p| {
                RistrettoPoint::from_hash(
                    H::default()
                        .chain_update(b"nazgul-H_p-v3")
                        .chain_update(p.compress().to_bytes()),
                )
            })
            .collect();

        self.hashed_points == expected_points
    }
}

/// Internal representation of ring members.
///
/// - `Full`: Both decompressed points and their compressed forms are available.
///   This is the default state after `Ring::new()` and is required for signing/verification.
/// - `Compressed`: Only compressed points are stored, saving memory.
///   Must be decompressed via `Ring::decompress()` before accessing `members()`.
#[derive(Clone, Debug)]
enum RingRepr {
    Full {
        compressed: Vec<CompressedRistretto>,
        points: Vec<RistrettoPoint>,
    },
    Compressed(Vec<CompressedRistretto>),
}

/// Represents a ring of public keys for a ring signature.
///
/// The `Ring` struct guarantees that its internal list of public keys is always
/// sorted by their compressed byte representation. This is a critical invariant
/// that allows for high-performance binary searching during the signing process,
/// avoiding a slow linear scan.
///
/// A `Ring` can exist in two internal states:
///
/// - **Full**: Both decompressed `RistrettoPoint`s and `CompressedRistretto` bytes
///   are available. Created via `Ring::new()` or `Ring::decompress()`.
/// - **Compressed**: Only `CompressedRistretto` bytes are stored. Created via
///   `Ring::from_compressed()`. This state uses ~50% less memory but requires
///   explicit decompression before signing or verification.
#[derive(Clone, Debug)]
pub struct Ring {
    repr: RingRepr,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ring {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.compressed_members().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ring {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let compressed = Vec::<CompressedRistretto>::deserialize(deserializer)?;
        Ok(Ring::from_compressed(compressed))
    }
}

impl From<Vec<RistrettoPoint>> for Ring {
    fn from(points: Vec<RistrettoPoint>) -> Self {
        Self::new(points)
    }
}

impl From<Ring> for Vec<RistrettoPoint> {
    fn from(ring: Ring) -> Self {
        match ring.repr {
            RingRepr::Full { points, .. } => points,
            RingRepr::Compressed(_) => {
                panic!("Ring must be decompressed before converting to Vec<RistrettoPoint>. Call decompress() first.")
            }
        }
    }
}

impl Ring {
    /// Creates a new `Ring` from a vector of public keys.
    ///
    /// The constructor takes ownership of the vector and immediately sorts the
    /// public keys to enforce the struct's invariant. Both decompressed and
    /// compressed forms are stored (Full representation).
    pub fn new(public_keys: Vec<RistrettoPoint>) -> Self {
        let sorted = sort_and_compress(public_keys);
        Self {
            repr: RingRepr::Full {
                compressed: sorted.compressed,
                points: sorted.points,
            },
        }
    }

    /// Creates a `Ring` from pre-compressed points.
    ///
    /// The points are sorted by their byte representation. No decompression
    /// is performed, so this is an O(n log n) operation on cheap byte comparisons.
    ///
    /// The resulting ring is in `Compressed` state. Call [`decompress()`](Ring::decompress)
    /// before passing it to signing or verification functions.
    pub fn from_compressed(compressed_keys: Vec<CompressedRistretto>) -> Self {
        let mut sorted = compressed_keys;
        sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Self {
            repr: RingRepr::Compressed(sorted),
        }
    }

    /// Decompresses a `Compressed` ring into a `Full` ring.
    ///
    /// If the ring is already `Full`, returns `self` unchanged.
    /// Returns `Err(SignatureError::DecompressionFailed)` if any point fails to decompress.
    pub fn decompress(self) -> Result<Ring, SignatureError> {
        match self.repr {
            RingRepr::Full { .. } => Ok(self),
            RingRepr::Compressed(compressed) => {
                let mut points = Vec::with_capacity(compressed.len());
                for c in &compressed {
                    match c.decompress() {
                        Some(p) => points.push(p),
                        None => return Err(SignatureError::DecompressionFailed),
                    }
                }
                Ok(Ring {
                    repr: RingRepr::Full { compressed, points },
                })
            }
        }
    }

    /// Returns `true` if the ring is in `Full` (decompressed) state.
    pub fn is_decompressed(&self) -> bool {
        matches!(self.repr, RingRepr::Full { .. })
    }

    /// Returns a slice containing all the public key members of the ring, guaranteed
    /// to be in sorted order.
    ///
    /// # Panics
    ///
    /// Panics if the ring is in `Compressed` state. Call `decompress()` first.
    pub fn members(&self) -> &[RistrettoPoint] {
        match &self.repr {
            RingRepr::Full { points, .. } => points,
            RingRepr::Compressed(_) => {
                panic!(
                    "Ring must be decompressed before accessing members. Call decompress() first."
                )
            }
        }
    }

    /// Returns a slice of the compressed ring members.
    ///
    /// Works on both `Full` and `Compressed` rings.
    pub fn compressed_members(&self) -> &[CompressedRistretto] {
        match &self.repr {
            RingRepr::Full { compressed, .. } => compressed,
            RingRepr::Compressed(compressed) => compressed,
        }
    }

    /// Returns the number of members in the ring.
    ///
    /// Works on both `Full` and `Compressed` rings.
    pub fn len(&self) -> usize {
        match &self.repr {
            RingRepr::Full { points, .. } => points.len(),
            RingRepr::Compressed(compressed) => compressed.len(),
        }
    }

    /// Returns `true` if the ring contains no members.
    ///
    /// Works on both `Full` and `Compressed` rings.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Computes the canonical hash of this ring.
    ///
    /// Uses SHA3-512 (truncated to 32 bytes) as the fixed digest algorithm, ensuring
    /// the same ring members always produce the same `RingHash` regardless of the
    /// caller's choice of cryptographic hash function.
    ///
    /// Since `Ring` guarantees its members are sorted, this hash is deterministic
    /// regardless of the order in which keys were originally provided to `Ring::new()`.
    ///
    /// Works on both `Full` and `Compressed` rings (uses compressed bytes for hashing).
    ///
    /// # Example
    /// ```
    /// # use nazgul::ring::Ring;
    /// # use curve25519_dalek::ristretto::RistrettoPoint;
    /// # use rand_core::OsRng;
    /// # fn main() {
    /// # let mut csprng = OsRng;
    /// let points = vec![
    ///     RistrettoPoint::random(&mut csprng),
    ///     RistrettoPoint::random(&mut csprng)
    /// ];
    /// let ring = Ring::new(points);
    /// let hash = ring.canonical_hash();
    /// # }
    /// ```
    pub fn canonical_hash(&self) -> RingHash {
        RingHash::from_compressed_members(self.compressed_members())
    }

    /// Performs the pre-computation step for this ring.
    ///
    /// This iterates through all public keys in the ring, hashes them to a point on
    /// the curve, and returns a [`PreparedRing`] containing the results along with
    /// the ring's canonical hash. The prepared data can then be reused to accelerate
    /// future signing and verification operations.
    ///
    /// # Panics
    ///
    /// Panics if the ring is in `Compressed` state. Call `decompress()` first.
    pub fn precompute<H: Digest<OutputSize = U64> + Clone + Default>(&self) -> PreparedRing {
        let members = self.members();
        let hashed_points = members
            .iter()
            .map(|p| {
                RistrettoPoint::from_hash(
                    H::default()
                        .chain_update(b"nazgul-H_p-v3")
                        .chain_update(p.compress().to_bytes()),
                )
            })
            .collect();
        PreparedRing {
            ring_hash: self.canonical_hash(),
            hashed_points,
        }
    }

    /// Adds a public key to the ring while preserving the sorted invariant.
    ///
    /// The key is inserted and the members are re-sorted by their compressed byte
    /// representation. Duplicate entries are allowed and will be placed according
    /// to their sort order.
    ///
    /// Any previously computed [`PreparedRing`] will become invalid after this call,
    /// since the ring's canonical hash changes when members are added.
    ///
    /// # Panics
    ///
    /// Panics if the ring is in `Compressed` state. Call `decompress()` first.
    pub fn add_public_key(&mut self, pubkey: RistrettoPoint) {
        match &mut self.repr {
            RingRepr::Full { compressed, points } => {
                points.push(pubkey);
                let sorted = sort_and_compress(core::mem::take(points));
                *compressed = sorted.compressed;
                *points = sorted.points;
            }
            RingRepr::Compressed(_) => {
                panic!("Cannot mutate a compressed ring. Call decompress() first.")
            }
        }
    }

    /// Removes the first occurrence of the given public key, preserving order.
    ///
    /// Returns `true` if a matching key was removed, `false` otherwise. The
    /// ring remains sorted after removal.
    ///
    /// Any previously computed [`PreparedRing`] will become invalid after this call,
    /// since the ring's canonical hash changes when members are removed.
    ///
    /// # Panics
    ///
    /// Panics if the ring is in `Compressed` state. Call `decompress()` first.
    pub fn remove_public_key(&mut self, pubkey: RistrettoPoint) -> bool {
        match &mut self.repr {
            RingRepr::Full { compressed, points } => {
                let target_bytes = pubkey.compress();
                match compressed.binary_search_by(|c| c.as_bytes().cmp(target_bytes.as_bytes())) {
                    Ok(mut pos) => {
                        while pos > 0 && compressed[pos - 1].as_bytes() == target_bytes.as_bytes() {
                            pos -= 1;
                        }
                        compressed.remove(pos);
                        points.remove(pos);
                        true
                    }
                    Err(_) => false,
                }
            }
            RingRepr::Compressed(_) => {
                panic!("Cannot mutate a compressed ring. Call decompress() first.")
            }
        }
    }
}

/// Result of sorting points: both compressed and decompressed forms, kept in sync.
struct SortedMembers {
    compressed: Vec<CompressedRistretto>,
    points: Vec<RistrettoPoint>,
}

/// Sorts ring members by their compressed byte representation, returning both forms.
fn sort_and_compress(members: Vec<RistrettoPoint>) -> SortedMembers {
    let mut pairs: Vec<(CompressedRistretto, RistrettoPoint)> =
        members.into_iter().map(|p| (p.compress(), p)).collect();

    pairs.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let (compressed, points) = pairs.into_iter().unzip();
    SortedMembers { compressed, points }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Sha3_512;

    fn sample_points() -> Vec<RistrettoPoint> {
        ["alpha", "beta", "gamma"]
            .iter()
            .map(|label| RistrettoPoint::from_hash(Sha3_512::new().chain_update(label.as_bytes())))
            .collect()
    }

    #[test]
    fn new_ring_is_full() {
        let points = sample_points();
        let ring = Ring::new(points);
        assert!(ring.is_decompressed());
    }

    #[test]
    fn from_compressed_creates_compressed_ring() {
        let points = sample_points();
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let ring = Ring::from_compressed(compressed);
        assert!(!ring.is_decompressed());
    }

    #[test]
    fn decompress_roundtrip() {
        let points = sample_points();
        let full_ring = Ring::new(points.clone());
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let compressed_ring = Ring::from_compressed(compressed);

        let decompressed = compressed_ring.decompress().unwrap();
        assert!(decompressed.is_decompressed());

        // Same canonical hash as the full ring
        assert_eq!(full_ring.canonical_hash(), decompressed.canonical_hash());
        assert_eq!(full_ring.members(), decompressed.members());
    }

    #[test]
    fn decompress_full_is_noop() {
        let points = sample_points();
        let ring = Ring::new(points.clone());
        let hash_before = ring.canonical_hash();
        let ring = ring.decompress().unwrap();
        assert_eq!(hash_before, ring.canonical_hash());
    }

    #[test]
    fn compressed_members_works_on_both() {
        let points = sample_points();
        let full_ring = Ring::new(points.clone());
        let compressed_keys: Vec<CompressedRistretto> =
            points.iter().map(|p| p.compress()).collect();
        let compressed_ring = Ring::from_compressed(compressed_keys);

        // Both should have the same compressed members (same sorting)
        assert_eq!(
            full_ring.compressed_members(),
            compressed_ring.compressed_members()
        );
    }

    #[test]
    fn len_works_on_both() {
        let points = sample_points();
        let full_ring = Ring::new(points.clone());
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let compressed_ring = Ring::from_compressed(compressed);

        assert_eq!(full_ring.len(), 3);
        assert_eq!(compressed_ring.len(), 3);
    }

    #[test]
    fn canonical_hash_same_for_both_reprs() {
        let points = sample_points();
        let full_ring = Ring::new(points.clone());
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let compressed_ring = Ring::from_compressed(compressed);

        assert_eq!(full_ring.canonical_hash(), compressed_ring.canonical_hash());
    }

    #[test]
    #[should_panic(
        expected = "Ring must be decompressed before accessing members. Call decompress() first."
    )]
    fn members_panics_on_compressed() {
        let points = sample_points();
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let ring = Ring::from_compressed(compressed);
        let _ = ring.members();
    }

    #[test]
    #[should_panic(
        expected = "Ring must be decompressed before accessing members. Call decompress() first."
    )]
    fn precompute_panics_on_compressed() {
        let points = sample_points();
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let ring = Ring::from_compressed(compressed);
        let _ = ring.precompute::<Sha3_512>();
    }

    #[test]
    fn add_public_key_keeps_ring_sorted() {
        let mut points = sample_points();
        let p_gamma = points.pop().unwrap();
        let p_beta = points.pop().unwrap();
        let p_alpha = points.pop().unwrap();

        let mut ring = Ring::new(vec![p_beta, p_gamma]);
        ring.add_public_key(p_alpha);

        let expected = Ring::new(vec![p_alpha, p_beta, p_gamma]);
        assert_eq!(ring.members(), expected.members());
    }

    #[test]
    fn remove_public_key_removes_first_match() {
        let points = sample_points();
        let mut ring = Ring::new(points.clone());

        assert!(ring.remove_public_key(points[1]));

        let expected = Ring::new(vec![points[0], points[2]]);
        assert_eq!(ring.members(), expected.members());
    }

    #[test]
    fn remove_public_key_returns_false_when_absent() {
        let points = sample_points();
        let mut ring = Ring::new(vec![points[0], points[1]]);

        assert!(!ring.remove_public_key(points[2]));

        let expected = Ring::new(vec![points[0], points[1]]);
        assert_eq!(ring.members(), expected.members());
    }

    #[test]
    fn remove_public_key_with_duplicates_removes_single_occurrence() {
        let points = sample_points();
        let mut ring = Ring::new(vec![points[0], points[1], points[1], points[2]]);

        assert!(ring.remove_public_key(points[1]));

        let remaining = ring
            .members()
            .iter()
            .filter(|p| p.compress().to_bytes() == points[1].compress().to_bytes())
            .count();
        assert_eq!(remaining, 1);

        let expected = Ring::new(vec![points[0], points[1], points[2]]);
        assert_eq!(ring.members(), expected.members());
    }

    // --- RingHash consistency tests across Full/Compressed representations ---

    #[test]
    fn canonical_hash_consistent_across_reprs_shuffled_input() {
        // Same members given in different order produce the same canonical hash
        let points = sample_points();
        let reversed: Vec<RistrettoPoint> = points.iter().rev().copied().collect();

        let ring_a = Ring::new(points.clone());
        let ring_b = Ring::new(reversed);

        assert_eq!(ring_a.canonical_hash(), ring_b.canonical_hash());
    }

    #[test]
    fn canonical_hash_full_eq_compressed_shuffled_input() {
        // Full ring and Compressed ring from the same members (different insertion order)
        // must produce identical canonical hashes.
        let points = sample_points();
        let reversed: Vec<RistrettoPoint> = points.iter().rev().copied().collect();
        let compressed_reversed: Vec<CompressedRistretto> =
            reversed.iter().map(|p| p.compress()).collect();

        let full_ring = Ring::new(points);
        let compressed_ring = Ring::from_compressed(compressed_reversed);

        assert_eq!(full_ring.canonical_hash(), compressed_ring.canonical_hash());
    }

    #[test]
    fn sort_consistency_full_vs_compressed() {
        // Verify that compressed_members() returns identical slices for both repr paths.
        let points = sample_points();
        let compressed_keys: Vec<CompressedRistretto> =
            points.iter().map(|p| p.compress()).collect();

        let full_ring = Ring::new(points);
        let compressed_ring = Ring::from_compressed(compressed_keys);

        assert_eq!(
            full_ring.compressed_members(),
            compressed_ring.compressed_members(),
            "Sort order must be identical across Full and Compressed representations"
        );
    }

    #[test]
    fn decompress_members_match_full_ring() {
        // After from_compressed → decompress(), members() must return the same
        // decompressed points as Ring::new() with the same member set.
        let points = sample_points();
        let compressed_keys: Vec<CompressedRistretto> =
            points.iter().map(|p| p.compress()).collect();

        let full_ring = Ring::new(points);
        let decompressed_ring = Ring::from_compressed(compressed_keys).decompress().unwrap();

        assert_eq!(
            full_ring.members(),
            decompressed_ring.members(),
            "Decompressed members must match Full ring members"
        );
    }

    #[test]
    fn single_member_ring_hash_consistency() {
        // Edge case: ring with exactly one member
        let point = RistrettoPoint::from_hash(Sha3_512::new().chain_update(b"single"));
        let compressed = vec![point.compress()];

        let full_ring = Ring::new(vec![point]);
        let compressed_ring = Ring::from_compressed(compressed);

        assert_eq!(full_ring.canonical_hash(), compressed_ring.canonical_hash());
        assert_eq!(full_ring.len(), 1);
        assert_eq!(compressed_ring.len(), 1);

        let decompressed = compressed_ring.decompress().unwrap();
        assert_eq!(full_ring.members(), decompressed.members());
    }

    #[test]
    fn large_ring_hash_consistency() {
        // Edge case: ring with 25 members
        let points: Vec<RistrettoPoint> = (0..25u64)
            .map(|i| {
                RistrettoPoint::from_hash(
                    Sha3_512::new().chain_update(format!("member-{}", i).as_bytes()),
                )
            })
            .collect();

        let compressed_keys: Vec<CompressedRistretto> =
            points.iter().map(|p| p.compress()).collect();

        let full_ring = Ring::new(points);
        let compressed_ring = Ring::from_compressed(compressed_keys);

        assert_eq!(
            full_ring.canonical_hash(),
            compressed_ring.canonical_hash(),
            "Large ring (25 members) must have consistent hash across representations"
        );
        assert_eq!(
            full_ring.compressed_members(),
            compressed_ring.compressed_members(),
            "Large ring sort order must be identical"
        );

        let decompressed = compressed_ring.decompress().unwrap();
        assert_eq!(full_ring.members(), decompressed.members());
    }

    #[test]
    fn prepared_ring_valid_for_decompressed_from_compressed() {
        // PreparedRing from a Full ring should also validate against the
        // equivalent decompressed-from-compressed ring (same canonical hash).
        let points = sample_points();
        let compressed_keys: Vec<CompressedRistretto> =
            points.iter().map(|p| p.compress()).collect();

        let full_ring = Ring::new(points);
        let prepared = full_ring.precompute::<Sha3_512>();

        let decompressed = Ring::from_compressed(compressed_keys).decompress().unwrap();
        assert!(
            prepared.is_valid_for(&decompressed),
            "PreparedRing from Full must be valid for equivalent decompressed ring"
        );
        assert!(
            prepared.verify::<Sha3_512>(&decompressed),
            "PreparedRing full verify must pass against equivalent decompressed ring"
        );
    }

    #[test]
    fn decompression_failure_returns_error() {
        // Create an invalid compressed point (all 0xFF bytes is not a valid Ristretto point)
        let invalid = CompressedRistretto::from_slice(&[0xFFu8; 32]).unwrap();
        let ring = Ring::from_compressed(vec![invalid]);
        let result = ring.decompress();
        assert_eq!(result.unwrap_err(), SignatureError::DecompressionFailed);
    }

    #[test]
    #[should_panic(expected = "Cannot mutate a compressed ring. Call decompress() first.")]
    fn add_public_key_panics_on_compressed() {
        let points = sample_points();
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let mut ring = Ring::from_compressed(compressed);
        ring.add_public_key(points[0]);
    }

    #[test]
    #[should_panic(expected = "Cannot mutate a compressed ring. Call decompress() first.")]
    fn remove_public_key_panics_on_compressed() {
        let points = sample_points();
        let compressed: Vec<CompressedRistretto> = points.iter().map(|p| p.compress()).collect();
        let mut ring = Ring::from_compressed(compressed);
        ring.remove_public_key(points[0]);
    }

    #[test]
    fn add_public_key_invalidates_prepared_ring() {
        let points = sample_points();
        let mut ring = Ring::new(vec![points[0], points[1]]);
        let prepared = ring.precompute::<Sha3_512>();

        assert!(prepared.is_valid_for(&ring));

        ring.add_public_key(points[2]);

        assert!(!prepared.is_valid_for(&ring));
    }

    #[test]
    fn remove_public_key_invalidates_prepared_ring() {
        let points = sample_points();
        let mut ring = Ring::new(points.clone());
        let prepared = ring.precompute::<Sha3_512>();

        assert!(prepared.is_valid_for(&ring));

        ring.remove_public_key(points[0]);

        assert!(!prepared.is_valid_for(&ring));
    }
}
