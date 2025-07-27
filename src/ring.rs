//! Module for the `Ring` structure, ensuring sorted public keys for efficient signing.

use crate::prelude::*;
use curve25519_dalek::ristretto::RistrettoPoint;

/// Represents a ring of public keys for a ring signature.
///
/// The `Ring` struct guarantees that its internal list of public keys is always
/// sorted by their byte representation. This is a critical invariant that allows
/// for high-performance binary searching during the signing process, avoiding
/// a slow linear scan.
#[derive(Clone, Debug)]
pub struct Ring {
    members: Vec<RistrettoPoint>,
}

impl Ring {
    /// Creates a new `Ring` from a vector of public keys.
    ///
    /// The constructor takes ownership of the vector and immediately sorts the
    /// public keys to enforce the struct's invariant.
    pub fn new(public_keys: Vec<RistrettoPoint>) -> Self {
        let mut members = public_keys;
        // Sort by the compressed byte representation to ensure a canonical ordering.
        members.sort_unstable_by_key(|p| p.compress().to_bytes());
        Self { members }
    }

    /// Returns a slice containing all the public key members of the ring, guaranteed
    /// to be in sorted order.
    pub fn members(&self) -> &[RistrettoPoint] {
        &self.members
    }
}
