use crate::error::SignatureError;
use crate::ring::{PreparedRing, Ring};
use crate::scalar::RistrettoPoint;
use anyhow::Result as AResult;
use digest::{generic_array::typenum::U64, Digest};
use rand_core::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(feature = "std")]
use std::string::String;

pub trait KeyImageGen<Secret, Point> {
    fn generate_key_image<Hash: Digest<OutputSize = U64> + Clone + Default>(k: Secret) -> Point;
}

pub trait Sign<Secret, Ring> {
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Secret,
        ring: Ring,
        secret_index: usize,
        message: &[u8],
    ) -> Self;
}

pub trait Verify {
    /// To verify a `signature` you need the `message` too
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: Self,
        message: &[u8],
    ) -> bool;
}

pub trait Link {
    /// This is for linking two signatures and checking if they are signed by the same person
    fn link(signature_1: Self, signature_2: Self) -> bool;
}

// ================================================================================================
// Traits for passing by reference, intended for gradual adoption.
// ================================================================================================

pub trait VerifyRef {
    /// To verify a `signature` you need the `message` too. This trait passes the signature
    /// by reference.
    fn verify<Hash: Digest<OutputSize = U64> + Clone + Default>(
        signature: &Self,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<Hash>>,
        message: &[u8],
    ) -> bool;
}

pub trait LinkRef {
    /// This is for linking two signatures and checking if they are signed by the same person.
    /// This trait passes signatures by reference.
    fn link(signature_1: &Self, signature_2: &Self) -> bool;
}

pub trait SignRef<Secret> {
    fn sign<
        Hash: Digest<OutputSize = U64> + Clone + Default,
        CSPRNG: CryptoRng + RngCore + Default,
    >(
        k: Secret,
        ring: &Ring,
        precomputed_data: Option<&PreparedRing<Hash>>,
        message: &[u8],
    ) -> Result<Self, SignatureError>
    where
        Self: Sized;
}

// ================================================================================================
// General-purpose traits for key and byte conversions.
// ================================================================================================

pub trait PublicKeyComputable {
    fn compute_pubkey(&self) -> RistrettoPoint;
}

pub trait LocalByteConvertible {
    fn to_bytes(&self) -> [u8; 32];
    fn from_bytes(bytes: &[u8]) -> AResult<Self>
    where
        Self: Sized;
    fn to_base58(&self) -> String;
    fn from_base58(input: String) -> AResult<Self>
    where
        Self: Sized;
}

// ================================================================================================
// Trait for non-hardened key derivation.
// ================================================================================================

/// A trait for types that can be deterministically derived into a child
/// using non-hardened derivation.
pub trait Derivable: Sized {
    /// Derives a child object from a parent using the provided derivation data.
    ///
    /// This function must be deterministic: for the same parent and the same
    /// `derivation_data`, it must always produce the same child.
    ///
    /// The hash function `H` is used to create a "tweak" from the parent's
    /// public information and the `derivation_data`.
    fn derive_child<H: Digest<OutputSize = U64> + Clone + Default>(
        &self,
        derivation_data: &[u8],
    ) -> Self;
}
