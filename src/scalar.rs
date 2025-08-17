use anyhow::{anyhow, Result as AResult};
use bs58;
use core::convert::TryInto;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

pub use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::CompressedRistretto,
    ristretto::RistrettoPoint,
    // self,
    scalar::Scalar,
};

pub type PubRing = Vec<RistrettoPoint>;

pub trait PublicKeyComputable {
    fn compute_pubkey(&self) -> RistrettoPoint;
}

impl PublicKeyComputable for Scalar {
    fn compute_pubkey(&self) -> RistrettoPoint {
        self * RISTRETTO_BASEPOINT_POINT
    }
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

impl LocalByteConvertible for RistrettoPoint {
    fn to_bytes(&self) -> [u8; 32] {
        self.compress().to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> AResult<Self> {
        let compressed = CompressedRistretto::from_slice(bytes)
            .map_err(|_| anyhow!("Invalid bytes {bytes:?} length or format"))?;
        let point = compressed
            .decompress()
            .ok_or_else(|| anyhow!("Bytes {bytes:?} do not represent a valid Ristretto point"))?;
        Ok(point)
    }

    fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    fn from_base58(input: String) -> AResult<Self> {
        let bytes = bs58::decode(input).into_vec()?;

        Self::from_bytes(&bytes)
    }
}

impl LocalByteConvertible for Scalar {
    fn to_bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> AResult<Self>
    where
        Self: Sized,
    {
        let bytes_array: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow!(
                "Invalid byte length for Scalar, expected 32, got {}",
                bytes.len()
            )
        })?;
        Scalar::from_canonical_bytes(bytes_array)
            .into()
            .ok_or_else(|| anyhow!("Bytes do not represent a canonical Scalar"))
    }

    fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    fn from_base58(input: String) -> AResult<Self>
    where
        Self: Sized,
    {
        let bytes = bs58::decode(input).into_vec()?;
        Self::from_bytes(&bytes)
    }
}
