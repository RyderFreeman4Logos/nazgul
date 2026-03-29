use crate::traits::{Derivable, LocalByteConvertible, PublicKeyComputable};
use anyhow::{anyhow, Result as AResult};
use bs58;
use core::convert::TryInto;
use digest::{generic_array::typenum::U64, Digest};

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

impl PublicKeyComputable for Scalar {
    fn compute_pubkey(&self) -> RistrettoPoint {
        self * RISTRETTO_BASEPOINT_POINT
    }
}

impl LocalByteConvertible for RistrettoPoint {
    fn to_bytes(&self) -> [u8; 32] {
        self.compress().to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> AResult<Self> {
        let compressed = CompressedRistretto::from_slice(bytes)
            .map_err(|_| anyhow!("Invalid bytes {bytes:?} length or format"))?;
        let point = compressed.decompress().ok_or(anyhow!(
            "Bytes {bytes:?} do not represent a valid Ristretto point"
        ))?;
        Ok(point)
    }

    fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    fn from_base58(input: String) -> AResult<Self> {
        let bytes = bs58::decode(input)
            .into_vec()
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Self::from_bytes(&bytes)
    }
}

/// Computes the derivation tweak from a public key and derivation data.
///
/// Tweak = H(public_key || derivation_data)
pub fn compute_derivation_tweak<H: Digest<OutputSize = U64> + Clone + Default>(
    public_key: &RistrettoPoint,
    derivation_data: &[u8],
) -> Scalar {
    let mut hasher = H::default();
    hasher.update(public_key.to_bytes());
    hasher.update(derivation_data);
    Scalar::from_hash(hasher)
}

impl Derivable for RistrettoPoint {
    fn derive_child<H: Digest<OutputSize = U64> + Clone + Default>(
        &self,
        derivation_data: &[u8],
    ) -> Self {
        let tweak = compute_derivation_tweak::<H>(self, derivation_data);
        let tweak_point = tweak * RISTRETTO_BASEPOINT_POINT;
        self + tweak_point
    }
}

impl Derivable for Scalar {
    fn derive_child<H: Digest<OutputSize = U64> + Clone + Default>(
        &self,
        derivation_data: &[u8],
    ) -> Self {
        let public_key = self.compute_pubkey();
        let tweak = compute_derivation_tweak::<H>(&public_key, derivation_data);
        self + tweak
    }
}

impl LocalByteConvertible for Scalar {
    fn to_bytes(&self) -> [u8; 32] {
        Scalar::to_bytes(self)
    }

    fn from_bytes(bytes: &[u8]) -> AResult<Self> {
        let bytes_array: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow!(
                "Invalid byte length for Scalar, expected 32, got {}",
                bytes.len()
            )
        })?;
        Option::from(Scalar::from_canonical_bytes(bytes_array))
            .ok_or(anyhow!("Bytes do not represent a canonical Scalar"))
    }

    fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    fn from_base58(input: String) -> AResult<Self> {
        let bytes = bs58::decode(input)
            .into_vec()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_ristretto_point_byte_conversion() {
        let mut csprng = OsRng::default();
        let original_point = RistrettoPoint::random(&mut csprng);
        let bytes = original_point.to_bytes();
        let recovered_point = RistrettoPoint::from_bytes(&bytes).unwrap();
        assert_eq!(original_point, recovered_point);
    }

    #[test]
    fn test_ristretto_point_base58_conversion() {
        let mut csprng = OsRng::default();
        let original_point = RistrettoPoint::random(&mut csprng);
        let base58_str = original_point.to_base58();
        let recovered_point = RistrettoPoint::from_base58(base58_str).unwrap();
        assert_eq!(original_point, recovered_point);
    }

    #[test]
    fn test_ristretto_point_invalid_bytes() {
        // Use a byte sequence that is known not to be a valid compressed point.
        let invalid_bytes = [255u8; 32];
        let result = RistrettoPoint::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_scalar_byte_conversion() {
        let mut csprng = OsRng::default();
        let original_scalar = Scalar::random(&mut csprng);
        let bytes = original_scalar.to_bytes();
        let recovered_scalar = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(original_scalar, recovered_scalar);
    }

    #[test]
    fn test_scalar_base58_conversion() {
        let mut csprng = OsRng::default();
        let original_scalar = Scalar::random(&mut csprng);
        let base58_str = original_scalar.to_base58();
        let recovered_scalar = Scalar::from_base58(base58_str).unwrap();
        assert_eq!(original_scalar, recovered_scalar);
    }

    #[test]
    fn test_scalar_invalid_bytes() {
        // A non-canonical scalar representation (a value >= l)
        let high_order_bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let result = Scalar::from_bytes(&high_order_bytes);
        assert!(result.is_err());

        let wrong_length_bytes = [0u8; 31];
        let result = Scalar::from_bytes(&wrong_length_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_pubkey_computation() {
        let mut csprng = OsRng::default();
        let secret = Scalar::random(&mut csprng);
        let public = secret.compute_pubkey();
        assert_eq!(public, secret * RISTRETTO_BASEPOINT_POINT);
    }
}
