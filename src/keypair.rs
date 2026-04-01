use crate::scalar::{compute_derivation_tweak, RistrettoPoint, Scalar, RISTRETTO_BASEPOINT_POINT};
use crate::traits::{Derivable, LocalByteConvertible, PublicKeyComputable};
use anyhow::Result as AResult;
use core::fmt;
use digest::{generic_array::typenum::U64, Digest};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(feature = "std")]
use std::string::String;

/// A keypair containing a secret key (`Scalar`) and a public key (`RistrettoPoint`).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPair {
    secret: Option<Scalar>,
    public: RistrettoPoint,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secret_debug = if self.secret.is_some() {
            "<REDACTED>"
        } else {
            "None"
        };

        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .field("secret", &secret_debug)
            .finish()
    }
}

impl KeyPair {
    /// Creates a new `KeyPair` from a secret `Scalar`.
    /// The public key is computed from the secret key.
    pub fn new(secret: Scalar) -> Self {
        let public = secret.compute_pubkey();
        Self {
            secret: Some(secret),
            public,
        }
    }

    /// Creates a new `KeyPair` from a public key (`RistrettoPoint`) only.
    /// This `KeyPair` will not contain a secret key.
    pub fn from_public_key_only(public: RistrettoPoint) -> Self {
        Self {
            secret: None,
            public,
        }
    }

    /// Generates a new random `KeyPair`.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = Scalar::random(rng);
        Self::new(secret)
    }

    /// Returns a reference to the public key.
    pub fn public(&self) -> &RistrettoPoint {
        &self.public
    }

    /// Returns a reference to the secret key, if present.
    pub fn secret(&self) -> Option<&Scalar> {
        self.secret.as_ref()
    }

    /// Consumes the `KeyPair` and returns the secret and public keys.
    ///
    /// The secret scalar is moved out before Drop runs, so it will NOT be
    /// zeroized by this type — the caller assumes ownership and responsibility.
    pub fn into_keys(mut self) -> (Option<Scalar>, RistrettoPoint) {
        let secret = self.secret.take();
        let public = self.public;
        (secret, public)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        if let Some(ref mut scalar) = self.secret {
            scalar.zeroize();
        }
    }
}

impl Derivable for KeyPair {
    /// Derives a child `KeyPair` from a parent `KeyPair` using non-hardened derivation.
    ///
    /// The derivation is performed by creating a tweak from the master public key and
    /// the derivation data. This ensures that public key derivation can be performed
    /// by parties who only have the public key.
    ///
    /// Tweak = H(master_public_key || derivation_data)
    /// child_secret_key = master_secret_key + Tweak
    /// child_public_key = master_public_key + Tweak * G
    fn derive_child<H: Digest<OutputSize = U64> + Clone + Default>(
        &self,
        derivation_data: &[u8],
    ) -> Self {
        let tweak = compute_derivation_tweak::<H>(&self.public, derivation_data);

        // If we have a secret key, derive the child secret key.
        let child_secret = self.secret.map(|s| s + tweak);

        let tweak_point = tweak * RISTRETTO_BASEPOINT_POINT;
        let child_public = self.public + tweak_point;

        Self {
            secret: child_secret,
            public: child_public,
        }
    }
}

impl LocalByteConvertible for KeyPair {
    /// Returns the byte representation of the secret key.
    /// Note: This exposes the secret key.
    ///
    /// # Panics
    ///
    /// Panics if the `KeyPair` does not contain a secret key.
    fn to_bytes(&self) -> [u8; 32] {
        self.secret
            .expect("Cannot convert public-only KeyPair to secret bytes")
            .to_bytes()
    }

    /// Creates a `KeyPair` from a byte slice representing the secret key.
    fn from_bytes(bytes: &[u8]) -> AResult<Self> {
        let secret = Scalar::from_bytes(bytes)?;
        Ok(Self::new(secret))
    }

    /// Returns the base58-encoded string of the secret key.
    /// Note: This exposes the secret key.
    ///
    /// # Panics
    ///
    /// Panics if the `KeyPair` does not contain a secret key.
    fn to_base58(&self) -> String {
        self.secret
            .expect("Cannot convert public-only KeyPair to secret bytes")
            .to_base58()
    }

    /// Creates a `KeyPair` from a base58-encoded string representing the secret key.
    fn from_base58(input: String) -> AResult<Self> {
        let secret = Scalar::from_base58(input)?;
        Ok(Self::new(secret))
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use super::*;
    use crate::traits::Derivable;
    use rand::rngs::OsRng;
    use sha3::Sha3_512;

    #[test]
    fn test_keypair_new() {
        let mut csprng = OsRng::default();
        let secret = Scalar::random(&mut csprng);
        let keypair = KeyPair::new(secret);
        assert_eq!(keypair.secret(), Some(&secret));
        assert_eq!(keypair.public(), &secret.compute_pubkey());
    }

    #[test]
    fn test_keypair_from_public_key_only() {
        let mut csprng = OsRng::default();
        let secret = Scalar::random(&mut csprng);
        let public = secret.compute_pubkey();
        let keypair = KeyPair::from_public_key_only(public);
        assert_eq!(keypair.secret(), None);
        assert_eq!(keypair.public(), &public);
    }

    #[test]
    fn test_keypair_generate() {
        let mut csprng = OsRng::default();
        let keypair = KeyPair::generate(&mut csprng);
        assert_eq!(
            keypair.public(),
            &keypair.secret().unwrap().compute_pubkey()
        );
    }

    #[test]
    fn test_keypair_into_keys() {
        let mut csprng = OsRng::default();
        let secret = Scalar::random(&mut csprng);
        let keypair = KeyPair::new(secret);
        let (s, p) = keypair.into_keys();
        assert_eq!(s, Some(secret));
        assert_eq!(p, secret.compute_pubkey());
    }

    #[test]
    fn test_keypair_byte_conversion() {
        let mut csprng = OsRng::default();
        let original_keypair = KeyPair::generate(&mut csprng);
        let bytes = original_keypair.to_bytes();
        let recovered_keypair = KeyPair::from_bytes(&bytes).unwrap();
        assert_eq!(original_keypair, recovered_keypair);
    }

    #[test]
    #[should_panic(expected = "Cannot convert public-only KeyPair to secret bytes")]
    fn test_keypair_public_only_to_bytes_panic() {
        let mut csprng = OsRng::default();
        let secret = Scalar::random(&mut csprng);
        let public = secret.compute_pubkey();
        let keypair = KeyPair::from_public_key_only(public);
        keypair.to_bytes();
    }

    #[test]
    fn test_keypair_base58_conversion() {
        let mut csprng = OsRng::default();
        let original_keypair = KeyPair::generate(&mut csprng);
        let base58_str = original_keypair.to_base58();
        let recovered_keypair = KeyPair::from_base58(base58_str).unwrap();
        assert_eq!(original_keypair, recovered_keypair);
    }

    #[test]
    fn test_keypair_invalid_bytes() {
        let wrong_length_bytes = [0u8; 31];
        let result = KeyPair::from_bytes(&wrong_length_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_debug_format() {
        let mut csprng = OsRng::default();
        let keypair = KeyPair::generate(&mut csprng);
        let debug_str = format!("{:?}", keypair);
        assert!(debug_str.contains("public"));
        assert!(debug_str.contains("<REDACTED>"));
        assert!(!debug_str.contains(&format!("{:?}", keypair.secret().unwrap())));

        let public_only = KeyPair::from_public_key_only(*keypair.public());
        let debug_str_pub = format!("{:?}", public_only);
        assert!(debug_str_pub.contains("None"));
    }

    #[test]
    fn test_keypair_derivation() {
        let mut csprng = OsRng::default();
        let master_keypair = KeyPair::generate(&mut csprng);
        let derivation_data = b"my derivation path";

        // Derive the child keypair from the master keypair
        let child_keypair = master_keypair.derive_child::<Sha3_512>(derivation_data);

        // For non-hardened derivation, it must be possible to derive the child
        // public key from the master public key, without access to the private key.
        let child_pubkey_from_master_pubkey = master_keypair
            .public()
            .derive_child::<Sha3_512>(derivation_data);

        // The public key of the derived keypair should match the public key derived
        // from the master public key.
        assert_eq!(child_keypair.public(), &child_pubkey_from_master_pubkey);

        // Derivation should be deterministic
        let another_child_keypair = master_keypair.derive_child::<Sha3_512>(derivation_data);
        assert_eq!(child_keypair, another_child_keypair);

        // Different derivation data should result in a different keypair
        let different_child_keypair = master_keypair.derive_child::<Sha3_512>(b"other data");
        assert_ne!(child_keypair, different_child_keypair);
    }

    #[test]
    fn test_public_only_derivation() {
        let mut csprng = OsRng::default();
        let master_secret = Scalar::random(&mut csprng);
        let master_public = master_secret.compute_pubkey();

        let master_keypair_full = KeyPair::new(master_secret);
        let master_keypair_pub = KeyPair::from_public_key_only(master_public);

        let derivation_data = b"view only derivation";

        // Derive from full keypair
        let child_full = master_keypair_full.derive_child::<Sha3_512>(derivation_data);

        // Derive from public only keypair
        let child_pub = master_keypair_pub.derive_child::<Sha3_512>(derivation_data);

        // Public keys should match
        assert_eq!(child_full.public(), child_pub.public());

        // Child from public only should have no secret
        assert_eq!(child_pub.secret(), None);

        // Child from full should have secret
        assert!(child_full.secret().is_some());
    }
}
