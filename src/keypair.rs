use crate::prelude::*;
use crate::scalar::{LocalByteConvertible, PublicKeyComputable, RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};

/// A keypair containing a secret key (`Scalar`) and a public key (`RistrettoPoint`).
#[derive(Clone, Debug)]
pub struct KeyPair {
    secret: Scalar,
    public: RistrettoPoint,
}

impl KeyPair {
    /// Creates a new `KeyPair` from a secret `Scalar`.
    /// The public key is computed from the secret key.
    pub fn new(secret: Scalar) -> Self {
        let public = secret.compute_pubkey();
        Self { secret, public }
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

    /// Returns a reference to the secret key.
    pub fn secret(&self) -> &Scalar {
        &self.secret
    }

    /// Consumes the `KeyPair` and returns the secret and public keys.
    pub fn into_keys(self) -> (Scalar, RistrettoPoint) {
        (self.secret, self.public)
    }
}

impl LocalByteConvertible for KeyPair {
    /// Returns the byte representation of the secret key.
    /// Note: This exposes the secret key.
    fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Creates a `KeyPair` from a byte slice representing the secret key.
    fn from_bytes(bytes: &[u8]) -> AResult<Self>
    where
        Self: Sized,
    {
        let secret = Scalar::from_bytes(bytes)?;
        Ok(Self::new(secret))
    }

    /// Returns the base58-encoded string of the secret key.
    /// Note: This exposes the secret key.
    fn to_base58(&self) -> String {
        self.secret.to_base58()
    }

    /// Creates a `KeyPair` from a base58-encoded string representing the secret key.
    fn from_base58(input: String) -> AResult<Self>
    where
        Self: Sized,
    {
        let secret = Scalar::from_base58(input)?;
        Ok(Self::new(secret))
    }
}
