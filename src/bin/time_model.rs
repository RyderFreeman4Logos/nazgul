// use curve25519_dalek::scalar::Scalar;
use nazgul::{
    blsag::BLSAG,
    keypair::KeyPair,
    ring::Ring,
    traits::{SignRef, VerifyRef},
};
use rand::rngs::OsRng;

use sha3::Keccak512;
// use blake3::Hasher;
// use blake2::Blake2b512;
// use sha2::Sha512;
use std::time::{Duration, Instant};

const MESSAGE: &[u8] = b"This is a performance benchmark for time modeling.";

fn main() {
    println!("--- BLSAG::verify() Performance Model Data ---");
    println!("Ring Size (n),Avg. Time (nanoseconds)");

    // Expanded ring sizes as requested, up to 10,000
    let ring_sizes = [100, 500, 1000, 2500, 5000, 7500, 10000];

    for &n in &ring_sizes {
        // For very large rings, we do fewer iterations to keep test time reasonable.
        let iterations = if n >= 5000 { 10 } else { 50 };

        let mut csprng = OsRng;
        let signer_keypair = KeyPair::generate(&mut csprng);

        // Create a ring of size n
        let mut public_keys: Vec<_> = (0..(n - 1))
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        public_keys.push(*signer_keypair.public());
        let ring = Ring::new(public_keys);

        // Generate a signature to be verified
        let signature =
            BLSAG::sign::<Keccak512, OsRng>(*signer_keypair.secret(), &ring, None, MESSAGE)
                .unwrap();

        let mut total_duration = Duration::new(0, 0);
        for _ in 0..iterations {
            let start = Instant::now();
            // The volatile read is a simple way to prevent the compiler from optimizing
            // away the function call without needing a full dependency like `criterion::black_box`.
            BLSAG::verify::<Keccak512>(&signature, &ring, None, MESSAGE);
            // unsafe {
            // let _ = std::ptr::read_volatile(&is_valid);
            // }
            total_duration += start.elapsed();
        }

        let avg_nanos = total_duration.as_nanos() / iterations as u128;
        println!("{},{}", n, avg_nanos);
    }

    println!("--- End of Data ---");
}
