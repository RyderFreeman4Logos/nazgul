//! Default-ring-hash vectors from BLAKE3's official test_vectors/test_vectors.json.
//! Source: https://github.com/BLAKE3-team/BLAKE3/blob/f55849f89cd85083c1c9daa2c5de20766f309c00/test_vectors/test_vectors.json
//! Its input pattern is bytes 0..250 repeated. Hashing a compressed ring does not
//! decompress points, so the 64-byte vector exercises the encoding contract directly.

use curve25519_dalek::ristretto::CompressedRistretto;
use nazgul::ring::Ring;

#[test]
fn default_hash_matches_official_empty_blake3_vector() {
    assert_eq!(
        Ring::from_compressed(vec![]).canonical_hash().0,
        [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62
        ]
    );
}

#[test]
fn default_hash_matches_official_64_byte_blake3_vector() {
    let first = CompressedRistretto(core::array::from_fn(|i| i as u8));
    let second = CompressedRistretto(core::array::from_fn(|i| (i + 32) as u8));
    let sorted = Ring::from_compressed(vec![first, second]);
    let shuffled = Ring::from_compressed(vec![second, first]);
    assert_eq!(
        sorted.canonical_hash().0,
        [
            0x4e, 0xed, 0x71, 0x41, 0xea, 0x4a, 0x5c, 0xd4, 0xb7, 0x88, 0x60, 0x6b, 0xd2, 0x3f,
            0x46, 0xe2, 0x12, 0xaf, 0x9c, 0xac, 0xeb, 0xac, 0xdc, 0x7d, 0x1f, 0x4c, 0x6d, 0xc7,
            0xf2, 0x51, 0x1b, 0x98
        ]
    );
    assert_eq!(shuffled.canonical_hash(), sorted.canonical_hash());
}
