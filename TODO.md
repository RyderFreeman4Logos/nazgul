# TODO

## 1. Refactor `BLSAG::sign` for Memory and Clarity
- [x] **Remove `cs` vector**: The current implementation allocates a vector to store all challenges. We only need to track `c_0` (for the final signature) and the current challenge in the loop. This reduces space complexity from O(N) to O(1).
- [x] **Simplify Loop Logic**: Replace the manual index manipulation and `loop` with a cleaner iterator-based approach using `cycle()` and `skip()`.
- [x] **Direct `r_s` Calculation**: Calculate the signer's response `r_s` immediately after the loop using the final challenge value, avoiding the need to index back into a `cs` array.

## 2. Optimize `Ring::new` Performance
- [x] **Cache Compressed Points**: `RistrettoPoint::compress()` is computationally expensive. The current sorting in `Ring::new` calls this for every comparison (O(N log N) calls).
- [x] **Strategy**:
    1. Pre-calculate compressed bytes for all points (O(N)).
    2. Sort based on these bytes.
    3. Reconstruct the `Ring` with the sorted points.

## 3. Ring Enhancements for Production (New)
- [x] **Serde Support for `Ring`**: Implement `Serialize` and `Deserialize` for the `Ring` struct to facilitate storage and network transmission.
    - *Note*: `RistrettoPoint` serialization should use its compressed form for efficiency.
- [x] **Consensus Hash**: Implement `consensus_hash<D: Digest>()` for `Ring`.
    - *Requirement*: Use SHA3 (Keccak) as the default or recommended hash in examples.
    - *Implementation*: Since `Ring` is already sorted, we can sequentially hash the compressed bytes of all members to produce a deterministic fingerprint.
- [x] **Zstd Compression Investigation**:
    - *Result*: High-entropy elliptic curve points (compressed) are essentially incompressible. Adding Zstd adds overhead without benefit for typical Ring structures.

## 4. Verification
- [x] Run `cargo test --all-features`.
- [x] Verify `serde` functionality with a test case.
- [x] Verify `consensus_hash` determinism.