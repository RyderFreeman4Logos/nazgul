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

## 3. Ring Enhancements for Production
- [x] **Serde Support for `Ring`**: Implement `Serialize` and `Deserialize` for the `Ring` struct to facilitate storage and network transmission.
- [x] **Consensus Hash**: Implement `consensus_hash<D: Digest>()` for `Ring`.
- [x] **Zstd Compression Investigation**: Decided against it due to high entropy.

## 4. Contextual BLSAG (Hybrid Storage/Verify)
- [x] **Define `RingHash` Type**: Create a NewType `struct RingHash([u8; 32])` in `src/ring.rs` to strongly type the consensus hash. Implement `Serialize`, `Deserialize`, `Debug`, `Display`, `FromStr`, etc.
- [x] **Define `RingContext` Enum**:
    - `Compact(RingHash)`: For efficient transmission/storage.
    - `Archival(Ring)`: For self-contained backups/sharing.
- [x] **Define `ContextualBLSAG` Struct**:
    - A wrapper containing `sig: BLSAG` and `context: RingContext`.
- [x] **Implement Smart Constructors**:
    - `sign_compact(...)`: Generates signature and stores only the hash.
    - `sign_archival(...)`: Generates signature and stores the full ring.
- [x] **Implement Smart Verification**:
    - `verify(...)`: Accepts an optional external `Ring`.
    - If `Archival`: Uses the internal ring (and optionally validates against external if provided).
    - If `Compact`: **Requires** the external ring, verifies its hash against the stored `RingHash`, then verifies the signature.

## 5. Verification
- [x] Run `cargo test --all-features`.
- [x] Add specific tests for `ContextualBLSAG` covering both Compact and Archival modes.
