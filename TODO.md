# TODO

## 1. Refactor `BLSAG::sign` for Memory and Clarity
- [ ] **Remove `cs` vector**: The current implementation allocates a vector to store all challenges. We only need to track `c_0` (for the final signature) and the current challenge in the loop. This reduces space complexity from O(N) to O(1).
- [ ] **Simplify Loop Logic**: Replace the manual index manipulation and `loop` with a cleaner iterator-based approach using `cycle()` and `skip()`.
- [ ] **Direct `r_s` Calculation**: Calculate the signer's response `r_s` immediately after the loop using the final challenge value, avoiding the need to index back into a `cs` array.

## 2. Optimize `Ring::new` Performance
- [ ] **Cache Compressed Points**: `RistrettoPoint::compress()` is computationally expensive. The current sorting in `Ring::new` calls this for every comparison (O(N log N) calls).
- [ ] **Strategy**:
    1. Pre-calculate compressed bytes for all points (O(N)).
    2. Sort based on these bytes.
    3. Reconstruct the `Ring` with the sorted points.
