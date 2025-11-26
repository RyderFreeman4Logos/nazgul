d6ae7f7af414e1681be9402b45cf9b569d4289ce
### Feature: Contextual BLSAG

Introduced `ContextualBLSAG` to support flexible ring management strategies in distributed systems.

*   **Hybrid Storage Models**:
    *   **Compact Mode**: Stores only the `RingHash` (32 bytes). Designed for high-frequency transactions where the Verifier retrieves the Ring from a cache/DB.
    *   **Archival Mode**: Stores the full `Ring` definition. Designed for self-contained proofs, backups, and cross-system sharing.
*   **Smart Verification**:
    *   `verify()` automatically handles context validation.
    *   In Compact mode, it enforces that the provided external ring matches the stored hash.
    *   In Archival mode, it uses the internal ring for verification but can optionally validate against an external ring source.

cea90f32d98197646bee1c73b84bbc0db2195fce
### Feature: Ring Enhancements for Production

Implemented key features to support distributed, caching-heavy architectures for ring signatures.

*   **Serde Support**: `Ring` now implements `Serialize` and `Deserialize`.
    *   It serializes as a simple list of points (`Vec<RistrettoPoint>`).
    *   Deserialization **enforces** the sorting invariant by internally calling `Ring::new()`. This ensures that even manually constructed or potentially tampered JSON loads into a valid, sorted `Ring` object.
*   **Consensus Hash**: Added `Ring::consensus_hash::<D: Digest>()`.
    *   Provides a deterministic fingerprint of the ring's content.
    *   Independent of the input order of keys (due to internal sorting).
    *   Crucial for using Ring IDs in caching (Redis keys) and event sourcing (Version IDs).
    *   Recommended default: `Sha3_256`.
*   **Zstd Investigation**: Concluded that Zstd compression for Rings is unnecessary as compressed Elliptic Curve points are high-entropy.

58c44e0dbc0d29ca90d6af514c5754141eebaa09
### Performance: Ring Initialization

Optimized `Ring::new` to reduce the computational cost of sorting public keys.
*   **Mechanism**: Pre-computed compressed byte representations for all keys before sorting.
*   **Impact**: Reduced sorting complexity from $O(N \log N \times \text{compress})$ to $O(N \times \text{compress} + N \log N \times \text{compare})$. This avoids repeated expensive modular inversions during the sort.

54ba499065068ef89a842e08b76453741f00dd00
### Refactor: BLSAG Signing Optimization

Refactored `BLSAG::sign` to improve memory usage and code clarity.
*   **Memory**: Removed the `cs` vector allocation ($O(N)$), reducing the space complexity to $O(1)$ by tracking only the current challenge and $c_0$.
*   **Readability**: Replaced the manual index tracking loop with a standard Rust iterator chain (`cycle`, `skip`, `take`).
*   **Correctness**: Verified via existing test suite.

5d643de3f6cab17ed6660b6c468a883145882b2d
### Plan: BLSAG Optimization

Created `TODO.md` and `TODO.zh.md` to outline the roadmap for optimizing the bLSAG signature scheme.
The optimization focuses on two key areas:
1.  **Memory & Readability in `sign`**: Reducing heap allocations by removing the `cs` vector (saving O(N) space) and simplifying the challenge generation loop using iterators.
2.  **Performance in `Ring::new`**: Pre-calculating compressed points to avoid repeated expensive curve operations during sorting (O(N log N) -> O(N)).

This planning step ensures a clear path forward before touching the core cryptographic code.