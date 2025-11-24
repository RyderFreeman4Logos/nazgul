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