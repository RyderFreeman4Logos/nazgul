## Phase 0 — Breaking Changes

Summary of all breaking changes introduced during Phase 0 development.

*   **`serde-derive` feature now pulls in `no_std`**: The `serde-derive` feature compiles without `std` by default.
*   **`pow` module requires `std` feature explicitly**: The proof-of-work module is now gated behind the `std` feature flag.
*   **`consensus_hash` renamed to `canonical_hash`**: Uses a fixed Sha3-512 digest internally; no longer generic over the hash function.
*   **`PrecomputedRingData` now binds to ring identity (`RingHash`)**: Precomputed data carries the ring hash it was computed for.
*   **`sign`/`verify` check ring identity on precomputed data**: Signing and verification reject precomputed data whose `RingHash` does not match the ring.
*   **New `SignatureError::RingMismatch` variant**: Returned when precomputed ring data does not match the ring being used.
*   **`SignatureError` is now `#[non_exhaustive]`**: Downstream `match` statements must include a wildcard arm.
*   **`sign_with_rng` added to BLSAG**: Allows deterministic signature generation by accepting an external RNG.

26a1149924b803b2e5077229b5454ae50b384b0a
### Fix: Deterministic ring member removal

Ensured `Ring::remove_public_key` matches its documented behavior when duplicates exist.

*   **Bug**: The implementation used `binary_search_by`, which may return any matching index in the presence of duplicates. While duplicates are unusual for rings, the method's contract explicitly said it removes the first occurrence.
*   **Fix**: After `binary_search_by` succeeds, the code now scans backward to the first equal compressed-key segment before removing.
*   **Coverage**: Added a unit test for removal when duplicate keys are present, ensuring one occurrence is removed and the ring remains sorted.

fcbfcdbfd24c0383ff89c5dcff617d89bf0db2c4
### Feature: Fake signature generators

Added helpers to efficiently produce *structurally valid* but *cryptographically invalid* signatures for negative testing and stress/load scenarios.

*   **Motivation**: Benchmarks and robustness tests often need to process large volumes of invalid signatures without paying the full cost of real signing. A dedicated generator avoids ad-hoc test code and makes the intent explicit.
*   **API**:
    *   `BLSAG::generate_fake` creates a signature-shaped object with random scalars/points.
    *   `ContextualBLSAG::{generate_fake_compact, generate_fake_archival}` mirror the existing storage modes for end-to-end testing.
*   **Tests**: Added a regression test asserting that a fake signature does not accidentally pass verification.

0fdcc5e06a1bedd8a4619695235840b2282f5aba
### Refactor: RingHash derivation helper

Centralized the "digest output → 32-byte RingHash" conversion into `RingHash::from_output`.

*   **Motivation**: The project needs a stable 32-byte identifier for rings (`RingHash`), while the signing hash (`H`) is typically 64 bytes. Several call sites were duplicating the same truncate/zero-pad logic. Duplicating that logic is easy to get subtly wrong and makes it harder to change the convention later.
*   **Change**: Introduced `RingHash::from_output` and reused it in `RingContext::consensus_hash` and `ContextualBLSAG` hash verification/creation paths.
*   **Design note**: This makes the convention explicit: `RingHash` is defined as the first 32 bytes of the chosen digest output (zero-padded if shorter).

9fbe2987cfb84e05e024d49608c7037ec0636513
### Fix: wasm build gating

*   Gated `pow` out of wasm builds to avoid missing `cpu_time::ThreadTime` on `wasm32-unknown-unknown -F wasm`.
*   Wrapped the `time_model` binary so wasm targets no-op while native targets retain benchmarking output.
*   Verified with `cargo clippy --target wasm32-unknown-unknown -F wasm -- -D warnings` and `cargo test --all --all-features`.

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
4e560b0fef5f4c5f868819f0adc421986a81c2b1
### Chore: ignore local cargo cache

*   Added `.cargo-local` to `.gitignore` to keep workspace-specific tool state out of version control.
c9986eae07061eb7b217b0d8677e98422a2d875e
### Feature: Ring public key mutations

*   Added `add_public_key` and `remove_public_key` helpers that maintain the ring's sorted invariant by reusing the shared in-place sort routine.
*   Extracted `sort_members_in_place` for consistent sorting logic across construction and mutation paths.
*   Covered insertion/removal behaviors with unit tests to ensure ordering and successful removal semantics.
