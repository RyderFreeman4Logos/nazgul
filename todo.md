# Hash Security Hardening — Issues #20-#23

Version bump: 2.1.0 → 3.0.0 (breaking: domain separation + PreparedRing<H>)

## Debate Consensus (CSA Session 01KKV1G2XD11FKBX6F4JDRM1R7)

- PhantomData<H> on PreparedRing (compile-time safety, zero runtime cost)
- Domain separation tags on all hash calls (protocol break)
- Batch all breaking changes into single v3.0.0 release
- SecretScalar wrapping is non-breaking internal improvement (do first)
- BLAKE3 as optional feature with documented security margin

## Tasks

### T1: SecretScalar wrapping (#23) [non-breaking]

Wrap the secret key parameter `k: Scalar` in `SecretScalar` inside
`sign_with_rng` and `sign_precomputed` for zeroization on drop.
Use Option B (internal wrapping, non-breaking API).

Files: `src/blsag/sign.rs`

DONE WHEN:
- `sign_with_rng` wraps `k` in `SecretScalar` immediately on entry
- `sign_precomputed` does the same where applicable
- `just pre-commit` exits 0
- No API signature changes (k remains `Scalar` in public API)

### T2: Domain separation tags (#22) [protocol break]

Add domain prefixes to all hash invocations across all 4 schemes:
- H_p (hash-to-point): prefix `b"nazgul-H_p-v3"`
- Challenge hash: prefix `b"nazgul-chal-v3"`

Files: `src/blsag/engine.rs`, `src/blsag/sign.rs`, `src/blsag/verify.rs`,
       `src/clsag.rs`, `src/mlsag.rs`, `src/sag.rs`

DONE WHEN:
- Every `RistrettoPoint::from_hash(H::default().chain_update(...))` includes domain tag
- Every challenge hash `Scalar::from_hash(h)` starts with domain tag
- All 4 schemes (BLSAG, CLSAG, MLSAG, SAG) updated consistently
- `just pre-commit` exits 0
- Tests updated to match new signature format

### T3: PreparedRing<H> type binding (#21) [API break]

Add `PhantomData<H>` to `PreparedRing` so it's bound to a specific hash
function at the type level. Compiler enforces correct usage.

Files: `src/ring.rs`, `src/blsag/sign.rs`, `src/blsag/verify.rs`,
       `src/blsag/mod.rs`, `src/blsag/contextual.rs`, `src/blsag/tests.rs`

DONE WHEN:
- `PreparedRing<H>` has `PhantomData<H>` field
- `Ring::precompute::<H>()` returns `PreparedRing<H>`
- `sign_with_rng::<H, R>(..., precomputed: Option<&PreparedRing<H>>)` enforces H match
- `verify::<H>(..., precomputed: Option<&PreparedRing<H>>)` enforces H match
- Attempting `PreparedRing<Sha512>` with `verify::<Blake2b512>` is a compile error
- `just pre-commit` exits 0

### T4: BLAKE3 XOF wrapper (#20) [feature addition]

Add optional `blake3` feature with `Blake3_512` wrapper implementing
`Digest<OutputSize = U64>` via BLAKE3's XOF mode.

Files: `Cargo.toml`, `src/blake3_compat.rs` (new), `src/lib.rs`

DONE WHEN:
- `blake3` feature in Cargo.toml with optional `blake3` dependency
- `Blake3_512` struct implements `Digest<OutputSize = U64>`
- Doc comments document 128-bit collision resistance alignment with Ristretto255
- `cargo test --features blake3` passes BLSAG sign+verify roundtrip
- `just pre-commit` exits 0 (default features, no blake3 in default)

### T5: Version bump + docs

Bump version to 3.0.0 in Cargo.toml. Update docs/performance.md
hash function table to include BLAKE3 and document domain separation.

Files: `Cargo.toml`, `docs/performance.md`

DONE WHEN:
- `Cargo.toml` version = "3.0.0"
- performance.md hash table updated with BLAKE3 row
- Domain separation documented
- `just pre-commit` exits 0
