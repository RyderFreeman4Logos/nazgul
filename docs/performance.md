# Native Target Performance Guide

This guide covers compiler flags, feature selection, and backend behaviour
for native (non-WASM) targets. For WebAssembly, see [`WASM.md`](WASM.md).

## Compiler Flags

### `target-cpu=native`

The single most impactful optimisation for native builds. Add to
`.cargo/config.toml`:

```toml
[target.'cfg(not(target_arch = "wasm32"))']
rustflags = ["-C", "target-cpu=native"]
```

**What it enables:**

| Architecture | Effect |
|-------------|--------|
| x86_64 (Intel/AMD with AVX2) | Enables dalek's SIMD backend (runtime AVX2 dispatch), vectorised loops, optimised memcpy |
| aarch64 (Apple Silicon, ARM servers) | General codegen improvements (loop vectorisation, register allocation); dalek uses `serial` backend |
| x86_64 (older CPUs without AVX2) | General codegen improvements; dalek falls back to `serial` backend at runtime |

> **Note**: `target-cpu=native` produces binaries that may not run on older
> CPUs. For portable distribution, omit this flag or use a specific target
> like `target-cpu=haswell`.

### Link-Time Optimisation (LTO)

For release builds where compile time is acceptable:

```toml
[profile.release]
lto = "fat"
codegen-units = 1
```

This allows LLVM to optimise across crate boundaries, which is particularly
beneficial for the curve25519-dalek inlined arithmetic.

## Feature Combinations by Platform

| Platform | Recommended Features | Notes |
|----------|---------------------|-------|
| Server (x86_64) | `default` | Includes `std`, `serde-derive`, `optimized-msm`, `cpu-time` |
| Desktop (x86_64/aarch64) | `default` | Same as server; add `progress-callback` for UI feedback |
| ARM SBC (aarch64, memory-constrained) | `default` | `precomputed-tables` is part of `std` feature chain |
| `no_std` library | `no_std` | Minimal `alloc`-only build, no `cpu-time` or `pow` module |
| Benchmarking | `default` + `progress-callback` | All features active for comprehensive benchmarks |

### Feature Details

| Feature | Default | Effect |
|---------|---------|--------|
| `std` | yes | Full standard library; enables `precomputed-tables` in curve25519-dalek (cached basepoint multiplication table for faster `r_i * G` in BLSAG verify L equation) |
| `optimized-msm` | yes | Uses `vartime_double_scalar_mul_basepoint` and `VartimeRistrettoPrecomputation` for faster sign/verify |
| `serde-derive` | yes | Serde support for all public types; Ring serialises in compressed format |
| `cpu-time` | yes | Enables `pow` module for CPU-time-based cost modelling |
| `progress-callback` | no | Adds `sign_with_rng_and_progress` / `verify_with_progress` variants |
| `no_std` | no | `#![no_std]` with `alloc`; base for `serde-derive` when `std` is off |

## Hash Function Performance

Nazgul's hash function is generic (`H: Digest<OutputSize = U64>`). The BLSAG
verify hot path calls the hash once per ring member (`H(msg || L_j || R_j)`),
so hash performance matters at large ring sizes.

Different hash implementations have different SIMD acceleration profiles:

| Hash | `target-cpu=native` benefit | wasm32 + SIMD128 benefit |
|------|----------------------------|--------------------------|
| SHA-512 | Moderate (AVX2 message scheduling) | None |
| BLAKE2b | Good (AVX2 G function) | None |
| SHA3/Keccak | Minimal (bitwise ops, no SIMD path) | None |
| BLAKE3 | Excellent (AVX2/AVX-512 compression) | Possible (see [BLAKE3#116](https://github.com/BLAKE3-team/BLAKE3/issues/116)) |

> **WASM note**: While `-C target-feature=+simd128` does not affect dalek's
> field arithmetic on wasm32, it may benefit hash functions with SIMD support.
> The impact depends on your chosen `H: Digest` implementation.

## curve25519-dalek Backend Selection

Nazgul depends on `curve25519-dalek` 4.x. On x86_64, dalek compiles both
`simd` (AVX2/AVX512) and `serial` backends, then dispatches at **runtime**
based on detected CPU features. On other architectures, only `serial` is used.

| Target | Backend | Notes |
|--------|---------|-------|
| x86_64 (64-bit) | `simd` with runtime dispatch | AVX2/AVX512 used if CPU supports it; falls back to `serial` |
| i686 / x86 (32-bit) | `serial` | SIMD backend requires 64-bit target |
| aarch64 | `serial` | No NEON backend for dalek field ops in 4.x |
| wasm32 | `serial` (default) | Fiat (formally verified) backend available via explicit `RUSTFLAGS='--cfg curve25519_dalek_backend="fiat"'` override |

The `simd` (AVX2) backend provides ~30-40% speedup for scalar multiplication
over the `serial` backend. Verify which backend is active:

```bash
# Build with verbose output to see backend selection
cargo build --release -vv 2>&1 | grep 'curve25519.*backend'
```

## `optimized-msm` Feature

When enabled (default), BLSAG sign and verify use specialised multi-scalar
multiplication routines instead of generic `multiscalar_mul`:

- **Verify L equation**: `RistrettoPoint::vartime_double_scalar_mul_basepoint(&c_i, &P_i, &r_i)`
  computes `c_i * P_i + r_i * G` in one call, exploiting the fixed basepoint.
- **Verify R equation**: `VartimeRistrettoPrecomputation::new([key_image])` creates
  a precomputed table, then `vartime_mixed_multiscalar_mul` computes
  `c_i * key_image + r_i * H_p(P_i)` per iteration.
- **Sign**: Same optimisations applied to the ring iteration loop.

The precomputation table is built once before the ring loop, amortising setup
cost across all ring members.

## Running Benchmarks

Criterion benchmarks cover BLSAG sign and verify across ring sizes 2-2000:

```bash
# Run all benchmarks
cargo bench

# Run only BLSAG sign benchmarks
cargo bench -- "blsag_sign"

# Run only BLSAG verify benchmarks
cargo bench -- "blsag_verify"

# Compare optimized-msm on vs off
cargo bench -- --save-baseline msm-on
cargo bench --no-default-features --features std,serde-derive,cpu-time -- --save-baseline msm-off
```

Benchmark results are saved to `target/criterion/` with HTML reports.

### Expected Relative Performance

`optimized-msm` impact varies by ring size:

| Ring Size | Expected MSM Speedup |
|-----------|---------------------|
| 2 | Minimal (overhead ≈ benefit) |
| 8-32 | 10-20% for verify |
| 128+ | 15-25% for verify |

> These are rough estimates. Actual numbers depend on CPU, backend, and
> compiler version. Always measure on your target hardware.

## PreparedRing (Precomputed Ring Data)

For repeated operations on the same ring, use `Ring::precompute()` to create
a `PreparedRing` that caches the vartime precomputation tables:

```text
use nazgul::blsag::BLSAG;
use nazgul::ring::Ring;
use nazgul::traits::{SignRef, VerifyRef};

// Precompute once per ring
let prepared = ring.precompute::<Sha512>();

// Sign: k is the signer's Scalar secret key, rng is &mut impl CryptoRng + RngCore
let sig = BLSAG::sign_with_rng::<Sha512, _>(k, &ring, Some(&prepared), msg, &mut rng)?;

// Verify: VerifyRef trait import required
let ok = BLSAG::verify::<Sha512>(&sig, &ring, Some(&prepared), msg);
```

`PreparedRing` is bound to its ring via `RingHash`. Passing it to a different
ring causes `sign_with_rng` to return `Err(SignatureError::RingMismatch)` and
`verify` to return `false`.
