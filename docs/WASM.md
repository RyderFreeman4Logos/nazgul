# WebAssembly (WASM) Build Guide

Nazgul supports compilation to `wasm32-unknown-unknown` for use in browsers
and other WASM runtimes. This guide covers recommended configurations,
feature selection, and size optimization.

## Quick Start

```bash
# Using the cargo alias (recommended)
cargo wasm-check

# Using wasm-pack for a production .wasm + JS glue
wasm-pack build --target web -- --features wasm
```

## Feature Selection

Nazgul uses Cargo features to control what is compiled. The `wasm` feature
activates `wasm-bindgen` bindings, `std`, and `rand`.

| Target Platform | Recommended Features | Notes |
|-----------------|---------------------|-------|
| Server / Desktop (default) | `default` | Includes `std`, `serde-derive`, `optimized-msm`, `cpu-time` |
| ARM64 / Embedded | `default` | Same as server; no special feature needed |
| WebAssembly | `wasm` | Enables `wasm-bindgen`, `std`, `rand`; excludes `cpu-time` and `pow` module |
| `no_std` (bare metal) | `no_std` | Minimal allocation-only build via `alloc` |

### WASM-Specific Behaviour

When the `wasm` feature is active **or** the target is `wasm32-*`:

- The `pow` module (proof-of-work / timing model) is excluded — it depends
  on `cpu-time` which requires OS threading APIs.
- The `time_model` binary compiles to a no-op stub.
- `getrandom` is configured with the `js` backend so `OsRng` works in
  browsers via `crypto.getRandomValues`.

## wasm-pack Configuration

Create or update `wasm-pack.toml` at the crate root if you want to
customise the wasm-pack build:

```toml
# No special config is needed — defaults work.
# Override profile settings in Cargo.toml [profile.release] instead.
```

### Recommended Cargo.toml Profile for WASM Release Builds

Add these sections to your workspace or crate `Cargo.toml`:

```toml
[profile.release]
opt-level = "z"       # Optimise for size (smallest .wasm)
lto = true            # Full link-time optimisation
codegen-units = 1     # Better optimisation at the cost of compile time
strip = true          # Strip debug info from the binary
```

If you prefer speed over size, use `opt-level = 3` instead of `"z"`.

## Size Optimisation Tips

1. **`opt-level = "z"` + LTO** — the single biggest win. Combines
   aggressive dead-code elimination with size-oriented codegen.

2. **`codegen-units = 1`** — allows LLVM to optimise across the entire
   crate as one unit. Slower to compile but smaller output.

3. **`strip = true`** — removes debug symbols and names from the final
   `.wasm` file.

4. **`wasm-opt`** — wasm-pack runs `wasm-opt -Oz` automatically in
   release mode. If building manually, install `binaryen` and run:
   ```bash
   wasm-opt -Oz -o output.wasm input.wasm
   ```

5. **`wee_alloc`** (optional) — a tiny allocator (~1 KB vs ~10 KB for
   the default allocator). Add to your crate if every byte counts:
   ```rust
   #[cfg(target_arch = "wasm32")]
   #[global_allocator]
   static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
   ```
   Note: `wee_alloc` is unmaintained as of 2023. Consider `dlmalloc` or
   `lol_alloc` as alternatives if you need a minimal allocator.

6. **Avoid pulling in unnecessary features** — only enable `wasm`, not
   `default`. The `default` feature includes `cpu-time` which does not
   compile on wasm32.

## Cargo Aliases

A convenience alias is defined in `.cargo/config.toml`:

```bash
cargo wasm-check   # Compile-check for wasm32-unknown-unknown
```

This runs:
```
cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

## CI

The GitHub Actions workflow includes a `wasm32-unknown-unknown` compile
check that verifies the library builds for WASM on every push and PR.
See `.github/workflows/rust.yml` for details.

## Troubleshooting

### `cpu-time` compile error on wasm32

Ensure you are **not** enabling the `default` features when targeting wasm.
Use `--no-default-features --features wasm` explicitly.

### `getrandom` error: "no suitable implementation"

The `getrandom/js` feature is activated automatically for `wasm32` targets
in `Cargo.toml` via:
```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```
If you see this error, make sure your build tool is passing the correct
target triple (`wasm32-unknown-unknown`).

### Binary size is too large

Follow the size optimisation tips above. The most impactful change is
switching from `opt-level = 3` to `opt-level = "z"` with LTO enabled.
