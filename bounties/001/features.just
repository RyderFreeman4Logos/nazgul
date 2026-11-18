# Validate native, embedded-target and WebAssembly feature paths used by the fork.
bounty-features: test-default test-no-std bounty-native-variants bounty-wasm-runtime

bounty-native-variants:
    ionice -c 3 nice -n 19 cargo test --features blake3,progress-callback,smallvec-responses --lib --tests
    ionice -c 3 nice -n 19 cargo test --no-default-features --features std --lib --test blsag_tests --test streaming_equivalence --test ring_hash_vectors
    ionice -c 3 nice -n 19 cargo check --lib --target {{thumb_target}} --no-default-features --features no_std,blake3,progress-callback,smallvec-responses
    ionice -c 3 nice -n 19 cargo run --release --bin time_model

# Build fresh JS and WASM, then exercise both the build and the checked-in package.
bounty-wasm-runtime:
    #!/usr/bin/env bash
    set -euo pipefail
    ionice -c 3 nice -n 19 cargo build --lib --target wasm32-unknown-unknown --no-default-features --features wasm
    output=$(mktemp -d target/wasm32-unknown-unknown/debug/bounty-bindings.XXXXXXXX)
    trap 'rm -r -- "$output"' EXIT
    "${BOUNTY_WASM_BINDGEN:-wasm-bindgen}" --target web --out-dir "$output" target/wasm32-unknown-unknown/debug/nazgul.wasm
    node --experimental-default-type=module bounties/001/wasm.mjs "$output"
    node --experimental-default-type=module bounties/001/wasm.mjs pkg
