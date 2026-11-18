thumb_target := "thumbv8m.main-none-eabihf"


# Default recipe
default: pre-commit

# Run all tests and checks to ensure CI passes
pre-commit: test bounty-test check-fmt clippy audit check-chinese

# Run all tests
test: test-default test-serde test-no-std test-blake3

# Run default feature tests
test-default:
    cargo test --verbose

# Run serde tests
test-serde:
    cargo test --features serde-derive --verbose

# Run blake3 feature tests
test-blake3:
    cargo test --features blake3 --test blsag_tests --test streaming_equivalence --test contextual_blsag_tests --test serde_tests --verbose

# Run no_std compatibility and behavior checks
test-no-std:
    cargo check --no-default-features --features no_std --target {{thumb_target}} --verbose
    cargo check --manifest-path tests/no_std_consumer/Cargo.toml --target {{thumb_target}} --verbose
    cargo test --no-default-features --features no_std --lib --verbose

# Check formatting
check-fmt:
    cargo fmt
    git add -A

# Run all clippy checks
clippy: clippy-default clippy-no-std clippy-serde clippy-blake3

# Run clippy
clippy-default:
    cargo clippy -- -D warnings

# Run clippy on no_std
clippy-no-std:
    cargo clippy --no-default-features --features no_std --target {{thumb_target}} -- -D warnings

# Run clippy on serde
clippy-serde:
    cargo clippy --features serde-derive -- -D warnings

# Run clippy on blake3
clippy-blake3:
    cargo clippy --features blake3 -- -D warnings

# Run security audit
audit:
    cargo audit

check-wasm:
    cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

check-chinese:
    @echo "Checking for Chinese characters..."
    @! rg "\\p{Script=Han}" . --vimgrep --glob '!target/**' --glob '!.git/**' --glob '!.cargo-local/**' --glob '!mandate-dev-drafts/**'

# Find files exceeding monolith thresholds (800 lines or 8000 tokens)
find-monolith-files:
    @echo "Checking for monolith files (>800 lines)..."
    @find src -name '*.rs' -exec sh -c 'lines=$(wc -l < "$1"); if [ "$lines" -gt 800 ]; then echo "MONOLITH: $1 ($lines lines)"; fi' _ {} \;

import 'bounties/001/features.just'

# Generate an isolated, sealed 100-voter fixture
bounty-generate $public $private $recipient $secret:
    @bash bounties/001/generate.sh "$public" "$private" "$recipient" "$secret"

_bounty-ballots $action $public:
    @ionice -c 3 nice -n 19 cargo run --release --features blake3 --example bounty_ballots -- "$action" "$public"

# Verify the file digests, complete tally and every ballot
bounty-audit $public:
    @bash bounties/001/audit.sh "$public"

# Check a complete answer without disclosing the secret
bounty-check $public $answer:
    @uv run --script bounties/001/answers.py check "$public" "$answer"

# Write the recovered bytes to a new owner-only file
bounty-open $public $answer $output:
    @uv run --script bounties/001/answers.py open "$public" "$answer" "$output"

# Run the fast signature, envelope and negative-control tests
bounty-test:
    @ionice -c 3 nice -n 19 cargo test --features blake3 --example bounty_ballots
    @uv run --script bounties/001/test_answers.py

# Generate an independent answer and verify the full-cost SUCCESS round trip
bounty-self-test $scratch:
    @bash bounties/001/self-test.sh "$scratch"
