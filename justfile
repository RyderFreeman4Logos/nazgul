cargo_home := "$(git rev-parse --show-toplevel)/.cargo-local"


# Default recipe
default: pre-commit

# Run all tests and checks to ensure CI passes
pre-commit: test check-fmt clippy audit check-chinese

# Run all tests
test: test-default test-serde test-no-std

# Run default feature tests
test-default:
    CARGO_HOME={{cargo_home}} cargo test --verbose

# Run serde tests
test-serde:
    CARGO_HOME={{cargo_home}} cargo test --features serde-derive --verbose

# Run no_std tests
test-no-std:
    CARGO_HOME={{cargo_home}} cargo test --no-default-features --features no_std --verbose

# Check formatting
check-fmt:
    CARGO_HOME={{cargo_home}} cargo fmt
    git add -A

# Run all clippy checks
clippy: clippy-default clippy-no-std clippy-serde

# Run clippy
clippy-default:
    CARGO_HOME={{cargo_home}} cargo clippy -- -D warnings

# Run clippy on no_std
clippy-no-std:
    CARGO_HOME={{cargo_home}} cargo clippy --no-default-features --features no_std -- -D warnings

# Run clippy on serde
clippy-serde:
    CARGO_HOME={{cargo_home}} cargo clippy --features serde-derive -- -D warnings

# Run security audit
audit:
    CARGO_HOME={{cargo_home}} cargo audit

check-chinese:
    @echo "Checking for Chinese characters..."
    @! rg "\\p{Script=Han}" . --vimgrep --glob '!target/**' --glob '!.git/**' --glob '!.cargo-local/**' --glob '!mandate-dev-drafts/**'
