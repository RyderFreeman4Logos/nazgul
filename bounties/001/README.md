# Round 001 · 100 synthetic voters

**Does Xi Jinping Look Like Winnie the Pooh?** This local test uses the first 100 names in Mandate's shuffled synthetic activity roster (`mandate-dev-drafts` commit `073a7e5`, `voter-names/1000-voters.txt`). Every ballot is signed over the same complete ring.

| Answer ID | Choice | Votes |
| --- | --- | ---: |
| `opt-like` | Looks alike | 60 |
| `opt-unlike` | Does not look alike | 20 |
| `opt-abstain` | Abstain | 20 |

## Run a known-answer test

On Linux, install Rust, just, uv, age, age-keygen and GNU coreutils. Allow more than 4 GiB of available memory. From the repository root, run:

```sh
just bounty-test
just bounty-self-test "$HOME/tmp"
just bounty-features
```

Use an existing scratch directory outside the checkout. The self-test creates its own single-use organizer identity, a new random answer and a seven-byte `SUCCESS` file. It opens the sealed payload with the correct answer, compares all seven bytes, then rejects an incorrect answer with the same tally. The private temporary directory is removed when the test exits. The [coverage table](COVERAGE.md) lists the additional toolchain requirements and maps the feature checks to their evidence.

## What is verified

`voters.csv` has one `name,public_key` row per synthetic voter, sorted by the Base58 encoding of the compressed public key. `ballots.jsonl` contains the public options and signatures in an independent random order. Nazgul sorts the ring itself by compressed key bytes. Ballots sign the ASCII bytes `nazgul-bounty-001`, NUL, the question exactly as printed above, NUL, and the answer ID.

The generator uses SHA-512 and BLAKE3-512 with direct and streaming signing, 25 ballots per combination. Every voter also supplies a SHA-512 signature on their ballot, giving the auditor one common key-image domain for duplicate checks. The auditor verifies each of the 150 signatures through both the precomputed and streaming verification APIs, checks unique SHA-512 key images, and checks the roster, suite counts and exact tally. An additional BLAKE3 signature establishes validity under that suite. The public data carries no cross-suite proof of signer identity.

The answer is a two-column UTF-8 CSV of `name,option_id` without a header. The checker accepts any row order, orders rows by roster public key and joins them with LF without a final newline. SHA3-512 followed by Argon2id v19 (4 GiB, 120 passes, one lane) derives the age X25519 identity for `secret.age`. A separate organizer recipient protects the answer backup. The secret file can contain arbitrary bytes from 1 to 65,536 bytes. Keep the source secret, answer CSV and recovered output outside the checkout.

See the [organizer skill](../../skills/nazgul-bounty-organizer/SKILL.md) to retain a draw and the [challenger skill](../../skills/nazgul-bounty-challenger/SKILL.md) to verify one.
