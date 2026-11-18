---
name: nazgul-bounty-organizer
description: Prepare a local 100-voter Nazgul test draw, seal a supplied payload to its answer, and retain an encrypted organizer copy for verification.
---

# Prepare the fixture

Use the [round specification](../../bounties/001/README.md) and its original synthetic roster. Place the payload in a local file outside the checkout. For a smoke test, `just bounty-self-test SCRATCH` creates its own `SUCCESS` file and temporary organizer identity.

For a retained test, choose a public age X25519 recipient whose identity the organizer holds. Supply two new, separate output directories outside the checkout, with existing parents:

```sh
just bounty-generate PUBLIC_DIR PRIVATE_DIR AGE_RECIPIENT SECRET_FILE
just bounty-audit PUBLIC_DIR
```

Record the source commit with the fixture. Preserve `PRIVATE_DIR/challenge-answer.csv.age` and the organizer identity separately. The answer can be recovered using `age -d -i ORGANIZER_IDENTITY -o PRIVATE_ANSWER PRIVATE_DIR/challenge-answer.csv.age` inside an owner-only directory outside the checkout. Run `just bounty-open PUBLIC_DIR PRIVATE_ANSWER NEW_PRIVATE_OUTPUT` and compare the output with the original payload.

Only the public directory is intended for sharing. The [feature matrix](../../bounties/001/COVERAGE.md) identifies the separate hardware, native and WASM checks.
