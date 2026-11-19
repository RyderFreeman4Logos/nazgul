---
name: nazgul-bounty-challenger
description: Validate the Nazgul 100-voter synthetic poll, test the fork's feature matrix, and open a sealed fixture with its supplied answer.
---

# Validate a local round

Read the [round](../../bounties/001/README.md) for artifact formats and the [feature matrix](../../bounties/001/COVERAGE.md) for build requirements and evidence.

Run `just bounty-self-test /absolute/private/scratch` to generate a fresh roster, signatures, organizer identity, answer and sealed `SUCCESS` payload. It verifies the entire draw, decrypts the organizer's answer, compares the recovered payload byte for byte and checks that swapping two different choices fails. Report the command's exit status and the observed checks.

For an existing fixture, trust the published `SHA256SUMS` and keep the fixture unchanged while checking it. Use an owner-only `TMPDIR` for the audit snapshot. Run `just bounty-audit PUBLIC_DIR` before using the supplied answer. Use `just bounty-check PUBLIC_DIR ANSWER_CSV` for status only or `just bounty-open PUBLIC_DIR ANSWER_CSV NEW_PRIVATE_OUTPUT` to recover the bytes. Keep the answer CSV and recovered output outside the checkout in owner-only directories. The CSV must be a regular file owned by you, without a file-level symbolic link or group/other write access.

Run `just bounty-features` for the additional fork paths. Record the tested commit, runtime and failed or skipped checks. Publish only with the organizer's authorization.
