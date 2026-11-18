#!/usr/bin/env bash
set -euo pipefail
public=$(realpath -e -- "$1")
(cd -- "$public" && sha256sum voters.csv ballots.jsonl recipient.txt secret.age | cmp - SHA256SUMS)
just _bounty-ballots audit "$public"
