#!/usr/bin/env bash
set -euo pipefail
umask 077
public=$(realpath -m -- "$1")
private=$(realpath -m -- "$2")
repo=$(git rev-parse --show-toplevel)
if [[ "$public/" == "$private/"* || "$private/" == "$public/"* ||
      "$public/" == "$repo/"* || "$private/" == "$repo/"* ]]; then
    echo "Use separate new public and private directories outside the checkout." >&2
    exit 1
fi
test -f "$4" && test -r "$4" || { echo "A readable secret file is required." >&2; exit 1; }
mkdir -m 700 -- "$public" "$private"
just _bounty-ballots generate "$public" |
    uv run --script bounties/001/answers.py seal "$public" "$private" "$3" "$4"
(cd -- "$public" && sha256sum voters.csv ballots.jsonl recipient.txt secret.age > SHA256SUMS.pending && mv SHA256SUMS.pending SHA256SUMS)
