#!/usr/bin/env bash
set -euo pipefail
public=$(realpath -e -- "$1")
scratch=$(realpath -e -- "${TMPDIR:-$HOME/tmp}")
python3 bounties/001/fixture_files.py private-dir "$scratch"
snapshot=$(mktemp -d -- "$scratch/nazgul-audit.XXXXXXXX")
trap 'rm -r -- "$snapshot"' EXIT
python3 bounties/001/fixture_files.py snapshot "$public" "$snapshot"
just _bounty-ballots audit "$snapshot"
