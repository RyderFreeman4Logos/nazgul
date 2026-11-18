#!/usr/bin/env bash
set -euo pipefail
umask 077

scratch=$(realpath -e -- "$1")
case "$scratch/" in
    "$(git rev-parse --show-toplevel)/"*) echo "Choose a scratch directory outside the checkout." >&2; exit 1 ;;
esac
work=$(mktemp -d -- "$scratch/nazgul-self-test.XXXXXXXX")
trap 'rm -r -- "$work"' EXIT
age-keygen -o "$work/organizer.key" 2>"$work/keygen.log"
recipient=$(age-keygen -y "$work/organizer.key")
printf SUCCESS > "$work/input"
just bounty-generate "$work/public" "$work/private" "$recipient" "$work/input"
just bounty-audit "$work/public"
age -d -i "$work/organizer.key" -o "$work/answer.csv" "$work/private/challenge-answer.csv.age"
just bounty-open "$work/public" "$work/answer.csv" "$work/recovered"
cmp "$work/input" "$work/recovered"
test "$(stat -c %a "$work/recovered")" = 600

# Swap unlike choices: the wrong answer still has the complete roster and the same tally.
python3 - "$work/answer.csv" "$work/wrong.csv" <<'PY'
import sys
from pathlib import Path
rows = [row.split(",") for row in Path(sys.argv[1]).read_text().splitlines()]
other = next(i for i, row in enumerate(rows) if row[1] != rows[0][1])
rows[0][1], rows[other][1] = rows[other][1], rows[0][1]
Path(sys.argv[2]).write_text("\n".join(",".join(row) for row in rows))
PY
if just bounty-open "$work/public" "$work/wrong.csv" "$work/rejected" >"$work/negative.log" 2>&1; then
    echo "Wrong answer unexpectedly opened the envelope." >&2
    exit 1
fi
grep -Fq 'Answer does not match the published recipient.' "$work/negative.log"
test ! -e "$work/rejected"
echo "PASS: recovered SUCCESS byte for byte; a different 60/20/20 answer was rejected."
