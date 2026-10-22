#!/usr/bin/env bash
set -euo pipefail
linux=${1:-/usr/src/linux}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 "$here/extract.py" "$linux" "$work"
for kind in vendor pcon; do
    cc -std=c11 -O2 -Wall -Wextra -Werror "$work/$kind.c" -o "$work/$kind"
    "$work/$kind"
done
