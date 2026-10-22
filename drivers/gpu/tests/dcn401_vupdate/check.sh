#!/usr/bin/env bash
set -euo pipefail
linux=${1:-${LINUX_SRC:-/usr/src/linux}}
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 "$script_dir/extract.py" "$linux" "$work/primary.c"
cc -std=c11 -Wall -Wextra -Werror -O2 "$work/primary.c" -o "$work/primary"
"$work/primary" > "$work/vectors.txt"
diff -u "$script_dir/vectors.txt" "$work/vectors.txt"
echo 'PASS: actual Linux DCN401 VUPDATE IRQ table, source IDs, enable/ACK and shared-clear masks (4 physical OTGs)'
