#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_cursor_position/vectors.txt: the cursor
# registers Linux programs on every pipe of a DCN4 stream, from the Linux
# tree's own functions compiled on the host (amdgpu_dm's
# amdgpu_dm_plane_get_cursor_position, dcn401_set_cursor_position with
# adjust_hotspot_between_slices_for_2x_magnify, resource_can_pipe_disable_
# cursor, hubp401_cursor_set_position and dpp401_set_cursor_position, and
# DC's fixed-point helpers). See harness.c for the line format.
#   drivers/gpu/tests/dcn401_cursor_position/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_cursor_position/check.sh --generate [linux-tree] > vectors.txt
# inputs.txt is gen_inputs.py's output. amdgpu_dcn401_cursor.rs must produce
# Linux's output for every line (the dcn401-cursor kernel tests replay them).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
d=$linux/drivers/gpu/drm/amd/display
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Print from the first line matching $2 in $1 through the next line that
# matches $3 (both included).
range() {
	START="$2" END="$3" awk '!on && $0 ~ ENVIRON["START"] { on = 1 }
		on { print } on && $0 ~ ENVIRON["END"] { exit }' "$1"
}
x() {
	local out
	out=$(range "$@")
	[ -n "$out" ] || { echo "not found in $1: $2" >&2; exit 1; }
	printf '%s\n\n' "$out"
}
python3 "$here/gen_inputs.py" > "$work/inputs.txt"
cmp -s "$work/inputs.txt" "$here/inputs.txt" ||
	{ echo "inputs.txt is not gen_inputs.py's output" >&2; exit 1; }
{
	# DC's fixed-point helpers, without their includes.
	grep -v '^#include' "$d/dc/basics/fixpt31_32.c"
	x "$d/amdgpu_dm/amdgpu_dm_plane.c" '^int amdgpu_dm_plane_get_cursor_position\(' '^}'
	x "$d/dc/core/dc_resource.c" '^bool resource_can_pipe_disable_cursor\(' '^}'
	x "$d/dc/hwss/dcn401/dcn401_hwseq.c" '^void adjust_hotspot_between_slices_for_2x_magnify\(' '^}'
	x "$d/dc/hwss/dcn401/dcn401_hwseq.c" '^void dcn401_set_cursor_position\(' '^}'
	x "$d/dc/hubp/dcn401/dcn401_hubp.c" '^void hubp401_cursor_set_position\(' '^}'
	x "$d/dc/dpp/dcn401/dcn401_dpp_cm.c" '^void dpp401_set_cursor_position\(' '^}'
} > "$work/linux.inc"
cc -O1 -w -I"$work" -I"$d" -I"$d/dc" "$here/harness.c" -o "$work/cursor"

if [ $generate -eq 1 ]; then
	echo "# Linux DCN4 cursor registers per pipe for amdgpu_dcn401_cursor.rs; see check.sh."
	echo "# cx cy cw ch ref pix n (seg layer rx ry rw rh vx vy vw vh ratio src_w src_h slice_w){n}"
	echo "#   = (enable x y hot_x hot_y dst_x_offset cur0_enable){n}"
	# Each configuration's name line (from gen_inputs.py) stays.
	tail -n +2 "$work/inputs.txt" | while read -r in; do
		case $in in
		'') continue ;;
		'#'*) echo "$in" ;;
		*) echo "$in = $(echo "$in" | "$work/cursor")" ;;
		esac
	done
	exit 0
fi
fail=0
n=0
while IFS= read -r line; do
	case $line in '' | '#'*) continue ;; esac
	in=${line%% = *}
	want=${line#* = }
	got=$(echo "$in" | "$work/cursor")
	n=$((n + 1))
	if [ "$got" != "$want" ]; then
		echo "MISMATCH: $in" >&2
		echo "  linux:  $got" >&2
		echo "  vector: $want" >&2
		fail=1
	fi
done < "$here/vectors.txt"
[ $fail -eq 0 ] || exit 1
echo "dcn401_cursor_position: $n vectors match Linux"
