#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_cursor_plane/vectors.txt: whether
# amdgpu_dm takes an enabled DRM cursor plane on DCN 4.0.1, from the Linux
# tree's own code compiled on the host (amdgpu_dm_check_native_cursor_state
# and dm_check_cursor_fb from amdgpu_dm_cursor.c, amdgpu_dm_atomic_check's
# DCN 4.x rotation/scaling rule from amdgpu_dm.c, the tiling-flag helpers
# from the amdgpu UAPI). See harness.c for the line format.
#   drivers/gpu/tests/dcn401_cursor_plane/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_cursor_plane/check.sh --generate [linux-tree] > vectors.txt
# inputs.txt is gen_inputs.py's output. drm_native_planes::check_cursor must
# give Linux's answer for every line (a drivers/gpu/drm kernel test replays
# them).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
dm=$linux/drivers/gpu/drm/amd/display/amdgpu_dm
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
	x "$dm/amdgpu_dm_cursor.c" '^static int dm_check_cursor_fb\(' '^}'
	x "$dm/amdgpu_dm_cursor.c" '^int amdgpu_dm_check_native_cursor_state\(' '^}'
} > "$work/linux.inc"
x "$dm/amdgpu_dm.c" '^[[:space:]]+is_rotated = new_cursor_state &&' 'new_cursor_state->crtc_h\)\);' \
	> "$work/scaled.inc"
{
	grep -E '^#define AMDGPU_TILING_(ARRAY_MODE|MICRO_TILE_MODE|SWIZZLE_MODE|GFX12_SWIZZLE_MODE)_(SHIFT|MASK)' \
		"$linux/include/uapi/drm/amdgpu_drm.h"
	x "$linux/include/uapi/drm/amdgpu_drm.h" '^#define AMDGPU_TILING_GET\(' 'AMDGPU_TILING_##field##_MASK\)$'
} > "$work/tiling.inc"
[ "$(grep -c AMDGPU_TILING_ "$work/tiling.inc")" -ge 9 ] ||
	{ echo "tiling helpers not found" >&2; exit 1; }
cc -O1 -w -I"$work" "$here/harness.c" -o "$work/cursor"

grep -v '^#' "$here/inputs.txt" | grep -v '^$' > "$work/lines.txt"
"$work/cursor" < "$work/lines.txt" > "$work/out.txt"
[ "$(wc -l < "$work/lines.txt")" -eq "$(wc -l < "$work/out.txt")" ] ||
	{ echo "harness output short" >&2; exit 1; }
paste -d '=' "$work/lines.txt" "$work/out.txt" | sed 's/=/ = /' > "$work/vectors.txt"

if [ $generate -eq 1 ]; then
	echo "# Linux amdgpu_dm cursor plane checks on DCN 4.0.1 for drm_native_planes.rs; see check.sh."
	echo "# fb_w fb_h pitch mods tiling src_x src_y src_w src_h crtc_w crtc_h = errno"
	cat "$work/vectors.txt"
	exit 0
fi
grep -v '^#' "$here/vectors.txt" > "$work/want.txt"
if ! cmp -s "$work/want.txt" "$work/vectors.txt"; then
	diff "$work/want.txt" "$work/vectors.txt" | head -20 >&2
	echo "dcn401_cursor_plane: vectors differ from Linux" >&2
	exit 1
fi
n=$(wc -l < "$work/vectors.txt")
echo "dcn401_cursor_plane: $n vectors match Linux"
