#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_yuv/vectors.txt: what Linux programs for a
# DCN4 plane's input conversion, from the Linux tree's own code compiled on
# the host: amdgpu_dm's fill_plane_color_attributes (COLOR_ENCODING /
# COLOR_RANGE to a DC color space), dpp401_dpp_setup's pixel-format switch
# (CNVC pixel format, alpha, input CSC select, the default color space)
# and dpp3_program_post_csc's choice of dpp_input_csc_matrix entry, packed as
# cm_helper_program_color_matrices writes CM_POST_CSC_C11_C12..C33_C34;
# also hubp2_program_pixel_format's DCSURF_SURFACE_PIXEL_FORMAT and crossbar.
# See harness.c for the line format.
#   drivers/gpu/tests/dcn401_yuv/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_yuv/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_dcn401_dpp.rs / amdgpu_dcn401_surface.rs must produce Linux's
# output for every line (the dcn401-dpp kernel tests replay them).
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
{
	x "$d/dc/dc_hw_types.h" '^enum surface_pixel_format \{' '^};'
	x "$d/dc/dc_hw_types.h" '^enum dc_color_space \{' '^};'
	x "$d/dc/dpp/dcn10/dcn10_dpp.h" '^enum dcn10_input_csc_select \{' '^};'
	x "$d/dc/inc/hw/dpp.h" '^struct dpp_input_csc_matrix \{' '^};'
	x "$d/dc/inc/hw/dpp.h" '^static const struct dpp_input_csc_matrix' '^};'
	# (its "STATIC_IFN_KUNIT int" line precedes it)
	echo 'static int'
	x "$d/amdgpu_dm/amdgpu_dm.c" '^fill_plane_color_attributes\(' '^}'
} > "$work/linux.inc"
# dpp401_dpp_setup's format switch and default color space, as a body.
{
	range "$d/dc/dpp/dcn401/dcn401_dpp.c" '^	switch \(format\) \{' '^	}$'
	range "$d/dc/dpp/dcn401/dcn401_dpp.c" 'Set default color space based on format' 'color_space = input_color_space'
} > "$work/dpp_setup.inc"
grep -q 'pixel_format = 66' "$work/dpp_setup.inc" || { echo "dpp401_dpp_setup switch not found" >&2; exit 1; }
# hubp2_program_pixel_format, and fill_dc_plane_info_and_addr's DRM to DC
# format switch.
awk '/^void hubp2_program_pixel_format\(/ { on = 1 } on { print } on && /^}/ { exit }' \
	"$d/dc/hubp/dcn20/dcn20_hubp.c" > "$work/hubp_fn.inc"
[ -s "$work/hubp_fn.inc" ] || { echo "hubp2_program_pixel_format not found" >&2; exit 1; }
awk '/^fill_dc_plane_info_and_addr\(/ { fn = 1 } fn && /^\tswitch \(fb->format->format\) \{/ { on = 1 }
	on { print } on && /^\t}$/ { exit }' "$d/amdgpu_dm/amdgpu_dm.c" > "$work/dm_format.inc"
grep -q 'VIDEO_420_10bpc_YCrCb' "$work/dm_format.inc" || { echo "fill_dc_plane_info_and_addr switch not found" >&2; exit 1; }

cc -O1 -w -I"$work" "$here/harness.c" -o "$work/yuv"

inputs() {
	for f in XR24 AR24 XB24 AB24 XR30 AR30 XB30 AB30 RG16 XR4H AR4H XB4H AB4H NV12 P010; do
		for enc in 0 1 2 3; do
			for range in 0 1; do
				echo "$f $enc $range"
			done
		done
	done
}
if [ $generate -eq 1 ]; then
	echo "# Linux DCN4 plane input conversion vectors; see check.sh and harness.c."
	inputs | while read -r in; do
		echo "$in = $(echo "$in" | "$work/yuv")"
	done
	exit 0
fi
grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//' | "$work/yuv" > "$work/got"
grep -v '^#' "$here/vectors.txt" | sed 's/.* = //' > "$work/want"
if ! diff -q "$work/want" "$work/got" >/dev/null; then
	diff "$work/want" "$work/got" | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
fi
inputs | diff -q - <(grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//') >/dev/null ||
	{ echo "vectors.txt inputs differ from check.sh's" >&2; exit 1; }
echo "$(wc -l < "$work/want") ok"
