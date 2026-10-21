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
# Also color_vectors.txt: the plane's input transfer function under the
# CRTC's legacy gamma (map_crtc_degamma_to_dc_plane through
# mod_color_calculate_degamma_params, then dcn32_set_input_transfer_func's
# dpp3_set_pre_degam, cm3_helper_translate_curve_to_degamma_hw_format and
# dpp3_program_gamcor_lut; input_tf.c, linked against tests/dcn401_color's
# host build of color_gamma.c and dcn30_cm_common.c), the input CSC's double-buffered coefficient set
# (dpp3_program_post_csc against CM_POST_CSC_MODE_CURRENT), and the cursor
# over the plane (dpp401_set_cursor_matrix, and dpp401_set_cursor_attributes
# with amdgpu_dm's ENABLE_CURSOR_DEGAMMA); see color_input.c. And
# gamcor_vectors.txt: every register write of that input transfer function
# for each format under legacy gamma, from each GAMCOR RAM state.
#   drivers/gpu/tests/dcn401_yuv/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_yuv/check.sh --generate [linux-tree] > vectors.txt
#   drivers/gpu/tests/dcn401_yuv/check.sh --generate-color [linux-tree] > color_vectors.txt
#   drivers/gpu/tests/dcn401_yuv/check.sh --generate-gamcor [linux-tree] > gamcor_vectors.txt
# amdgpu_dcn401_dpp.rs / amdgpu_dcn401_surface.rs / amdgpu_dcn401_color.rs /
# amdgpu_dcn401_cursor.rs must produce Linux's output for every line (the
# dcn401-dpp kernel tests replay them).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
elif [ "${1:-}" = --generate-color ]; then
	generate=2
	shift
elif [ "${1:-}" = --generate-gamcor ]; then
	generate=3
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

# color_input.c's Linux code.
fn() {
	awk -v start="$2" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$1"
}
{
	x "$d/dc/dc_hw_types.h" '^enum surface_pixel_format \{' '^};'
	x "$d/dc/dc_hw_types.h" '^enum dc_color_space \{' '^};'
	x "$d/dc/dc_hw_types.h" '^enum cursor_matrix_mode \{' '^};'
	x "$d/dc/dc_hw_types.h" '^enum dc_cursor_color_format \{' '^};'
	x "$d/dc/dc_hw_types.h" '^struct dc_csc_transform \{' '^};'
	x "$d/dc/dpp/dcn10/dcn10_dpp.h" '^enum dcn10_input_csc_select \{' '^};'
	x "$d/dc/inc/hw/dpp.h" '^struct dpp_input_csc_matrix \{' '^};'
	x "$d/dc/inc/hw/dpp.h" '^static const struct dpp_input_csc_matrix' '^};'
	echo 'static int'
	x "$d/amdgpu_dm/amdgpu_dm.c" '^fill_plane_color_attributes\(' '^}'
} > "$work/color.inc"
{
	fn "$d/dc/dpp/dcn30/dcn30_dpp.c" 'void dpp3_program_post_csc('
	fn "$d/dc/dpp/dcn401/dcn401_dpp_cm.c" 'void dpp401_set_cursor_attributes('
	fn "$d/dc/dpp/dcn401/dcn401_dpp_cm.c" 'static void dpp401_program_cursor_csc('
	fn "$d/dc/dpp/dcn401/dcn401_dpp_cm.c" 'void dpp401_set_cursor_matrix('
} > "$work/dpp_fns.inc"
for f in dpp3_program_post_csc dpp401_set_cursor_attributes dpp401_program_cursor_csc dpp401_set_cursor_matrix; do
	grep -q "$f(" "$work/dpp_fns.inc" || { echo "$f not found" >&2; exit 1; }
done
# amdgpu_dm_plane_handle_cursor_update's ENABLE_CURSOR_DEGAMMA, on the
# harness's locals.
awk '/crtc_state->cm_is_degamma_srgb &&/ { on = 1 } on { print } on && /ENABLE_CURSOR_DEGAMMA = 1;/ { exit }' \
	"$d/amdgpu_dm/amdgpu_dm_plane.c" |
	sed -e 's/crtc_state->cm_is_degamma_srgb/cm_is_degamma_srgb/' \
		-e 's/adev->dm.dc->caps.color.dpp.gamma_corr/gamma_corr/' \
		-e 's/attributes\./cursor./' > "$work/cursor_degamma.inc"
grep -q 'ENABLE_CURSOR_DEGAMMA = 1' "$work/cursor_degamma.inc" || { echo "cursor degamma not found" >&2; exit 1; }
# dcn401_resource's dpp gamma_corr cap, which the condition reads.
grep -q 'dc->caps.color.dpp.gamma_corr = 1;' "$d/dc/resource/dcn401/dcn401_resource.c" ||
	{ echo "dcn401 gamma_corr cap changed" >&2; exit 1; }
# input_tf.c's Linux code: the plane's implicit degamma and its programming.
{
	fn "$d/dc/dpp/dcn30/dcn30_dpp.c" 'void dpp3_set_pre_degam('
	for f in 'static void dpp3_enable_cm_block(' 'static enum dc_lut_mode dpp30_get_gamcor_current(' \
		'static void dpp3_program_gammcor_lut(' 'static void dpp3_power_on_gamcor_lut(' \
		'static void dpp3_gamcor_reg_field(' 'static void dpp3_configure_gamcor_lut(' \
		'bool dpp3_program_gamcor_lut('; do
		fn "$d/dc/dpp/dcn30/dcn30_dpp_cm.c" "$f"
	done
} > "$work/dpp_gamcor.inc"
for f in dpp3_set_pre_degam dpp3_enable_cm_block dpp30_get_gamcor_current dpp3_program_gammcor_lut \
	dpp3_power_on_gamcor_lut dpp3_gamcor_reg_field dpp3_configure_gamcor_lut dpp3_program_gamcor_lut; do
	grep -q "$f(" "$work/dpp_gamcor.inc" || { echo "$f not found" >&2; exit 1; }
done
fn "$d/dc/hwss/dcn32/dcn32_hwseq.c" 'bool dcn32_set_input_transfer_func(' > "$work/set_input_tf.inc"
grep -q 'dpp_program_gamcor_lut' "$work/set_input_tf.inc" || { echo "dcn32_set_input_transfer_func not found" >&2; exit 1; }
grep -q '\.set_input_transfer_func = dcn32_set_input_transfer_func,' "$d/dc/hwss/dcn401/dcn401_init.c" ||
	{ echo "dcn401 input transfer function changed" >&2; exit 1; }
{ grep -q '\.dpp_program_gamcor_lut[[:space:]]*= dpp3_program_gamcor_lut,' "$d/dc/dpp/dcn401/dcn401_dpp.c" &&
	grep -q '\.dpp_set_pre_degam[[:space:]]*= dpp3_set_pre_degam,' "$d/dc/dpp/dcn401/dcn401_dpp.c" &&
	! grep -q 'dpp_set_pregam_state' "$d/dc/dpp/dcn401/dcn401_dpp.c"; } ||
	{ echo "dcn401 dpp funcs changed" >&2; exit 1; }
awk '/^\t\.enable_mem_low_power = \{/ { on = 1 } on && /\.cm = false,/ { ok = 1 } on && /^\t\},/ { exit }
	END { exit !ok }' "$d/dc/resource/dcn401/dcn401_resource.c" ||
	{ echo "dcn401 CM low-power option changed" >&2; exit 1; }
{
	echo 'static int'
	fn "$d/amdgpu_dm/amdgpu_dm_color.c" 'map_crtc_degamma_to_dc_plane('
} > "$work/map_degamma.inc"
grep -q 'mod_color_calculate_degamma_params' "$work/map_degamma.inc" || { echo "map_crtc_degamma_to_dc_plane not found" >&2; exit 1; }
cflags=(-O1 -w -include os_types.h -I"$work" -I"$here/../dcn401_color/include" -I"$d/dc/inc/hw"
	-I"$d/dc/dwb" -I"$d/dc" -I"$d/dc/inc" -I"$d/include" -I"$d/modules/color" -I"$d"
	-I"$linux/drivers/gpu/drm/amd/include" -idirafter "$linux/include")
for f in "$d/modules/color/color_gamma.c" "$d/dc/basics/fixpt31_32.c" \
	"$d/modules/color/color_table.c" "$d/dc/basics/custom_float.c" \
	"$d/dc/basics/conversion.c" "$d/dc/dcn30/dcn30_cm_common.c" "$here/input_tf.c"; do
	cc -c "${cflags[@]}" "$f" -o "$work/$(basename "$f" .c).o"
done
cc -O1 -w -I"$work" -c "$here/color_input.c" -o "$work/color_input.o"
cc "$work"/*.o -o "$work/color"

gamcor_inputs() {
	for f in XR24 RG16 XR4H NV12 P010; do
		for control in 0 20 60; do
			echo "$f $control"
		done
	done
}
if [ $generate -eq 3 ]; then
	echo "# Linux DCN4 plane input transfer function writes under legacy gamma; see check.sh and color_input.c."
	gamcor_inputs | while read -r in; do
		echo "$in = $(echo "$in" | "$work/color" --gamcor)"
	done
	exit 0
fi

color_inputs() {
	for f in XR24 AR24 XB24 AB24 XR30 AR30 XB30 AB30 RG16 XR4H AR4H XB4H AB4H NV12 P010; do
		for legacy in 0 1; do
			for current in 0 1 2; do
				for enc in 0 1 2; do
					for range in 0 1; do
						echo "$f $legacy $current $enc $range"
					done
				done
			done
		done
	done
}
if [ $generate -eq 2 ]; then
	echo "# Linux DCN4 plane input transfer function, input CSC set and cursor color vectors; see check.sh and color_input.c."
	color_inputs | while read -r in; do
		echo "$in = $(echo "$in" | "$work/color")"
	done
	exit 0
fi

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
inputs | diff -q - <(grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//') >/dev/null ||
	{ echo "vectors.txt inputs differ from check.sh's" >&2; exit 1; }
grep -v '^#' "$here/color_vectors.txt" | sed 's/ = .*//' | "$work/color" > "$work/color_got"
grep -v '^#' "$here/color_vectors.txt" | sed 's/.* = //' > "$work/color_want"
if ! diff -q "$work/color_want" "$work/color_got" >/dev/null; then
	diff "$work/color_want" "$work/color_got" | head -20 >&2
	echo "color_vectors.txt does not match Linux" >&2
	exit 1
fi
color_inputs | diff -q - <(grep -v '^#' "$here/color_vectors.txt" | sed 's/ = .*//') >/dev/null ||
	{ echo "color_vectors.txt inputs differ from check.sh's" >&2; exit 1; }
grep -v '^#' "$here/gamcor_vectors.txt" | sed 's/ = .*//' | "$work/color" --gamcor > "$work/gamcor_got"
grep -v '^#' "$here/gamcor_vectors.txt" | sed 's/.* = //' > "$work/gamcor_want"
if ! diff -q "$work/gamcor_want" "$work/gamcor_got" >/dev/null; then
	echo "gamcor_vectors.txt does not match Linux" >&2
	exit 1
fi
gamcor_inputs | diff -q - <(grep -v '^#' "$here/gamcor_vectors.txt" | sed 's/ = .*//') >/dev/null ||
	{ echo "gamcor_vectors.txt inputs differ from check.sh's" >&2; exit 1; }
echo "$(wc -l < "$work/want") + $(wc -l < "$work/color_want") + $(wc -l < "$work/gamcor_want") ok"
