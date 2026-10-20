#!/usr/bin/env bash
# Verify drivers/gpu/tests/amd_modifiers/vectors.txt against Linux's GFX12
# modifier list, IN_FORMATS blob, format/modifier support, tiling-flag
# conversion and ADDFB2 framebuffer checks, compiled on the host from the
# Linux tree's own functions (amdgpu_dm_plane.c, amdgpu_display.c,
# drm_plane.c, drm_framebuffer.c, drm_fourcc.c); see harness.c for the line
# format.
#   drivers/gpu/tests/amd_modifiers/check.sh [linux-tree]
#   drivers/gpu/tests/amd_modifiers/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_dm_modifiers.rs must produce Linux's output for every line (its
# kernel test replays them).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
drm=$linux/drivers/gpu/drm
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Print the definition (not a prototype) of the C function or object whose
# first line matches $2 in file $1, through its closing brace at column 0.
# A preceding "static inline ..." line is kept.
extract() {
	RE="$2" awk '
		!on && $0 ~ ENVIRON["RE"] { on = 1; buf = (prev ~ /^static inline/ ? prev "\n" : ""); }
		on {
			buf = buf $0 "\n"
			if (!body && $0 ~ /\);[ \t]*$/ && $0 !~ /\{/) { on = 0; buf = ""; prev = $0; next }
			if ($0 ~ /\{/) body = 1
			if (body && $0 ~ /^}/) { printf "%s", buf; exit }
		}
		{ prev = $0 }' "$1"
}
x() {
	local out
	out=$(extract "$1" "$2")
	[ -n "$out" ] || { echo "not found in $1: $2" >&2; exit 1; }
	printf '%s\n\n' "$out"
}

{
	x "$linux/include/drm/drm_fourcc.h" '^struct drm_format_info \{'
	x "$linux/include/drm/drm_fourcc.h" '^int drm_format_info_plane_width\('
	x "$linux/include/drm/drm_fourcc.h" '^int drm_format_info_plane_height\('
	x "$drm/drm_fourcc.c" '^const struct drm_format_info \*__drm_format_info\('
	x "$drm/drm_fourcc.c" '^unsigned int drm_format_info_block_width\('
	x "$drm/drm_fourcc.c" '^unsigned int drm_format_info_block_height\('
	x "$drm/drm_fourcc.c" '^unsigned int drm_format_info_bpp\('
	x "$drm/drm_fourcc.c" '^uint64_t drm_format_info_min_pitch\('
} > "$work/fourcc.inc"
{
	x "$drm/drm_plane.c" '^formats_ptr\('
	x "$drm/drm_plane.c" '^modifiers_ptr\('
	x "$drm/drm_plane.c" '^static struct drm_property_blob \*create_in_format_blob\('
	x "$drm/drm_plane.c" '^bool drm_plane_has_format\('
	x "$drm/drm_framebuffer.c" '^static int framebuffer_check\('
} > "$work/drm.inc"
p=$drm/amd/display/amdgpu_dm/amdgpu_dm_plane.c
{
	x "$p" '^static const uint32_t rgb_formats\[\] = \{'
	x "$p" '^static const uint32_t overlay_formats\[\] = \{'
	x "$p" '^static const u32 cursor_formats\[\] = \{'
	x "$p" '^enum dm_micro_swizzle \{'
	x "$p" '^STATIC_IFN_KUNIT void amdgpu_dm_plane_add_modifier\('
	x "$p" '^STATIC_IFN_KUNIT bool amdgpu_dm_plane_modifier_has_dcc\('
	x "$p" '^STATIC_IFN_KUNIT unsigned int amdgpu_dm_plane_modifier_gfx9_swizzle_mode\('
	x "$p" '^static void amdgpu_dm_plane_add_gfx12_modifiers\('
	x "$p" '^STATIC_IFN_KUNIT int amdgpu_dm_plane_get_plane_modifiers\('
	x "$p" '^STATIC_IFN_KUNIT int amdgpu_dm_plane_get_plane_formats\('
	x "$p" '^STATIC_IFN_KUNIT bool amdgpu_dm_plane_format_mod_supported\('
} > "$work/dm.inc"
a=$drm/amd/amdgpu/amdgpu_display.c
{
	x "$a" '^static int convert_tiling_flags_to_modifier_gfx12\('
	x "$a" '^static void get_block_dimensions\('
	x "$a" '^static unsigned int get_dcc_block_size\('
	x "$a" '^static int amdgpu_display_verify_plane\('
	x "$a" '^static int amdgpu_display_verify_sizes\('
	x "$a" '^static int amdgpu_display_get_fb_info\('
	x "$a" '^static int amdgpu_display_framebuffer_init\('
	x "$a" '^static int amdgpu_display_gem_fb_verify_and_init\('
} > "$work/display.inc"

cc -O1 -w -I"$here/include" -I"$work" -I"$linux/include/uapi" "$here/harness.c" -o "$work/mods"

if [ $generate -eq 1 ]; then
	echo "# Linux GFX12 modifier / IN_FORMATS / ADDFB2 reference vectors for"
	echo "# amdgpu_dm_modifiers.rs; see check.sh and harness.c."
	"$here/inputs.sh" | while read -r in; do
		echo "$in = $(echo "$in" | "$work/mods")"
	done
	exit 0
fi

grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//' | "$work/mods" > "$work/got"
grep -v '^#' "$here/vectors.txt" | sed 's/.* = //' > "$work/want"
if ! diff -q "$work/want" "$work/got" >/dev/null; then
	diff "$work/want" "$work/got" | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
fi
# The vectors must also be the ones inputs.sh asks for.
"$here/inputs.sh" | diff -q - <(grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//') >/dev/null ||
	{ echo "vectors.txt inputs differ from inputs.sh" >&2; exit 1; }
echo "$(wc -l < "$work/want") ok"
