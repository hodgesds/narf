#!/usr/bin/env bash
# Verify drivers/gpu/tests/amdgpu_dcc_vram/vectors.txt against Linux's
# GFX12 DCC VRAM placement: gmc_v12_0_get_dcc_alignment and the
# GFX12_DCC | VRAM_CONTIGUOUS path of amdgpu_vram_mgr_new (the block rounded
# to a power of two, the start trimmed to the DCC alignment), compiled on
# the host from the Linux tree's own functions; see harness.c for the line
# format.
#   drivers/gpu/tests/amdgpu_dcc_vram/check.sh [linux-tree]
#   drivers/gpu/tests/amdgpu_dcc_vram/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_gem.rs's gmc_v12_dcc_alignment, dcc_block_size and dcc_trim_start
# must produce Linux's output for every line (its kernel test replays them).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
drm=$linux/drivers/gpu/drm
amd=$drm/amd/amdgpu
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Print the definition (not a prototype) of the C function whose first line
# matches $2 in file $1, through its closing brace at column 0.
extract() {
	RE="$2" awk '
		!on && $0 ~ ENVIRON["RE"] { on = 1; buf = "" }
		on {
			buf = buf $0 "\n"
			if (!body && $0 ~ /\);[ \t]*$/ && $0 !~ /\{/) { on = 0; buf = ""; next }
			if ($0 ~ /\{/) body = 1
			if (body && $0 ~ /^}/) { printf "%s", buf; exit }
		}' "$1"
}
x() {
	local out
	out=$(extract "$1" "$2")
	[ -n "$out" ] || { echo "not found in $1: $2" >&2; exit 1; }
	printf '%s\n\n' "$out"
}

x "$amd/gmc_v12_0.c" '^static unsigned int gmc_v12_0_get_dcc_alignment\(' > "$work/gmc.inc"
{
	echo 'static inline struct amdgpu_vram_mgr *'
	x "$amd/amdgpu_vram_mgr.c" '^to_vram_mgr\('
	echo 'static inline struct amdgpu_device *'
	x "$amd/amdgpu_vram_mgr.c" '^to_amdgpu_device\('
	echo 'static inline struct gpu_buddy_block *'
	x "$amd/amdgpu_vram_mgr.c" '^amdgpu_vram_mgr_first_block\('
	x "$amd/amdgpu_vram_mgr.c" '^static inline bool amdgpu_is_vram_mgr_blocks_contiguous\('
	x "$amd/amdgpu_vram_mgr.c" '^static inline u64 amdgpu_vram_mgr_blocks_size\('
	x "$amd/amdgpu_vram_mgr.c" '^static u64 amdgpu_vram_mgr_vis_size\('
	x "$amd/amdgpu_vram_mgr.c" '^static int amdgpu_vram_mgr_new\('
} > "$work/vram_mgr.inc"

cc -O1 -w -I"$work" "$here/harness.c" -o "$work/dcc"

if [ $generate -eq 1 ]; then
	echo "# Linux GFX12 DCC VRAM placement vectors for amdgpu_gem.rs; see"
	echo "# check.sh and harness.c."
	"$here/inputs.sh" | while read -r in; do
		echo "$in = $(echo "$in" | "$work/dcc")"
	done
	exit 0
fi

grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//' | "$work/dcc" > "$work/got"
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
