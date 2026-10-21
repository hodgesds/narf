#!/usr/bin/env bash
# Verify drivers/gpu/tests/amdgpu_dumb/vectors.txt against Linux's
# CREATE_DUMB on a dGPU amdgpu card: drm_mode_create_dumb's checks, then
# amdgpu_mode_dumb_create's pitch (amdgpu_gem_align_pitch), size, domain
# (amdgpu_display_supported_domains, amdgpu_bo_get_preferred_domain) and
# create flags, compiled on the host from the Linux tree's own functions;
# see harness.c for the line format.
#   drivers/gpu/tests/amdgpu_dumb/check.sh [linux-tree]
#   drivers/gpu/tests/amdgpu_dumb/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_gem.rs's dumb_layout, DUMB_DOMAIN and DUMB_CREATE_FLAGS must
# produce Linux's output for every line (its kernel test replays them).
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

x "$amd/amdgpu_display.c" '^uint32_t amdgpu_display_supported_domains\(' > "$work/display.inc"
x "$amd/amdgpu_object.c" '^uint32_t amdgpu_bo_get_preferred_domain\(' > "$work/object.inc"
{
	x "$amd/amdgpu_gem.c" '^static unsigned int amdgpu_gem_align_pitch\('
	x "$amd/amdgpu_gem.c" '^int amdgpu_mode_dumb_create\('
} > "$work/gem.inc"
x "$drm/drm_dumb_buffers.c" '^int drm_mode_create_dumb\(' > "$work/dumb.inc"

cc -O1 -w -I"$work" -I"$linux/include/uapi" "$here/harness.c" -o "$work/dumb"

if [ $generate -eq 1 ]; then
	echo "# Linux CREATE_DUMB reference vectors for amdgpu_gem.rs's dumb"
	echo "# buffers; see check.sh and harness.c."
	"$here/inputs.sh" | while read -r in; do
		echo "$in = $(echo "$in" | "$work/dumb")"
	done
	exit 0
fi

grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//' | "$work/dumb" > "$work/got"
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
