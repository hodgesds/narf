#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_mst_payload/vectors.txt against DRM's MST
# payload table helpers, compiled on the host: drm_dp_mst_update_slots,
# drm_dp_mst_atomic_check_payload_alloc_limits (time-slot and payload-count
# limits, VCPI assignment), drm_dp_add_payload_part1/2 and
# drm_dp_remove_payload_part1/2 (start slots, payload-table rows and
# ALLOCATE_PAYLOAD) with drm_dp_dpcd_write_payload, extracted verbatim from
# drm_dp_mst_topology.c / drm_dp_helper.c with their payload structs from
# drm_dp_mst_helper.h, and amdgpu_dm's dm_mst_get_pbn_divider; harness.c
# drives them and documents the line format.
#   drivers/gpu/tests/dcn401_mst_payload/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_mst_payload/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_navi48_mst.rs's payload allocator must reproduce every line.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
topo=$linux/drivers/gpu/drm/display/drm_dp_mst_topology.c
helper=$linux/drivers/gpu/drm/display/drm_dp_helper.c
header=$linux/include/drm/display/drm_dp_mst_helper.h
dm=$linux/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_mst_types.c
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# extract <file> <function name>...: each function from its signature line
# (or the line before, for a split signature) to the first closing brace in
# column 0.
extract() {
	local file=$1
	shift
	for name in "$@"; do
		awk -v n="$name" '
			!f && $0 ~ "^(static |)[a-z_0-9 ]*[ *]" n "\\(" { f = 1 }
			!f && prev ~ "^(static |)[a-z_0-9 ]*$" && $0 ~ "^" n "\\(" { f = 1; print prev }
			f { print }
			f && /^}/ { exit }
			{ prev = $0 }' "$file" >"$work/fn"
		grep -q . "$work/fn" || { echo "missing $name" >&2; exit 1; }
		cat "$work/fn"
	done
}

{
	cat "$here/shim.h"
	awk '/^enum drm_dp_mst_payload_allocation \{/,/^};/' "$header"
	awk '/^struct drm_dp_mst_atomic_payload \{/,/^};/' "$header"
	awk '/^struct drm_dp_mst_topology_state \{/,/^};/' "$header"
	extract "$helper" drm_dp_dpcd_write_payload
	extract "$topo" drm_dp_create_payload_at_dfp drm_dp_create_payload_to_remote \
		drm_dp_destroy_payload_at_remote_and_dfp drm_dp_add_payload_part1 \
		drm_dp_remove_payload_part1 drm_dp_remove_payload_part2 drm_dp_add_payload_part2 \
		drm_dp_mst_update_slots drm_dp_mst_atomic_check_payload_alloc_limits
	extract "$dm" dm_mst_get_pbn_divider
	cat "$here/harness.c"
} >"$work/payload.c"
cc -O1 -w "$work/payload.c" -o "$work/payload"

if [ $generate -eq 1 ]; then
	echo "# Linux DP MST payload table reference vectors; see check.sh."
	"$work/payload"
	exit 0
fi
"$work/payload" | diff -q - <(grep -v '^#' "$here/vectors.txt") >/dev/null || {
	"$work/payload" | diff - <(grep -v '^#' "$here/vectors.txt") | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
}
echo "$(grep -vc '^#' "$here/vectors.txt") ok"
