#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_pipes/vectors.txt against Linux DC's
# DCN401 pipe acquisition, compiled on the host:
#   drivers/gpu/tests/dcn401_pipes/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_pipes/check.sh --generate [linux-tree] > vectors.txt
# Cut verbatim out of the Linux tree:
#   core/dc_resource.c   the pipe types and queries, the free-pipe finders,
#                        acquire_otg_master_pipe_for_stream and
#                        acquire_first_split_pipe, plane append/remove,
#                        ODM and MPC slice add/remove and
#                        resource_update_pipes_for_{stream,plane}_with_slice_count
#   dcn32_resource.c     the pool's acquire_free_pipe_as_secondary_dpp_pipe
#                        and _opp_head (DCN401's pool funcs), with their
#                        pipe-swap-minimising searches
#   dcn20_resource.c     release_pipe and the DSC acquisition it calls
#   core/dc_state.c      dc_state_{add,remove}_{stream,plane}
#   dml2_dc_resource_mgmt.c  map_dc_pipes_with_callbacks (DCN401 sets
#                        map_dc_pipes_with_callbacks) with its factor
#                        population and the unmap/map per stream
# harness.c documents the script and line format. vectors.txt is the
# harness's output for the script its lines spell (results dropped);
# amdgpu_dcn401_resource.rs must reproduce every line
# (dcn401_pipe_acquisition_matches_linux).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
dc=$linux/drivers/gpu/drm/amd/display/dc
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
			!f && $0 ~ "^(static |)[a-z_0-9 ]*[ *]" n "\\(" && $0 !~ ";$" { f = 1 }
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
	extract "$dc/core/dc_resource.c" resource_is_pipe_type \
		resource_get_otg_master_for_stream resource_get_opp_heads_for_otg_master \
		resource_get_dpp_pipes_for_plane resource_get_otg_master resource_get_opp_head \
		resource_get_mpc_slice_index resource_get_mpc_slice_count resource_get_odm_slice_count \
		resource_find_free_pipe_used_as_sec_opp_head_by_cur_otg_master \
		resource_find_free_pipe_used_in_cur_mpc_blending_tree \
		recource_find_free_pipe_not_used_in_cur_res_ctx \
		recource_find_free_pipe_used_as_otg_master_in_cur_res_ctx \
		resource_find_free_pipe_used_as_cur_sec_dpp \
		resource_find_free_pipe_used_as_cur_sec_dpp_in_mpcc_combine \
		resource_find_any_free_pipe get_tail_pipe get_last_opp_head \
		get_last_dpp_pipe_in_mpcc_combine update_pipe_params_after_odm_slice_count_change \
		update_pipe_params_after_mpc_slice_count_change acquire_first_split_pipe \
		get_num_of_free_pipes resource_add_otg_master_for_stream_output \
		add_plane_to_opp_head_pipes acquire_secondary_dpp_pipes_and_add_plane \
		resource_append_dpp_pipes_for_plane_composition \
		resource_remove_dpp_pipes_for_plane_composition acquire_pipes_and_add_odm_slice \
		release_pipes_and_remove_odm_slice acquire_dpp_pipe_and_add_mpc_slice \
		release_dpp_pipe_and_remove_mpc_slice \
		resource_update_pipes_for_stream_with_slice_count \
		resource_update_pipes_for_plane_with_slice_count acquire_otg_master_pipe_for_stream
	extract "$dc/resource/dcn32/dcn32_resource.c" \
		dcn32_find_optimal_free_pipe_as_secondary_dpp_pipe find_idle_secondary_pipe_check_mpo \
		dcn32_acquire_idle_pipe_for_head_pipe_in_layer \
		find_optimal_free_pipe_as_secondary_opp_head \
		dcn32_acquire_free_pipe_as_secondary_dpp_pipe \
		dcn32_acquire_free_pipe_as_secondary_opp_head
	extract "$dc/resource/dcn20/dcn20_resource.c" dcn20_acquire_dsc dcn20_release_dsc \
		dcn20_release_pipe
	extract "$dc/core/dc_state.c" dc_state_add_stream dc_state_remove_stream \
		remove_mpc_combine_for_stream dc_state_add_plane dc_state_remove_plane
	extract "$dc/dml2_0/dml2_dc_resource_mgmt.c" get_source_odm_factor get_source_mpc_factor \
		populate_mpc_factors_for_stream populate_odm_factors unmap_dc_pipes_for_stream \
		map_dc_pipes_for_stream map_dc_pipes_with_callbacks
	cat "$here/harness.c"
} >"$work/pipes.c"
# DCN401's pool funcs: the secondary pipes are dcn32's, release dcn20's.
grep -q 'acquire_free_pipe_as_secondary_dpp_pipe = dcn32_acquire_free_pipe_as_secondary_dpp_pipe' \
	"$dc/resource/dcn401/dcn401_resource.c" || { echo "dcn401 pool funcs changed" >&2; exit 1; }
grep -q 'acquire_free_pipe_as_secondary_opp_head = dcn32_acquire_free_pipe_as_secondary_opp_head' \
	"$dc/resource/dcn401/dcn401_resource.c" || { echo "dcn401 pool funcs changed" >&2; exit 1; }
grep -q 'release_pipe = dcn20_release_pipe' "$dc/resource/dcn401/dcn401_resource.c" \
	|| { echo "dcn401 pool funcs changed" >&2; exit 1; }
grep -q 'enable_windowed_mpo_odm = true' "$dc/resource/dcn401/dcn401_resource.c" \
	|| { echo "dcn401 no longer sets enable_windowed_mpo_odm" >&2; exit 1; }
grep -q 'map_dc_pipes_with_callbacks = true' "$dc/resource/dcn401/dcn401_resource.c" \
	|| { echo "dcn401 no longer maps pipes with callbacks" >&2; exit 1; }
cc -O1 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare \
	-Wno-missing-field-initializers "$work/pipes.c" -o "$work/pipes"

# The script vectors.txt spells: its lines without their results.
sed -e 's/ \(ok\|fail\)$//' -e 's/^commit .*/commit/' "$here/vectors.txt" >"$work/script"
"$work/pipes" <"$work/script" >"$work/out"
if [ $generate -eq 1 ]; then
	cat "$work/out"
	exit 0
fi
diff -u "$here/vectors.txt" "$work/out" >&2 || {
	echo "vectors.txt does not match Linux" >&2
	exit 1
}
echo "dcn401_pipes: $(grep -c '^commit' "$here/vectors.txt") commits match $linux"
