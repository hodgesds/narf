#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_spl/vectors.txt (RGB planes) and
# video_vectors.txt (NV12/P010 4:2:0 planes) against Linux SPL (dc/sspl)
# compiled on the host, and that amdgpu_dcn401_spl_filters.rs is
# gen_filters.py's output; see harness.c for the line format.
#   drivers/gpu/tests/dcn401_spl/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_spl/check.sh --generate [linux-tree] > vectors.txt
#   drivers/gpu/tests/dcn401_spl/check.sh --generate-video [linux-tree] > video_vectors.txt
#   drivers/gpu/tests/dcn401_spl/check.sh --generate-mpc [linux-tree] > mpc_vectors.txt
#   drivers/gpu/tests/dcn401_spl/check.sh --generate-video-mpc [linux-tree] > video_mpc_vectors.txt
# mpc_vectors.txt answers mpc_inputs.txt: planes split into MPC slices, each
# line two values longer (the slice index and count; harness.c with MPC set),
# rotated planes among them. video_mpc_vectors.txt answers
# video_mpc_inputs.txt: NV12/P010 planes split so (harness.c video, MPC set).
# amdgpu_dcn401_spl.rs and amdgpu_dcn401_dscl.rs must produce Linux's
# output for every line (amdgpu_dcn401_spl_tests.rs replays them).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=
case ${1:-} in
--generate) generate=rgb; shift ;;
--generate-video) generate=video; shift ;;
--generate-mpc) generate=mpc; shift ;;
--generate-video-mpc) generate=video-mpc; shift ;;
esac
linux=${1:-/usr/src/linux}
sspl=$linux/drivers/gpu/drm/amd/display/dc/sspl
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

python3 "$here/gen_filters.py" "$linux" > "$work/filters.rs"
cmp -s "$work/filters.rs" "$here/../../src/amdgpu_dcn401_spl_filters.rs" ||
	{ echo "amdgpu_dcn401_spl_filters.rs differs from Linux's tables" >&2; exit 1; }

# The SPL line-buffer callback DC passes on DCN401, verbatim.
awk '/^void dscl401_spl_calc_lb_num_partitions\(/ { on = 1 }
	on { print }
	on && /^}/ { exit }' "$linux/drivers/gpu/drm/amd/display/dc/dpp/dcn401/dcn401_dpp.c" \
	> "$work/spl_lb.inc"
[ -s "$work/spl_lb.inc" ] || { echo "dscl401_spl_calc_lb_num_partitions not found" >&2; exit 1; }

flags=(-O1 -w -Wno-error=incompatible-pointer-types -I"$here/include" -I"$sspl" -I"$work" -I"$linux/drivers/gpu/drm/amd/include")
for f in dc_spl dc_spl_scl_filters dc_spl_scl_easf_filters dc_spl_isharp_filters \
	dc_spl_filters spl_fixpt31_32 spl_custom_float; do
	cc -c "${flags[@]}" "$sspl/$f.c" -o "$work/$f.o"
done
cc "${flags[@]}" "$here/harness.c" "$work"/*.o -o "$work/spl"

fields="src_x src_y src_w src_h dst_x dst_y dst_w dst_h stream_w stream_h odm_x odm_w rotation mirror alpha"
if [ "$generate" = mpc ]; then
	echo "# Linux SPL reference vectors for amdgpu_dcn401_spl.rs with MPC slices; see check.sh."
	echo "# $fields mpc_index mpc_count = writes"
	grep -v '^#' "$here/mpc_inputs.txt" | while read -r in; do
		[ -n "$in" ] || continue
		echo "$in = $(echo "$in" | MPC=1 "$work/spl")"
	done
	exit 0
fi
if [ "$generate" = video-mpc ]; then
	echo "# Linux SPL reference vectors for 4:2:0 planes in MPC slices; see check.sh,"
	echo "# harness.c and video_mpc_inputs.txt."
	echo "# format $fields mpc_index mpc_count = writes"
	grep -v '^#' "$here/video_mpc_inputs.txt" | while read -r in; do
		[ -n "$in" ] || continue
		echo "$in = $(echo "$in" | MPC=1 "$work/spl" video)"
	done
	exit 0
fi
if [ "$generate" = rgb ]; then
	echo "# Linux SPL reference vectors for amdgpu_dcn401_spl.rs; see check.sh and harness.c."
	echo "# $fields = writes"
	grep -v '^#' "$here/inputs.txt" | while read -r in; do
		[ -n "$in" ] || continue
		echo "$in = $(echo "$in" | "$work/spl")"
	done
	exit 0
fi
if [ "$generate" = video ]; then
	echo "# Linux SPL reference vectors for 4:2:0 planes (format 8 NV12/NV21, 10 P010);"
	echo "# see check.sh, harness.c and video_inputs.txt."
	echo "# format $fields = writes"
	grep -v '^#' "$here/video_inputs.txt" | while read -r in; do
		[ -n "$in" ] || continue
		echo "$in = $(echo "$in" | "$work/spl" video)"
	done
	exit 0
fi

fail=0
# verify <vector file> [harness mode]
verify() {
	local file=$1 mode=${2:-} n=0 line in want got
	while IFS= read -r line; do
		case $line in ''|'#'*) continue ;; esac
		in=${line%% = *}
		want=${line#* = }
		got=$(echo "$in" | "$work/spl" $mode)
		n=$((n + 1))
		if [ "$got" != "$want" ]; then
			echo "MISMATCH ($(basename "$file")): $in" >&2
			echo "  linux:  $got" >&2
			echo "  vector: $want" >&2
			fail=1
		fi
	done < "$file"
	echo "dcn401_spl: $n $(basename "$file") vectors checked against Linux SPL"
}
verify "$here/vectors.txt"
verify "$here/video_vectors.txt" video
MPC=1 verify "$here/mpc_vectors.txt"
MPC=1 verify "$here/video_mpc_vectors.txt" video
[ $fail -eq 0 ] || exit 1
echo "dcn401_spl: all vectors match Linux SPL"
