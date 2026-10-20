#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_spl/vectors.txt against Linux SPL
# (dc/sspl) compiled on the host, and that amdgpu_dcn401_spl_filters.rs is
# gen_filters.py's output; see harness.c for the line format.
#   drivers/gpu/tests/dcn401_spl/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_spl/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_dcn401_spl.rs and amdgpu_dcn401_dscl.rs must produce Linux's
# output for every line (amdgpu_dcn401_spl_tests.rs replays them).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
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

if [ $generate -eq 1 ]; then
	echo "# Linux SPL reference vectors for amdgpu_dcn401_spl.rs; see check.sh and harness.c."
	echo "# src_x src_y src_w src_h dst_x dst_y dst_w dst_h stream_w stream_h odm_x odm_w rotation mirror alpha = writes"
	grep -v '^#' "$here/inputs.txt" | while read -r in; do
		[ -n "$in" ] || continue
		echo "$in = $(echo "$in" | "$work/spl")"
	done
	exit 0
fi

fail=0 n=0
while IFS= read -r line; do
	case $line in ''|'#'*) continue ;; esac
	in=${line%% = *}
	want=${line#* = }
	got=$(echo "$in" | "$work/spl")
	n=$((n + 1))
	if [ "$got" != "$want" ]; then
		echo "MISMATCH: $in" >&2
		echo "  linux:  $got" >&2
		echo "  vector: $want" >&2
		fail=1
	fi
done < "$here/vectors.txt"
[ $fail -eq 0 ] || exit 1
echo "dcn401_spl: $n vectors match Linux SPL"
