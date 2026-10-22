#!/usr/bin/env bash
# Verify drivers/gpu/tests/navi22_dml30/vectors.txt against Linux's own
# DCN3.0 DML, compiled on the host (see harness.c for the policy).
#   drivers/gpu/tests/navi22_dml30/check.sh [--generate] [linux-tree]
# (default tree /usr/src/linux). Vector lines:
#   <9 soc> <n> <n x 13 stream> = <PLAN tokens>   Linux plans exactly this
#   <9 soc> <n> <n x 13 stream> ! REJECT          Linux rejects it
# --generate rewrites every line's right-hand side from Linux.
# amdgpu_dml30_tests.rs reads the same file and checks the Rust port
# against it (within one LSB on the fields named there).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
dc=$linux/drivers/gpu/drm/amd/display/dc
dml=$dc/dml
work=$(mktemp -d)
# KEEP=1 keeps the build (DEBUG=1 <work>/harness ... dumps per-plane VBA).
if [ -n "${KEEP:-}" ]; then
	echo "work=$work" >&2
else
	trap 'rm -rf -- "$work"' EXIT
fi

# dcn3_0_ip and dcn3_0_soc exactly as dcn30_fpu.c defines them.
{
	echo '/* extracted from dml/dcn30/dcn30_fpu.c by check.sh */'
	awk '/^struct _vcs_dpi_ip_params_st dcn3_0_ip = \{/ { p = 1; sub(/^struct/, "static struct") }
	     /^struct _vcs_dpi_soc_bounding_box_st dcn3_0_soc = \{/ { p = 1; sub(/^struct/, "static struct") }
	     p { print } p && /^\};/ { p = 0 }' "$dml/dcn30/dcn30_fpu.c"
} > "$work/dcn30_ip_soc.h"
grep -q dcn3_0_soc "$work/dcn30_ip_soc.h" || { echo "dcn3_0_soc not found" >&2; exit 1; }

# DCN30's DSC delay reads OutputBppPerState[k][VoltageLevel], the plane
# index in the state slot (the array is [state][plane]): with one state every
# plane after the first gets BPP 0 and no DSC delay, and on a multi-state
# board plane k gets plane VoltageLevel's bpp at state k. The port computes
# each plane's own delay, so the vectors are taken with the indices the
# array declares; the line must exist exactly once.
bug='double BPP = v->OutputBppPerState[k][v->VoltageLevel];'
[ "$(grep -cF "$bug" "$dml/dcn30/display_mode_vba_30.c")" = 1 ] ||
	{ echo "DCN30 DSC delay no longer matches; review the index fix" >&2; exit 1; }
mkdir -p "$work/dcn30"
sed 's/double BPP = v->OutputBppPerState\[k\]\[v->VoltageLevel\];/double BPP = v->OutputBppPerState[v->VoltageLevel][k];/' \
	"$dml/dcn30/display_mode_vba_30.c" > "$work/dcn30/display_mode_vba_30.c"
cp "$dml/dcn30/display_mode_vba_30.h" "$work/dcn30/"

flags=(-O1 -w -ffp-contract=off -I"$here/include" -I"$work" -I"$dml" -I"$dml/calcs" -I"$dc/inc")
for f in "$dml/display_mode_vba.c" "$work/dcn30/display_mode_vba_30.c" \
	"$dml/dcn30/display_rq_dlg_calc_30.c" "$dml/display_rq_dlg_helpers.c" \
	"$dml/calcs/dcn_calc_math.c"; do
	cc -c "${flags[@]}" "$f" -o "$work/$(basename "$f" .c).o"
done
# Newer DCN30 VBA calls the shared DML1 FRL capability checker. Link its
# primary implementation when present; older Linux trees predate this unit.
if [ -f "$dml/dml1_frl_cap_chk.c" ]; then
	cc -c "${flags[@]}" '-D__maybe_unused=__attribute__((unused))' \
		"$dml/dml1_frl_cap_chk.c" -o "$work/dml1_frl_cap_chk.o"
fi
cc "${flags[@]}" "$here/harness.c" "$work"/*.o -lm -o "$work/harness"

pass=0 fail=0
while IFS= read -r line; do
	case $line in ''|'#'*) [ $generate -eq 1 ] && echo "$line"; continue ;; esac
	inputs=${line%%[=!]*}
	read -ra a <<< "$inputs"
	got=$("$work/harness" "${a[@]}")
	if [ $generate -eq 1 ]; then
		case $got in
		PLAN*) echo "${inputs% } = ${got#PLAN }" ;;
		*) echo "${inputs% } ! $got" ;;
		esac
		continue
	fi
	want=${line#"$inputs"}
	case $want in
	'= '*) [ "PLAN ${want#= }" = "$got" ] ;;
	'! '*) [ "${want#! }" = "$got" ] ;;
	*) false ;;
	esac && pass=$((pass + 1)) || {
		fail=$((fail + 1))
		echo "MISMATCH: $inputs" >&2
		echo "  linux: $got" >&2
	}
done < "$here/vectors.txt"
[ $generate -eq 1 ] && exit 0
echo "navi22 DML30 vectors: $pass passed, $fail failed"
[ $fail -eq 0 ]
