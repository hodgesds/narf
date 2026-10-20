#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_color/vectors.txt against Linux's CRTC
# GAMMA_LUT -> MPC OGAM and CTM -> MPC gamut remap computation for DCN4
# (modules/color/color_gamma.c, dc/dcn30/dcn30_cm_common.c,
# dc/basics/{fixpt31_32,custom_float,conversion}.c and amdgpu_dm_color.c's
# helpers), compiled on the host; see harness.c for the line format.
#   drivers/gpu/tests/dcn401_color/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_color/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_dcn_color.rs must produce Linux's output for every line.
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
# Our stand-ins first: they replace dc.h, opp.h, dm_services.h and the DC
# core headers dcn30_cm_common.c names but does not use.
flags=(-O1 -w -include os_types.h -I"$here/include" -I"$d/dc/inc/hw" -I"$d/dc/dwb"
	-I"$d/dc" -I"$d/dc/inc" -I"$d/include" -I"$d/modules/color" -I"$d"
	-I"$linux/drivers/gpu/drm/amd/include" -idirafter "$linux/include")
for f in "$d/modules/color/color_gamma.c" "$d/dc/basics/fixpt31_32.c" \
	"$d/modules/color/color_table.c" "$d/dc/basics/custom_float.c" \
	"$d/dc/basics/conversion.c" \
	"$d/dc/dcn30/dcn30_cm_common.c"; do
	cc -c "${flags[@]}" "$f" -o "$work/$(basename "$f" .c).o"
done
cc "${flags[@]}" -Wall -Wno-unused-function "$here/harness.c" "$work"/*.o -o "$work/color"

if [ $generate -eq 1 ]; then
	echo "# Linux DCN4 CRTC color reference vectors; see check.sh and harness.c."
	{
	# Full LUT dumps for a few shapes, then hashed ones.
	for n in 256 4096; do
		for kind in 0 3 5; do
			echo "F $n $kind 1"
		done
	done
	for n in 256 4096; do
		for kind in 0 1 2 3 4 5 6 7 8 9 10; do
			for seed in 1 2 3 4 5 6; do
				echo "G $n $kind $seed"
			done
		done
	done
	# CTMs: S31.32 sign-magnitude words.
	one=0000000100000000
	neg=8000000000000000
	z=0000000000000000
	echo "C $one $z $z $z $one $z $z $z $one"
	echo "C $z $one $z $one $z $z $z $z $one"
	echo "C $z $z $one $z $one $z $one $z $z"
	echo "C $neg $z $z $z $neg $z $z $z $neg"
	echo "C 8000000100000000 $z $z $z 8000000100000000 $z $z $z 8000000100000000"
	echo "C 0000000080000000 0000000040000000 8000000020000000 $z $one $z $z $z $one"
	# BT.709 -> BT.2020 style, then around the S2.13/S3.12 boundaries.
	echo "C 00000000a0a1d5a3 0000000055b1ef7d 0000000007a24bde 00000000119a0e9a 00000000eb4a8bcd 0000000001660cf9 000000000444a5dc 0000000018e1a8ac 00000000e2d5b169"
	for v in 00000003ffd60e95 00000003ffd60e96 00000003ffd60e97 0000000400000000 0000000400000001 00000007ffac1d2a 00000007ffac1d2b 0000000800000000 0000001000000000 7fffffffffffffff; do
		echo "C $v $z $z $z $one $z $z $z $one"
		echo "C 8${v:1} $z $z $z $one $z $z $z $one"
	done
	echo "C ffffffffffffffff 7fffffffffffffff $z $z $one $z $z $z $one"
	echo "C 0000000000000001 8000000000000001 0000000000001000 80000000ffffffff 00000001ffffffff 0000000200000000 80000002fffffffe 0000000300000000 8000000380000000"
	RANDOM=4011
	for _ in $(seq 120); do
		c=C
		for _ in $(seq 9); do
			sign=$((RANDOM % 4 == 0 ? 8 : 0))
			int=$((RANDOM % 6 == 0 ? RANDOM % 16 : RANDOM % 3))
			c="$c $(printf '%x%07x%04x%04x' $sign $int $RANDOM $RANDOM)"
		done
		echo "$c"
	done
	} | while read -r in; do
		echo "$in = $(echo "$in" | "$work/color")"
	done
	exit 0
fi

grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//' | "$work/color" > "$work/got"
grep -v '^#' "$here/vectors.txt" | sed 's/.* = //' > "$work/want"
if ! diff -q "$work/want" "$work/got" >/dev/null; then
	diff "$work/want" "$work/got" | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
fi
echo "$(wc -l < "$work/want") ok"
