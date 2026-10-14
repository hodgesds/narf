#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_dsc/vectors.txt against Linux's DSC
# decision and configuration (dc/dsc/dc_dsc.c, dcn20_dsc.c's
# dsc_prepare_config, rc_calc*.c and DRM's drm_dsc_helper.c), compiled on
# the host with DCN401's encoder; see harness.c for the line format.
#   drivers/gpu/tests/dcn401_dsc/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_dsc/check.sh --generate [linux-tree] > vectors.txt
# amdgpu_dsc.rs must produce Linux's output for every line.
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
flags=(-O1 -w -include os_types.h -I"$here/include" -I"$d/dc" -I"$d/dc/inc" -I"$d/include"
	-I"$d/dc/dsc" -I"$d/dc/dsc/dcn401" -I"$d/dc/dml/dsc" -I"$d"
	-I"$linux/drivers/gpu/drm/amd/include" -idirafter "$linux/include")
for f in "$d/dc/dsc/dc_dsc.c" "$d/dc/dsc/rc_calc.c" "$d/dc/dsc/rc_calc_dpi.c" \
	"$d/dc/dml/dsc/rc_calc_fpu.c" "$d/dc/dsc/dcn20/dcn20_dsc.c" \
	"$d/dc/basics/fixpt31_32.c" "$linux/drivers/gpu/drm/display/drm_dsc_helper.c"; do
	cc -c "${flags[@]}" "$f" -o "$work/$(basename "$f" .c).o"
done
# dcn401_dsc.c (included for its static encoder caps) references register
# readers the harness never calls.
alias=()
for n in "" 2 3 4 5 6 7 8; do alias+=("-Wl,--defsym=generic_reg_get$n=abort"); done
cc "${flags[@]}" "$here/harness.c" "$work"/*.o -lm "${alias[@]}" -o "$work/dsc"

if [ $generate -eq 1 ]; then
	echo "# Linux DSC reference vectors (DCN401 encoder); see check.sh and harness.c."
	# pix_clk_100hz h_active h_total v_active v_total
	modes=("251750 640 800 480 525" "855000 1366 1792 768 798"
		"1485000 1920 2200 1080 1125" "5940000 1920 2200 1080 2250"
		"2415000 2560 2720 1440 1481" "6450000 2560 2720 1440 1580"
		"5550000 3440 3600 1440 1543" "5330000 3840 4000 2160 2222"
		"5940000 3840 4400 2160 2250" "13330000 3840 3920 2160 2287"
		"22440000 3840 3920 2160 2384" "9384000 5120 5280 2880 2962"
		"10000000 5120 5280 1440 1500" "11880000 7680 9000 4320 4400"
		"23760000 7680 9000 4320 4400" "5560000 4096 4400 2160 2250"
		"14850000 6016 6216 3384 3400" "3200000 2048 2200 1050 1100")
	# 4 x RBR..HBR3 with and without FEC, 2 x HBR2, 1 x HBR, UHBR10/13.5/20.
	links=(6480000 10800000 17280000 25920000 25142400 16761600 8640000 2160000
		38566400 52064700 77132800 19283200)
	clocks=(1200000 2000000 2400000 3000000)
	RANDOM=4011
	pick() { local -n a=$1; echo "${a[RANDOM % ${#a[@]}]}"; }
	for _ in $(seq 2500); do
		# Most vectors from a well-formed sink asked to compress; the rest
		# from arbitrary caps and targets.
		good=$((RANDOM % 10 < 7))
		v=$((RANDOM % 8 == 0 ? 0x12 : RANDOM % 3 == 0 ? 0x11 : 0x21))
		blk=$((RANDOM % 4 | (RANDOM % 4 == 0 ? (RANDOM % 32) << 3 : 0)))
		s1=$((RANDOM % 256)); [ $s1 -eq 0 ] && s1=11
		lb=$((RANDOM % 10))
		fmt=$((RANDOM % 4 == 0 ? RANDOM % 32 : RANDOM % 2 ? 0x1f : 0x13))
		dep=$((RANDOM % 4 == 0 ? RANDOM % 16 : 0x0e))
		tp=$((RANDOM % 256))
		sw=$((RANDOM % 5 == 0 ? RANDOM % 34 : 16))
		s2=$((RANDOM % 8))
		inc=$((RANDOM % 6))
		edp=$((RANDOM % 8 == 0 ? 96 + RANDOM % 300 : 0))
		sup=$((RANDOM % 30 == 0 ? 0 : 1))
		if [ $good -eq 1 ]; then
			lb=$((RANDOM % 8)) inc=$((RANDOM % 5)) sup=1
			tp=$(((1 + RANDOM % 15) | (1 + RANDOM % 15) << 4))
			fmt=$((fmt | 0x13)) dep=$((dep | 0x0e)) sw=$((sw < 8 ? 16 : sw))
		fi
		dpcd=$(printf '%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x00%02x' \
			$sup $v $blk $((RANDOM % 256)) $s1 $lb $((RANDOM % 2)) $((edp & 255)) \
			$((edp >> 8)) $fmt $dep $tp $sw $s2 $inc)
		m=$(pick modes)
		bpc=$(( (RANDOM % 3) * 2 + 8 ))
		enc=$((RANDOM % 4))
		link=$((RANDOM % 3 == 0 ? 1 : 0))
		if [ $good -eq 0 ] && [ $((RANDOM % 2)) -eq 0 ]; then
			target=$(pick links)
		else
			read -r pix _ <<<"$m"
			# 5..21 bpp worth of link (4..34 bpp off the good path).
			target=$(( pix / 10 * (good ? 50 + RANDOM % 160 : 40 + RANDOM % 300) / 10 ))
		fi
		force=$((RANDOM % 10 == 0 ? 1 : 0))
		in="$dpcd $(pick clocks) $m $bpc $enc $target $link $force"
		echo "$in = $(echo "$in" | "$work/dsc")"
	done
	exit 0
fi

grep -v '^#' "$here/vectors.txt" | sed 's/ = .*//' | "$work/dsc" > "$work/got"
grep -v '^#' "$here/vectors.txt" | sed 's/.* = //' > "$work/want"
if ! diff -q "$work/want" "$work/got" >/dev/null; then
	diff "$work/want" "$work/got" | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
fi
echo "$(wc -l < "$work/want") ok"
