#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_dsc/vectors.txt (DP) and frl_vectors.txt
# (HDMI FRL) against Linux's DSC decision and configuration
# (dc/dsc/dc_dsc.c, dcn20_dsc.c's dsc_prepare_config, rc_calc*.c and DRM's
# drm_dsc_helper.c), compiled on the host with DCN401's encoder; see
# harness.c and frl_harness.c for the line formats.
#   drivers/gpu/tests/dcn401_dsc/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_dsc/check.sh --generate [linux-tree] > vectors.txt
#   drivers/gpu/tests/dcn401_dsc/check.sh --generate-frl [linux-tree] > frl_vectors.txt
#   drivers/gpu/tests/dcn401_dsc/check.sh --generate-cvtem [linux-tree] > cvtem_vectors.txt
#   drivers/gpu/tests/dcn401_dsc/check.sh --generate-mst [linux-tree] > mst_vectors.txt
#   drivers/gpu/tests/dcn401_dsc/check.sh --generate-depth [linux-tree] > depth_vectors.txt
# cvtem_vectors.txt replays hpo_enc401_hdmi_set_dsc_config's CVTEM packets
# (cvtem_harness.c) for frl_vectors.txt's PPSes; mst_vectors.txt replays
# amdgpu_dm's MST DSC fairness search (mst_harness.c); depth_vectors.txt
# replays amdgpu_dm_create_validate_stream_for_sink's DP SST depth search
# with DSC at every depth (depth_harness.c).
# amdgpu_dsc.rs, the HPO FRL encoder's CVTEM and amdgpu_mst_dsc.rs must
# produce Linux's output for every line.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
elif [ "${1:-}" = --generate-frl ]; then
	generate=2
	shift
elif [ "${1:-}" = --generate-cvtem ]; then
	generate=3
	shift
elif [ "${1:-}" = --generate-mst ]; then
	generate=4
	shift
elif [ "${1:-}" = --generate-depth ]; then
	generate=5
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
cc "${flags[@]}" "$here/frl_harness.c" "$work"/*.o -lm "${alias[@]}" -o "$work/frl"
cc "${flags[@]}" "$here/depth_harness.c" "$work"/*.o -lm "${alias[@]}" -o "$work/depth"
# hpo_enc401_hdmi_set_dsc_config, extracted from the Linux source
# (cvtem_harness.c supplies its types and captures its packets).
awk '/^void hpo_enc401_hdmi_set_dsc_config\(/ { on = 1 } on { print } on && /^}/ { exit }' \
	"$d/dc/hpo/dcn401/dcn401_hpo_frl_stream_encoder.c" > "$work/set_dsc_config.c"
grep -q 'emp_packet' "$work/set_dsc_config.c" ||
	{ echo "hpo_enc401_hdmi_set_dsc_config not found" >&2; exit 1; }
cc -O1 -w -I"$work" "$here/cvtem_harness.c" -o "$work/cvtem"
# amdgpu_dm's MST DSC fairness functions, extracted from the Linux source
# (mst_harness.c supplies the DRM side and replays the link computation).
awk '/^struct dsc_mst_fairness_params \{/ { on = 1 }
	/^static bool get_conv_frl_bw/ { exit }
	on && !/^#if defined\(CONFIG_DRM_AMD_DC_FP\)/ { print }' \
	"$d/amdgpu_dm/amdgpu_dm_mst_types.c" > "$work/mst_fair.c"
grep -q 'try_disable_dsc' "$work/mst_fair.c" ||
	{ echo "amdgpu_dm MST DSC fairness functions not found" >&2; exit 1; }
cc "${flags[@]}" -I"$work" "$here/mst_harness.c" "$work"/*.o -lm "${alias[@]}" -o "$work/mst"
# cvtem_vectors.txt: every compressed frl_vectors.txt line's timing, slices,
# bpp and PPS, with a front porch and sync from its blanking.
cvtem_inputs() {
	grep -v '^#' "$here/frl_vectors.txt" | awk -F' = ' 'length($2) > 300 {
		split($1, i, " "); n = split($2, o, " ")
		ha = i[10]; ht = i[11]; b = ht - ha
		print ha, ht, int(b / 4), int(b / 8) < 4 ? 4 : int(b / 8), o[2], o[4], o[n]
	}'
}
if [ $generate -eq 5 ]; then
	echo "# Linux DP SST depth search reference vectors (DCN401 encoder); see check.sh and depth_harness.c."
	# pix_clk_100hz h_active h_total v_active v_total: 1080p60, 1440p165,
	# 3440x1440@100, 4K60, 4K120, 4K144 and 4K240 CVT-RBv2, 5K60, 8K30, 8K60
	# and 8K60 RBv2.
	modes=("1485000 1920 2200 1080 1125" "6450000 2560 2720 1440 1580"
		"5550000 3440 3600 1440 1543" "5940000 3840 4400 2160 2250"
		"11880000 3840 4400 2160 2250" "12542820 3840 3920 2160 2222"
		"21515900 3840 3920 2160 2287" "9384000 5120 5280 2880 2962"
		"11880000 7680 9000 4320 4400" "23760000 7680 9000 4320 4400"
		"20397930 7680 7760 4320 4381")
	rates=(6 10 20 30 30 30 1000 1350 2000)
	clocks=(1200000 2000000 2400000 3000000)
	edid=(0 8 10 10 12 12 14 16)
	requested=(8 10 10 12 12)
	RANDOM=4012
	pick() { local -n a=$1; echo "${a[RANDOM % ${#a[@]}]}"; }
	for _ in $(seq 2000); do
		# A DSC 1.1/1.2 decoder taking RGB at 8 bpc and, mostly, 10 and
		# 12 too; sometimes no decoder.
		v=$((RANDOM % 3 == 0 ? 0x11 : 0x21))
		dep=$((RANDOM % 4 == 0 ? 0x02 : RANDOM % 4 == 0 ? 0x06 : 0x0e))
		sup=$((RANDOM % 10 == 0 ? 0 : 1))
		dpcd=$(printf '%02x%02x%02x%02x%02x%02x%02x000013%02x%02x%02x%02x00%02x' \
			$sup $v $((RANDOM % 2)) $((RANDOM % 256)) $((0x0b | (RANDOM % 2) << 4)) \
			$((RANDOM % 8)) $((RANDOM % 2)) $dep \
			$(((1 + RANDOM % 15) | (1 + RANDOM % 15) << 4)) $((8 + RANDOM % 26)) \
			$((RANDOM % 8)) $((RANDOM % 5)))
		in="$dpcd $(pick clocks) $(pick modes) $(pick edid) $(pick requested)"
		in="$in $((1 << RANDOM % 3)) $(pick rates)"
		echo "$in = $(echo "$in" | "$work/depth")"
	done
	exit 0
fi
if [ $generate -eq 4 ]; then
	echo "# Linux MST DSC fairness reference vectors; see check.sh and mst_harness.c."
	# encoding link_kbps slots: 4 x HBR3, 4 x HBR2 and 2 x HBR3 with FEC;
	# 4 x UHBR10, 4 x UHBR20, 2 x UHBR10.
	links=("0 25142400 63" "0 16761600 63" "0 12571200 63" "1 38566400 64"
		"1 77132800 64" "1 19283200 64")
	# pix_clk_100hz h_active h_total v_active v_total: 4K144, 4K240 and 8K60
	# CVT-RBv2, 4K60, 1440p240, 5K60, 1080p60.
	modes=("12542820 3840 3920 2160 2222" "21515900 3840 3920 2160 2287"
		"20397930 7680 7760 4320 4381" "5940000 3840 4400 2160 2250"
		"9680000 2560 2720 1440 1481" "9384000 5120 5280 2880 2962"
		"1485000 1920 2200 1080 1125")
	# DSC 1.2 decoders: slices 1-12, 12-bit line buffer, block prediction,
	# RGB/YCbCr, 8-12 bpc, 700 or 450 MP/s per slice, 5120-pixel slices,
	# 1/16 or whole bpp increments; or none.
	decoders=("01210b0f7f030100001f0e8810000000" "01210b0f7f030100001f0e8810000000"
		"01210b0f7f030100001f0e3310000004" "01210b0f2b030100001f0e8810000000" "-")
	RANDOM=6201
	pick() { local -n a=$1; echo "${a[RANDOM % ${#a[@]}]}"; }
	for _ in $(seq 1500); do
		n=$((RANDOM % 10 == 0 ? 4 : 1 + RANDOM % 3))
		shared=$((RANDOM % 8 == 0 ? 2000 + RANDOM % 3000 : 65535))
		in="$(pick links) 2000000 $shared $n"
		for _ in $(seq $n); do
			port=$((RANDOM % 8 == 0 ? 1000 + RANDOM % 2000 : 65535))
			in="$in $(pick decoders) $(pick modes) $port"
		done
		echo "$in = $(echo "$in" | "$work/mst")"
	done
	exit 0
fi
if [ $generate -eq 3 ]; then
	echo "# Linux hpo_enc401_hdmi_set_dsc_config CVTEM packets; see check.sh and cvtem_harness.c."
	cvtem_inputs | while read -r line; do
		echo "$line =$(echo "$line" | "$work/cvtem")"
	done
	exit 0
fi

if [ $generate -eq 2 ]; then
	echo "# Linux HDMI FRL DSC reference vectors (DCN401 encoder); see check.sh and frl_harness.c."
	# pix_clk_100hz h_active h_total v_active v_total vic hdmi_vic: 4K30 (HDMI
	# VIC 1), 4K60 (97), 4K120 (118), 4K144 and 4K240 (RBv2), 5K120 (193),
	# 8K30 (196), 8K60 (199), 8K60 RBv2, 8K120 (201), 10K60 (215), 4096x2160
	# @120 (219), 1080p120 (63).
	modes=("2970000 3840 4400 2160 2250 0 1" "5940000 3840 4400 2160 2250 97 0"
		"11880000 3840 4400 2160 2250 118 0" "13330000 3840 3920 2160 2287 0 0"
		"22440000 3840 3920 2160 2384 0 0" "14850000 5120 5500 2160 2250 193 0"
		"11880000 7680 9000 4320 4400 196 0" "23760000 7680 9000 4320 4400 199 0"
		"20850000 7680 7760 4320 4481 0 0" "47520000 7680 9000 4320 4400 201 0"
		"29700000 10240 11000 4320 4500 215 0" "11880000 4096 4400 2160 2250 219 0"
		"2970000 1920 2200 1080 1125 63 0")
	clocks=(1200000 2000000 2400000 3000000)
	RANDOM=4401
	pick() { local -n a=$1; echo "${a[RANDOM % ${#a[@]}]}"; }
	for _ in $(seq 3000); do
		read -r pix ha ht va vt vic hvic <<<"$(pick modes)"
		# Mostly the mode's VIC; sometimes none (a detailed timing).
		if [ $((RANDOM % 4)) -eq 0 ]; then vic=0 hvic=0; fi
		# Mostly a well-formed 8-bpc RGB sink with slices, rate and chunk
		# buffer; the rest arbitrary.
		if [ $((RANDOM % 10)) -lt 7 ]; then
			caps="$((RANDOM % 2)) $((RANDOM % 2)) $((RANDOM % 3 == 0)) $((RANDOM % 2))"
			caps="$caps $((3 + RANDOM % 6)) $((3 + RANDOM % 4)) $((15 + RANDOM % 49))"
			fmt="$(( RANDOM % 4 == 0 ? (RANDOM % 3) * 2 + 8 : 8 )) $((RANDOM % 4 == 0 ? RANDOM % 4 : 0))"
		else
			caps="$((RANDOM % 2)) $((RANDOM % 2)) $((RANDOM % 3 == 0)) $((RANDOM % 2))"
			caps="$caps $((RANDOM % 9)) $((RANDOM % 8 == 0 ? RANDOM % 7 : 1 + RANDOM % 6))"
			caps="$caps $((RANDOM % 64))"
			fmt="$(( (RANDOM % 3) * 2 + 8 )) $((RANDOM % 4))"
		fi
		in="$caps $(pick clocks) $pix $ha $ht $va $vt $fmt $vic $hvic"
		echo "$in = $(echo "$in" | "$work/frl")"
	done
	exit 0
fi

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
grep -v '^#' "$here/frl_vectors.txt" | sed 's/ = .*//' | "$work/frl" > "$work/got_frl"
grep -v '^#' "$here/frl_vectors.txt" | sed 's/.* = //' > "$work/want_frl"
if ! diff -q "$work/want_frl" "$work/got_frl" >/dev/null; then
	diff "$work/want_frl" "$work/got_frl" | head -20 >&2
	echo "frl_vectors.txt does not match Linux" >&2
	exit 1
fi
grep -v '^#' "$here/cvtem_vectors.txt" | sed 's/ =.*//' | "$work/cvtem" > "$work/got_cvtem"
grep -v '^#' "$here/cvtem_vectors.txt" | sed 's/^[^=]*=//' > "$work/want_cvtem"
if ! diff -q "$work/want_cvtem" "$work/got_cvtem" >/dev/null; then
	diff "$work/want_cvtem" "$work/got_cvtem" | head -20 >&2
	echo "cvtem_vectors.txt does not match Linux" >&2
	exit 1
fi
grep -v '^#' "$here/mst_vectors.txt" | sed 's/ = .*//' | "$work/mst" > "$work/got_mst"
grep -v '^#' "$here/mst_vectors.txt" | sed 's/.* = //' > "$work/want_mst"
if ! diff -q "$work/want_mst" "$work/got_mst" >/dev/null; then
	diff "$work/want_mst" "$work/got_mst" | head -20 >&2
	echo "mst_vectors.txt does not match Linux" >&2
	exit 1
fi
grep -v '^#' "$here/depth_vectors.txt" | sed 's/ = .*//' | "$work/depth" > "$work/got_depth"
grep -v '^#' "$here/depth_vectors.txt" | sed 's/.* = //' > "$work/want_depth"
if ! diff -q "$work/want_depth" "$work/got_depth" >/dev/null; then
	diff "$work/want_depth" "$work/got_depth" | head -20 >&2
	echo "depth_vectors.txt does not match Linux" >&2
	exit 1
fi
# Every cvtem_vectors.txt input comes from frl_vectors.txt's PPSes.
if ! diff -q <(cvtem_inputs) <(grep -v '^#' "$here/cvtem_vectors.txt" | sed 's/ =.*//') >/dev/null; then
	echo "cvtem_vectors.txt inputs no longer follow frl_vectors.txt" >&2
	exit 1
fi
echo "$(cat "$work/want" "$work/want_frl" "$work/want_cvtem" "$work/want_mst" 	"$work/want_depth" | wc -l) ok"
