#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_frl/vectors.txt and dsc_vectors.txt against
# Linux's HDMI FRL capacity check (dml/dml1_frl_cap_chk.c), compiled on the
# host: uncompressed (harness.c), and compressed with the decided link's
# frl_modify_borrow_mode_for_dsc_padding (harness_dsc.c).
#   drivers/gpu/tests/dcn401_frl/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_frl/check.sh --generate [linux-tree] > vectors.txt
#   drivers/gpu/tests/dcn401_frl/check.sh --generate-dsc [linux-tree] > dsc_vectors.txt
# vectors.txt lines:
#   <lanes> <gbps> <pix_clk_100hz> <h_active> <h_blank> <bpc> <encoding>
#   <audio_packet_type> <f_audio> <layout> = <result> <audio_packets_line>
#   <borrow_mode>
# dsc_vectors.txt lines add <slices> <slice_width> <bpp_x16> <vic> <all_bpp>
# to the inputs and <hc_active> <hc_blank> <padding_borrow_mode> to the
# outputs (-1 for the last when the check fails).
# amdgpu_frl_cap.rs must produce Linux's result for every line (and, when
# the result is 0, every other output).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
elif [ "${1:-}" = --generate-dsc ]; then
	generate=2
	shift
fi
linux=${1:-/usr/src/linux}
dc=$linux/drivers/gpu/drm/amd/display/dc
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cc -O1 -w -I"$here/include" -I"$dc/dml" -I"$dc/inc" "$here/harness.c" \
	"$dc/dml/dml1_frl_cap_chk.c" "$dc/dml/calcs/dcn_calc_math.c" -lm -o "$work/frl"
cc -O1 -w -DCONFIG_DRM_AMD_DC_FP -I"$here/include" -I"$dc/dml" -I"$dc/inc" \
	"$here/harness_dsc.c" "$dc/dml/dml1_frl_cap_chk.c" "$dc/dml/calcs/dcn_calc_math.c" \
	-lm -o "$work/frl_dsc"

links=("3 3" "3 6" "4 6" "4 8" "4 10" "4 12")
audios=("2 0 0" "2 48000 0" "2 192000 1" "9 768000 1" "8 48000 0" "7 48000 0")
if [ $generate -eq 1 ]; then
	echo "# Linux HDMI FRL capacity check reference vectors; see check.sh."
	# pix_clk_100hz h_active h_blank: 480p60, 1080p60, 1080p240, 1440p240
	# (RBv2), 4K60, 4K120, 4K144 (RBv2), 4K240 (RBv2), 5K60, 8K30, 8K60.
	modes=("270000 720 138" "1485000 1920 280" "5940000 1920 280"
		"9680000 2560 160" "5940000 3840 560" "11880000 3840 560"
		"13330000 3840 80" "22440000 3840 80" "7425000 5120 380"
		"11880000 7680 1320" "23760000 7680 1320")
	for m in "${modes[@]}"; do
		for l in "${links[@]}"; do
			for bpc in 8 10 12; do
				for enc in 0 1 2; do
					for a in "${audios[@]}"; do
						in="$l $m $bpc $enc $a"
						# shellcheck disable=SC2086
						echo "$in = $("$work/frl" $in)"
					done
				done
			done
		done
	done
	exit 0
fi
if [ $generate -eq 2 ]; then
	echo "# Linux compressed HDMI FRL capacity check reference vectors; see check.sh."
	# pix_clk_100hz h_active h_blank vic: 1080p120 (VIC 63), 4K60 (97),
	# 4K120 (118), 4K144 and 4K240 (RBv2), 5K120 (193), 8K30 (196), 8K60
	# (199), 8K60 RBv2, 8K120 (201), 10K60 (215).
	modes=("2970000 1920 280 63" "5940000 3840 560 97" "11880000 3840 560 118"
		"13330000 3840 80 0" "22440000 3840 80 0" "14850000 5120 380 193"
		"11880000 7680 1320 196" "23760000 7680 1320 199" "20850000 7680 80 0"
		"47520000 7680 1320 201" "29700000 10240 760 215")
	slices=(1 2 4 8 12 16)
	RANDOM=2101
	pick() { local -n a=$1; echo "${a[RANDOM % ${#a[@]}]}"; }
	for m in "${modes[@]}"; do
		read -r pix ha hb vic <<<"$m"
		for l in "${links[@]}"; do
			for _ in $(seq 45); do
				enc=$((RANDOM % 4 == 0 ? 2 : RANDOM % 6 == 0 ? 1 : 0))
				bpc=$(( (RANDOM % 3) * 2 + 8 ))
				s=$(pick slices)
				sw=$(( (ha + s - 1) / s ))
				[ $enc -eq 2 ] && [ $((sw % 2)) -eq 1 ] && sw=$((sw + 1))
				bpp=$((96 + RANDOM % 161))
				# Mostly the mode's own VIC; sometimes none, or every bpp.
				v=$((RANDOM % 4 == 0 ? 0 : vic))
				all=$((RANDOM % 4 == 0 ? 1 : 0))
				in="$l $pix $ha $hb $bpc $enc $(pick audios) $s $sw $bpp $v $all"
				# shellcheck disable=SC2086
				echo "$in = $("$work/frl_dsc" $in)"
			done
		done
	done
	exit 0
fi

pass=0 fail=0
check() {
	local bin=$1 file=$2
	while read -r line; do
		case $line in ''|'#'*) continue ;; esac
		in=${line%% = *} want=${line##* = }
		# shellcheck disable=SC2086
		got=$("$bin" $in)
		if [ "$got" = "$want" ]; then
			pass=$((pass + 1))
		else
			fail=$((fail + 1))
			echo "MISMATCH: $in = $want (Linux: $got)" >&2
		fi
	done < "$file"
}
check "$work/frl" "$here/vectors.txt"
check "$work/frl_dsc" "$here/dsc_vectors.txt"
echo "$pass ok, $fail mismatched"
[ $fail -eq 0 ]
