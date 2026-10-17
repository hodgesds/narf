#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_frl/vectors.txt against Linux's HDMI FRL
# capacity check (dml/dml1_frl_cap_chk.c, uncompressed), compiled on the host.
#   drivers/gpu/tests/dcn401_frl/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_frl/check.sh --generate [linux-tree] > vectors.txt
# Vector lines:
#   <lanes> <gbps> <pix_clk_100hz> <h_active> <h_blank> <bpc> <encoding>
#   <audio_packet_type> <f_audio> <layout> = <result> <audio_packets_line>
#   <borrow_mode>
# amdgpu_frl_cap.rs must produce Linux's result for every line (and, when
# the result is 0, the same packets per line and borrow mode).
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
cc -O1 -w -I"$here/include" -I"$dc/dml" -I"$dc/inc" "$here/harness.c" \
	"$dc/dml/dml1_frl_cap_chk.c" "$dc/dml/calcs/dcn_calc_math.c" -lm -o "$work/frl"

if [ $generate -eq 1 ]; then
	echo "# Linux HDMI FRL capacity check reference vectors; see check.sh."
	# pix_clk_100hz h_active h_blank: 480p60, 1080p60, 1080p240, 1440p240
	# (RBv2), 4K60, 4K120, 4K144 (RBv2), 4K240 (RBv2), 5K60, 8K30, 8K60.
	modes=("270000 720 138" "1485000 1920 280" "5940000 1920 280"
		"9680000 2560 160" "5940000 3840 560" "11880000 3840 560"
		"13330000 3840 80" "22440000 3840 80" "7425000 5120 380"
		"11880000 7680 1320" "23760000 7680 1320")
	links=("3 3" "3 6" "4 6" "4 8" "4 10" "4 12")
	audios=("2 0 0" "2 48000 0" "2 192000 1" "9 768000 1" "8 48000 0" "7 48000 0")
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

pass=0 fail=0
while read -r line; do
	case $line in ''|'#'*) continue ;; esac
	in=${line%% = *} want=${line##* = }
	# shellcheck disable=SC2086
	got=$("$work/frl" $in)
	if [ "$got" = "$want" ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "MISMATCH: $in = $want (Linux: $got)" >&2
	fi
done < "$here/vectors.txt"
echo "$pass ok, $fail mismatched"
[ $fail -eq 0 ]
