#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_dml21/vectors.txt against Linux DML21.
#   drivers/gpu/tests/dcn401_dml21/check.sh [linux-tree]   (default /usr/src/linux)
# multi_vectors.txt is checked the same way with harness_multi.c, and
# ycbcr420_vectors.txt with it on HDMI YCbCr 4:2:0 outputs plane_vectors.txt
# (scaled planes, several planes per stream) is checked with harness_planes.c,
# whose inputs carry each plane's surface, viewport, ratios and taps.
#
# Builds the DCN4 DML21 sources twice on the host: as shipped ("plain"), and
# "strict" with the Tpre > max(Turg, Ttrip) + Tex check that Linux compiles
# out (#if 0 in CalculatePrefetchSchedule) enabled, as the Rust port enforces
# it. Vector lines:
#   <19 inputs> = <62 plan values>   strict Linux plans these exact values,
#                                    except +-1 on deep-sleep DCFCLK and the
#                                    three urgent-bandwidth fractions
#   <19 inputs> ! <Error>            strict Linux rejects the mode too
#   <19 inputs> ! <Error> if0        only the re-enabled check rejects it
#   <19 inputs> ! <Error> dfs        Linux plans a DISPCLK below DFS divider
#                                    2.0, which the DENTIST cannot produce
#   <19 inputs> ! <Error> range      Linux plans a DLG/TTU value outside the
#                                    field width it asserts (asserts are off)
#   <19 inputs> ! Unsupported odm    Linux plans the stream on three or four
#                                    ODM pipes, which the port does not admit
# Both harnesses let DML decide ODM combine (dml2_odm_mode_auto, dynamic ODM
# off). A plane on n > 1 pipes ends its plan values with "/<n>" and every
# further pipe's refcyc_h_blank_end, the one register Linux programs
# differently per pipe (the harness checks the rest are identical).
# dsc_vectors.txt lines are "<slices> <bpp_x16>" then a multi_vectors.txt
# line, every stream compressed so (harness_multi.c with DSC set); "! REJECT"
# asks only that Linux rejects. --generate-dsc rewrites it from the single-
# and multi-stream inputs. odm_vectors.txt, odm_dsc_vectors.txt and
# uhbr_dsc_vectors.txt holds the DSC configurations the native UHBR DSC
# policy picks (8K60, 4K240, 4K144 and pairs of them), every stream on a
# 128b/132b encoder (DP2P0=1, dml2_dp2p0 as DC passes an HPO stream);
# --regenerate-uhbr-dsc answers its inputs again. dsc_vectors.txt and
# odm_dsc_vectors.txt are replayed with DP2P0=1 too: the port's plan does
# not depend on the DP encoder. frl_dsc_vectors.txt holds the configurations
# the native HDMI FRL DSC policy picks (8K60 VIC 199, 8K60 and 4K240
# RBv2), every stream on an HDMI FRL encoder (HDMIFRL=1, dml2_hdmifrl);
# --regenerate-frl-dsc answers its inputs again, and dsc_vectors.txt and
# odm_dsc_vectors.txt are replayed with HDMIFRL=1 as well.
# odm_ycbcr420_vectors.txt are checked as multi_vectors.txt, dsc_vectors.txt
# and ycbcr420_vectors.txt; their streams need ODM 2:1 on most boards.
# format_vectors.txt lines are "<bytes per pixel>" then a multi_vectors.txt
# line, every plane RGB565 (2, dml2_444_16) or FP16 (8, dml2_444_64) as
# harness_multi.c plans it with PIXEL_BYTES set; --generate-format rewrites
# it from the single-, multi-stream and ODM inputs, each pitch re-aligned to
# 256 bytes at that depth. Its "! ClockState raised" lines are plans whose
# DCFCLK or FCLK DPMM raises above the pinned UCLK's minimum for bandwidth
# (harness_multi.c with RAISED set), which the port does not plan; its
# "! PixelClock dfs" lines are as vectors.txt's.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate_dsc=0 generate_format=0
if [ "${1:-}" = --generate-dsc ]; then
	generate_dsc=1
	shift
elif [ "${1:-}" = --regenerate-uhbr-dsc ]; then
	generate_dsc=2
	shift
elif [ "${1:-}" = --generate-format ]; then
	generate_format=1
	shift
elif [ "${1:-}" = --regenerate-frl-dsc ]; then
	generate_dsc=3
	shift
fi
linux=${1:-/usr/src/linux}
dml=$linux/drivers/gpu/drm/amd/display/dc/dml2_0/dml21
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

inc=(-I"$here/include" -I"$dml/inc" -I"$dml/src/inc" -I"$dml/inc/bounding_boxes"
     -I"$linux/drivers/gpu/drm/amd/display/dmub/inc" -I"$linux/drivers/gpu/drm/amd/include")
for d in "$dml"/src/*/; do inc+=(-I"$d"); done

calcs=$dml/src/dml2_core/dml2_core_dcn4_calcs.c
mkdir -p "$work/obj"
for f in $(find "$dml/src" -name '*.c' ! -name dml2_top_legacy.c); do
	cc -c -O1 -w "${inc[@]}" "$f" -o "$work/obj/$(basename "$f" .c).o"
done
marker='bool tpre_gt_req_latency = true;'
awk -v m="$marker" '
	{ print }
	index($0, m) { getline; if ($0 != "#if 0") { exit 1 } print "#if 1"; n++ }
	END { if (n != 1) exit 1 }' "$calcs" > "$work/strict_calcs.c" ||
	{ echo "Linux CalculatePrefetchSchedule no longer matches; review the strict check" >&2; exit 1; }
cc -c -O1 -w "${inc[@]}" -I"$dml/src/dml2_core" "$work/strict_calcs.c" -o "$work/strict_calcs.o"
others=$(ls "$work"/obj/*.o | grep -v '/dml2_core_dcn4_calcs\.o$')
cc -O1 -w "${inc[@]}" "$here/harness.c" "$work/obj/dml2_core_dcn4_calcs.o" $others -lm -o "$work/plain"
cc -O1 -w "${inc[@]}" "$here/harness.c" "$work/strict_calcs.o" $others -lm -o "$work/strict"
cc -O1 -w "${inc[@]}" "$here/harness_multi.c" "$work/strict_calcs.o" $others -lm -o "$work/strict_multi"
cc -O1 -w "${inc[@]}" "$here/harness_planes.c" "$work/strict_calcs.o" $others -lm -o "$work/strict_planes"

# dsc_lines [env...]: classify "<slices> <bpp_x16> <multi-stream inputs>"
# lines from stdin with Linux (harness_multi.c, DSC, the given environment).
dsc_lines() {
	while read -r sl bp line; do
		read -ra a <<< "$line"
		out=$(env DSC="$sl $bp" "$@" "$work/strict_multi" "${a[@]:0:9}" "${a[@]:10}")
		# A plan whose DLG/TTU/watermark value overflows its register field
		# (Linux only asserts) is the port's Register rejection; a second
		# ODM pipe's blank end ("/2 <end>") has the blank end's field.
		if [ "${out%% *}" = PLAN ] && [[ " $out " == *" /3 "* || " $out " == *" /4 "* ]]; then
			echo "$sl $bp $line ! Unsupported odm"
		elif [ "${out%% *}" = PLAN ] && echo "${out#PLAN }" | awk '
			BEGIN { n = split("13 8192 14 32768 15 262144 16 2097152 17 8192 18 8 19 256 20 128 21 64 22 2097152 23 4194304 24 4194304 25 8192 26 8192 31 16384 32 16777216 33 16 34 8388608 35 8388608 36 16 38 16384 39 65536 40 65536 41 65536 42 65536 43 65536 44 16384 45 16384 46 16384 47 1024 48 1024 49 1024 55 4096 57 134217728", l)
				for (i = 1; i < n; i += 2) lim[l[i]] = l[i + 1] }
			{ f = 0
			  for (i = 1; i <= NF; i++) {
				if ($i == "|") { f = 0; continue }
				if ($i == "/2") { if ($(i + 1) + 0 >= 8192) bad = 1; i++; continue }
				if (f in lim && $i + 0 >= lim[f] + 0) bad = 1
				f++ } }
			END { exit !bad }'; then
			echo "$sl $bp $line ! Register"
		elif [ "${out%% *}" = PLAN ]; then
			echo "$sl $bp $line = ${out#PLAN }"
		else
			echo "$sl $bp $line ! REJECT"
		fi
	done
}
if [ $generate_dsc -eq 1 ]; then
	echo "# Linux DML21 reference vectors for amdgpu_dcn401_dml.rs with DSC; see check.sh."
	# Every single- and multi-stream input, as multi-stream lines, with a
	# cycle of slice counts (including counts one DSC cannot take) and
	# compressed bpps.
	{
		grep -v '^#' "$here/vectors.txt" | awk '{
			printf "%s %s %s %s %s %s %s %s %s 1", $10, $11, $12, $13, $14, $15, $16, $17, $18
			printf " %s %s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $19 }'
		grep -v '^#' "$here/multi_vectors.txt" | sed 's/ [=!].*//'
	} | awk 'BEGIN { split("1 2 4 3 8 1 2 4", sl); split("128 192 256 160 96 200 144 120 240", bpp) }
		{ print sl[NR % 8 + 1], bpp[NR % 9 + 1], $0 }' | dsc_lines
	exit 0
fi
if [ $generate_dsc -eq 3 ]; then
	# frl_dsc_vectors.txt likewise, every stream on an HDMI FRL encoder.
	while IFS= read -r line; do
		case $line in
		''|'#'*) echo "$line" ;;
		*) echo "${line%% [=!]*}" | dsc_lines HDMIFRL=1 ;;
		esac
	done < "$here/frl_dsc_vectors.txt"
	exit 0
fi
if [ $generate_dsc -eq 2 ]; then
	# uhbr_dsc_vectors.txt keeps its comments and inputs; Linux answers
	# each again with every stream on a 128b/132b (dml2_dp2p0) encoder.
	while IFS= read -r line; do
		case $line in
		''|'#'*) echo "$line" ;;
		*) echo "${line%% [=!]*}" | dsc_lines DP2P0=1 ;;
		esac
	done < "$here/uhbr_dsc_vectors.txt"
	exit 0
fi

# classify <prefix> <line> <strict_multi output>: the generated vector line.
classify() {
	local prefix=$1 line=$2 out=$3
	# A raised DCF/fabric state (RAISED set) is the port's ClockState, and a
	# DISPCLK or DPPREFCLK above VCO / 2 (DFS divider below 2.0) its
	# PixelClock, as vectors.txt's "dfs" lines.
	if [ "$out" = RAISED ]; then
		echo "$prefix $line ! ClockState raised"
		return
	fi
	if [ "${out%% *}" = PLAN ] && echo "${out#PLAN }" | awk '{ exit !($1 > 2250000 || $2 > 2250000) }'; then
		echo "$prefix $line ! PixelClock dfs"
		return
	fi
	# A plan whose DLG/TTU/watermark value overflows its register field
	# (Linux only asserts) is the port's Register rejection; a second
	# ODM pipe's blank end ("/2 <end>") has the blank end's field.
	if [ "${out%% *}" = PLAN ] && [[ " $out " == *" /3 "* || " $out " == *" /4 "* ]]; then
		echo "$prefix $line ! Unsupported odm"
	elif [ "${out%% *}" = PLAN ] && echo "${out#PLAN }" | awk '
		BEGIN { n = split("13 8192 14 32768 15 262144 16 2097152 17 8192 18 8 19 256 20 128 21 64 22 2097152 23 4194304 24 4194304 25 8192 26 8192 31 16384 32 16777216 33 16 34 8388608 35 8388608 36 16 38 16384 39 65536 40 65536 41 65536 42 65536 43 65536 44 16384 45 16384 46 16384 47 1024 48 1024 49 1024 55 4096 57 134217728", l)
			for (i = 1; i < n; i += 2) lim[l[i]] = l[i + 1] }
		{ f = 0
		  for (i = 1; i <= NF; i++) {
			if ($i == "|") { f = 0; continue }
			if ($i == "/2") { if ($(i + 1) + 0 >= 8192) bad = 1; i++; continue }
			if (f in lim && $i + 0 >= lim[f] + 0) bad = 1
			f++ } }
		END { exit !bad }'; then
		echo "$prefix $line ! Register"
	elif [ "${out%% *}" = PLAN ]; then
		echo "$prefix $line = ${out#PLAN }"
	else
		echo "$prefix $line ! REJECT"
	fi
}
# single_as_multi: vectors.txt inputs as one-stream multi_vectors.txt lines.
single_as_multi() {
	grep -v '^#' "$here/vectors.txt" | awk '{
		printf "%s %s %s %s %s %s %s %s %s 1", $10, $11, $12, $13, $14, $15, $16, $17, $18
		printf " %s %s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $19 }'
}

if [ $generate_format -eq 1 ]; then
	echo "# Linux DML21 reference vectors for amdgpu_dcn401_dml.rs with RGB565 (2) and"
	echo "# FP16 (8 bytes per pixel) planes; see check.sh."
	# Every single-, multi-stream and ODM input at both depths, each
	# stream's pitch the line rounded up to whole 256-byte requests.
	{
		single_as_multi
		grep -v '^#' "$here/multi_vectors.txt" | sed 's/ [=!].*//'
		grep -v '^#' "$here/odm_vectors.txt" | sed 's/ [=!].*//'
	} | while read -r line; do
		for b in 2 8; do
			at=$(echo "$line" | awk -v b=$b '{
				r = 256 / b
				for (k = 0; k < $10; k++) { i = 11 + 10 * k; $(i + 9) = int(($(i + 1) + r - 1) / r) * r }
				print }')
			read -ra a <<< "$at"
			out=$(RAISED=1 PIXEL_BYTES=$b "$work/strict_multi" "${a[@]:0:9}" "${a[@]:10}")
			classify "$b" "$at" "$out"
		done
	done
	exit 0
fi

tolerated=" 3 47 48 49 "
# plan_matches <planes> <strict output> <want...>: strict Linux plans
# <planes> planes with these values token for token ("|" between planes,
# "/2 <end>" after a two-pipe plane), except +-1 on the tolerated fields.
plan_matches() {
	local planes=$1 strict=$2 i d field=0 seps=0 got
	shift 2
	local want=("$@")
	[ "${strict%% *}" = PLAN ] || return 1
	read -ra got <<< "${strict#PLAN }"
	[ ${#got[@]} -eq ${#want[@]} ] || return 1
	for i in "${!want[@]}"; do
		case ${want[i]} in
		'|')
			[ "${got[i]}" = '|' ] || return 1
			field=0 seps=$((seps + 1))
			continue ;;
		/*)
			[ "${got[i]}" = "${want[i]}" ] || return 1
			field=-1
			continue ;;
		esac
		[[ ${got[i]} =~ ^[0-9]+$ ]] || return 1
		d=$(( got[i] - want[i] ))
		if [ $d -ne 0 ] && ! { [ $field -ge 0 ] && [[ $tolerated == *" $field "* ]] && [ ${d#-} -eq 1 ]; }; then
			return 1
		fi
		[ $field -lt 0 ] || field=$((field + 1))
	done
	[ $seps -eq $((planes - 1)) ]
}
# odm_plan <strict output>: Linux plans some stream on three or four pipes.
odm_plan() {
	[ "${1%% *}" = PLAN ] && [[ " $1 " == *" /3 "* || " $1 " == *" /4 "* ]]
}
pass=0 fail=0
while read -r line; do
	case $line in ''|'#'*) continue ;; esac
	read -ra f <<< "$line"
	inputs=("${f[@]:0:19}") kind=${f[19]} rest=("${f[@]:20}")
	strict=$("$work/strict" "${inputs[@]}")
	plain=$("$work/plain" "${inputs[@]}")
	ok=1
	if [ "$kind" = "=" ]; then
		plan_matches 1 "$strict" "${rest[@]}" || ok=0
	else
		case ${rest[1]:-} in
		'') [ "$strict" = REJECT ] || ok=0 ;;
		if0) [ "$strict" = REJECT ] && [ "${plain%% *}" = PLAN ] || ok=0 ;;
		dfs|range) [ "${strict%% *}" = PLAN ] || ok=0 ;;
		odm) odm_plan "$strict" || ok=0 ;;
		*) ok=0 ;;
		esac
	fi
	if [ $ok -eq 1 ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "MISMATCH: $line" >&2
		echo "  strict: $strict" >&2
	fi
done < "$here/vectors.txt"
echo "dcn401 DML21 vectors: $pass passed, $fail failed"

# check_multi <file> [env...]: multi-stream vectors with harness_multi.
check_multi() {
	local file=$1 pass=0 fail=0 dsc= bytes=
	shift
	while read -r line; do
		case $line in ''|'#'*) continue ;; esac
		read -ra f <<< "$line"
		if [ "${1:-}" = DSC ]; then
			dsc="${f[0]} ${f[1]}" f=("${f[@]:2}")
		elif [ "${1:-}" = FORMAT ]; then
			bytes=${f[0]} f=("${f[@]:1}")
		fi
		local envs=("${@:2}")
		[ "${1:-}" = DSC ] || [ "${1:-}" = FORMAT ] || envs=("$@")
		n=${f[9]} count=$((10 + 10 * f[9]))
		inputs=("${f[@]:0:count}") kind=${f[count]} rest=("${f[@]:count+1}")
		if [ -n "$dsc" ]; then
			strict=$(env DSC="$dsc" "${envs[@]}" "$work/strict_multi" "${inputs[@]:0:9}" "${inputs[@]:10}")
		else
			strict=$(env ${bytes:+RAISED=1 PIXEL_BYTES="$bytes"} "${envs[@]}" "$work/strict_multi" "${inputs[@]:0:9}" "${inputs[@]:10}")
		fi
		ok=1
		if [ "$kind" = "=" ]; then
			plan_matches "$n" "$strict" "${rest[@]}" || ok=0
		elif [ "${rest[1]:-}" = odm ]; then
			odm_plan "$strict" || ok=0
		elif [ "${rest[1]:-}" = raised ]; then
			[ "$strict" = RAISED ] || ok=0
		elif [ "${rest[1]:-}" = dfs ]; then
			[ "${strict%% *}" = PLAN ] || ok=0
		elif [ "${rest[0]:-}" = Register ]; then
			[ "${strict%% *}" = PLAN ] || ok=0
		else
			[ "$strict" = REJECT ] || ok=0
		fi
		if [ $ok -eq 1 ]; then
			pass=$((pass + 1))
		else
			fail=$((fail + 1))
			echo "MISMATCH: $line" >&2
			echo "  strict: $strict" >&2
		fi
	done < "$file"
	echo "dcn401 DML21 $(basename "$file" .txt)${envs[*]:+ (${envs[*]})}: $pass passed, $fail failed"
	[ $fail -eq 0 ]
}
# check_planes <file>: plane_vectors.txt lines (harness_planes.c, RAISED):
# "= <values>" is Linux's exact plan output, "! REJECT" its rejection.
check_planes() {
	local file=$1 pass=0 fail=0
	while read -r line; do
		case $line in ''|'#'*) continue ;; esac
		local inputs=${line%% [=!] *}
		local kind=${line:${#inputs}+1:1} result=${line:${#inputs}+3}
		read -ra a <<< "$inputs"
		strict=$(RAISED=1 "$work/strict_planes" "${a[@]}")
		if { [ "$kind" = "=" ] && [ "$strict" = "PLAN $result" ]; } ||
			{ [ "$kind" = "!" ] && [ "$result" = REJECT ] && [ "$strict" = REJECT ]; }; then
			pass=$((pass + 1))
		else
			fail=$((fail + 1))
			echo "MISMATCH: $line" >&2
			echo "  strict: $strict" >&2
		fi
	done < "$file"
	echo "dcn401 DML21 $(basename "$file" .txt): $pass passed, $fail failed"
	[ $fail -eq 0 ]
}
mfail=0
check_planes "$here/plane_vectors.txt" || mfail=1
check_multi "$here/multi_vectors.txt" || mfail=1
check_multi "$here/ycbcr420_vectors.txt" FMT420=1 || mfail=1
check_multi "$here/dsc_vectors.txt" DSC || mfail=1
check_multi "$here/odm_vectors.txt" || mfail=1
check_multi "$here/odm_dsc_vectors.txt" DSC || mfail=1
check_multi "$here/odm_ycbcr420_vectors.txt" FMT420=1 || mfail=1
# DC passes a 128b/132b stream as dml2_dp2p0; the port's plans do not depend
# on the DP encoder (the output link is disabled, the compressed bpp is
# forced), so the DSC sets must match Linux on HPO outputs unchanged.
check_multi "$here/dsc_vectors.txt" DSC DP2P0=1 || mfail=1
check_multi "$here/odm_dsc_vectors.txt" DSC DP2P0=1 || mfail=1
check_multi "$here/uhbr_dsc_vectors.txt" DSC DP2P0=1 || mfail=1
check_multi "$here/format_vectors.txt" FORMAT || mfail=1
# DC passes an HDMI FRL stream as dml2_hdmifrl; for a 4:4:4 DSC stream DML's
# DSC delays and plan do not depend on it either. DCN401 has one HDMI FRL
# output (NumberOfHDMIFRLSupport), so only the single-stream lines replay.
for f in dsc_vectors odm_dsc_vectors; do
	awk '/^#/ || $12 == 1' "$here/$f.txt" > "$work/${f}_single.txt"
	check_multi "$work/${f}_single.txt" DSC HDMIFRL=1 || mfail=1
done
check_multi "$here/frl_dsc_vectors.txt" DSC HDMIFRL=1 || mfail=1
[ $fail -eq 0 ] && [ $mfail -eq 0 ]
