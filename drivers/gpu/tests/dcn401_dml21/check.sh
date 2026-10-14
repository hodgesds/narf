#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_dml21/vectors.txt against Linux DML21.
#   drivers/gpu/tests/dcn401_dml21/check.sh [linux-tree]   (default /usr/src/linux)
# multi_vectors.txt is checked the same way with harness_multi.c, and
# ycbcr420_vectors.txt with it on HDMI YCbCr 4:2:0 outputs.
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
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
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

tolerated=" 3 47 48 49 "
pass=0 fail=0
while read -r line; do
	case $line in ''|'#'*) continue ;; esac
	read -ra f <<< "$line"
	inputs=("${f[@]:0:19}") kind=${f[19]} rest=("${f[@]:20}")
	strict=$("$work/strict" "${inputs[@]}")
	plain=$("$work/plain" "${inputs[@]}")
	ok=1
	if [ "$kind" = "=" ]; then
		read -ra got <<< "${strict#PLAN }"
		if [ "${strict%% *}" != PLAN ] || [ ${#got[@]} -ne ${#rest[@]} ]; then
			ok=0
		else
			for i in "${!rest[@]}"; do
				d=$(( got[i] - rest[i] ))
				if [ $d -ne 0 ] && ! { [[ $tolerated == *" $i "* ]] && [ ${d#-} -eq 1 ]; }; then
					ok=0
				fi
			done
		fi
	else
		case ${rest[1]:-} in
		'') [ "$strict" = REJECT ] || ok=0 ;;
		if0) [ "$strict" = REJECT ] && [ "${plain%% *}" = PLAN ] || ok=0 ;;
		dfs|range) [ "${strict%% *}" = PLAN ] || ok=0 ;;
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
	local file=$1 pass=0 fail=0
	shift
	while read -r line; do
		case $line in ''|'#'*) continue ;; esac
		read -ra f <<< "$line"
		n=${f[9]} count=$((10 + 10 * f[9]))
		inputs=("${f[@]:0:count}") kind=${f[count]} rest=("${f[@]:count+1}")
		strict=$(env "$@" "$work/strict_multi" "${inputs[@]:0:9}" "${inputs[@]:10}")
		ok=1
		if [ "$kind" = "=" ]; then
			read -ra got <<< "${strict#PLAN }"
			got=("${got[@]/|}") want=("${rest[@]/|}")
			got=(${got[@]}) want=(${want[@]})
			if [ "${strict%% *}" != PLAN ] || [ ${#got[@]} -ne ${#want[@]} ] || [ ${#got[@]} -ne $((62 * n)) ]; then
				ok=0
			else
				for i in "${!want[@]}"; do
					d=$(( got[i] - want[i] ))
					if [ $d -ne 0 ] && ! { [[ $tolerated == *" $((i % 62)) "* ]] && [ ${d#-} -eq 1 ]; }; then
						ok=0
					fi
				done
			fi
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
	echo "dcn401 DML21 $(basename "$file" .txt): $pass passed, $fail failed"
	[ $fail -eq 0 ]
}
mfail=0
check_multi "$here/multi_vectors.txt" || mfail=1
check_multi "$here/ycbcr420_vectors.txt" FMT420=1 || mfail=1
[ $fail -eq 0 ] && [ $mfail -eq 0 ]
