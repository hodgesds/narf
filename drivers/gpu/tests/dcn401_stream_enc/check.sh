#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_stream_enc/vectors.txt against Linux DC's
# DCN401 stream-encoder acquisition, compiled on the host:
#   drivers/gpu/tests/dcn401_stream_enc/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_stream_enc/check.sh --generate [linux-tree] > vectors.txt
# Cut verbatim out of the Linux tree:
#   core/dc_resource.c   update_stream_engine_usage,
#                        update_hpo_dp_stream_engine_usage,
#                        find_first_free_match_hpo_dp_stream_enc_for_link and
#                        the HPO DP link encoder pool (find, acquire, retain,
#                        release, add_/remove_hpo_dp_link_enc_to/from_ctx)
#   dcn10_resource.c     dcn10_find_first_free_match_stream_enc_for_link
#                        (DCN401's find_first_free_match_stream_enc_for_link)
# harness.c documents the line format. amdgpu_dcn401_resource.rs must
# reproduce every line (dcn401_stream_encoder_acquisition_matches_linux).
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

# extract <file> <function name>...: each function from its signature line
# (or the line before, for a split signature) to the first closing brace in
# column 0.
extract() {
	local file=$1
	shift
	for name in "$@"; do
		awk -v n="$name" '
			!f && $0 ~ "^(static |)[a-z_0-9 ]*[ *]" n "\\(" && $0 !~ ";$" { f = 1 }
			!f && prev ~ "^(static |)[a-z_0-9 ]*$" && $0 ~ "^" n "\\(" { f = 1; print prev }
			f { print }
			f && /^}/ { exit }
			{ prev = $0 }' "$file" >"$work/fn"
		grep -q . "$work/fn" || { echo "missing $name" >&2; exit 1; }
		cat "$work/fn"
	done
}

{
	cat "$here/shim.h"
	echo "typedef uint64_t u64;"
	extract "$dc/core/dc_resource.c" update_stream_engine_usage \
		update_hpo_dp_stream_engine_usage find_acquired_hpo_dp_link_enc_for_link \
		find_free_hpo_dp_link_enc acquire_hpo_dp_link_enc retain_hpo_dp_link_enc \
		release_hpo_dp_link_enc add_hpo_dp_link_enc_to_ctx \
		remove_hpo_dp_link_enc_from_ctx find_first_free_match_hpo_dp_stream_enc_for_link
	extract "$dc/resource/dcn10/dcn10_resource.c" \
		dcn10_find_first_free_match_stream_enc_for_link
	cat "$here/harness.c"
} >"$work/enc.c"
cc -O1 -w "$work/enc.c" -o "$work/enc"

if [ $generate -eq 1 ]; then
	echo "# Linux DCN401 stream-encoder acquisition reference vectors; see check.sh."
	"$work/enc"
	exit 0
fi
"$work/enc" | diff -q - <(grep -v '^#' "$here/vectors.txt") >/dev/null || {
	"$work/enc" | diff - <(grep -v '^#' "$here/vectors.txt") | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
}
echo "$(grep -vc '^#' "$here/vectors.txt") ok"
