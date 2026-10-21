#!/usr/bin/env bash
# Verify drivers/gpu/tests/dcn401_fams2 against Linux's DMUB headers and DC:
#   layout.c    static asserts on the FAMS2_CONFIG, inbox0 HW lock, DALSMC
#               and watermark-table layouts amdgpu_dmub_navi48.rs and
#               amdgpu_dcn401_clk.rs use, compiled and run;
#   vectors.txt the bytes dc_dmub_srv_rb_based_fams2_update_config (extracted
#               verbatim from dc_dmub_srv.c, after shim.h) posts for
#               harness.c's cases. The dmub-navi48 kernel test
#               dmub_navi48_fams2_config_replays_linux_vectors replays every
#               line through fams2_config_commands.
#   drivers/gpu/tests/dcn401_fams2/check.sh [linux-tree]
#   drivers/gpu/tests/dcn401_fams2/check.sh --generate [linux-tree] > vectors.txt
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
display=$linux/drivers/gpu/drm/amd/display
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
inc=(-I"$here/../dcn401_dml21/include" -I"$display/dmub/inc"
     -I"$display/dc/clk_mgr/dcn401" -I"$linux/drivers/gpu/drm/amd/include")

cc -Wall -Wextra -Werror -std=gnu11 "${inc[@]}" "$here/layout.c" -o "$work/layout"
"$work/layout" || { echo "layout.c: DMUB inbox0 or FAMS2 feature words differ" >&2; exit 1; }

fn=dc_dmub_srv_rb_based_fams2_update_config
{
	cat "$here/shim.h"
	awk -v n="$fn" '
		!f && $0 ~ "^static void " n "\\(" { f = 1 }
		f { print }
		f && /^}/ { exit }' "$display/dc/dc_dmub_srv.c"
	cat "$here/harness.c"
} >"$work/fams2.c"
grep -q "^static void $fn(" "$work/fams2.c" || { echo "missing $fn" >&2; exit 1; }
cc -O1 -Wall -Wno-unused-parameter -std=gnu11 "${inc[@]}" "$work/fams2.c" -o "$work/fams2"

if [ $generate -eq 1 ]; then
	echo "# Linux DCN401 FAMS2_CONFIG command lists; see check.sh."
	"$work/fams2"
	exit 0
fi
"$work/fams2" | diff -q - <(grep -v '^#' "$here/vectors.txt") >/dev/null || {
	"$work/fams2" | diff - <(grep -v '^#' "$here/vectors.txt") | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
}
echo "dcn401 FAMS2 layouts ok, $(grep -vc '^#' "$here/vectors.txt") command lists ok"
