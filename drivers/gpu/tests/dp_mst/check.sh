#!/usr/bin/env bash
# Verify drivers/gpu/tests/dp_mst/vectors.txt against Linux's DP MST
# sideband codec and PBN math, compiled on the host: the functions below are
# extracted verbatim from drm_dp_mst_topology.c / drm_dp_helper.c, with their
# structs from drm_dp_mst_helper.h, and driven by harness.c.
#   drivers/gpu/tests/dp_mst/check.sh [linux-tree]
#   drivers/gpu/tests/dp_mst/check.sh --generate [linux-tree] > vectors.txt
# dp_mst.rs must reproduce every line.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
topo=$linux/drivers/gpu/drm/display/drm_dp_mst_topology.c
helper=$linux/drivers/gpu/drm/display/drm_dp_helper.c
header=$linux/include/drm/display/drm_dp_mst_helper.h
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# extract <file> <function name>...: each function from its signature line to
# the first closing brace in column 0.
extract() {
	local file=$1
	shift
	for name in "$@"; do
		awk -v n="$name" '
			!f && $0 ~ "^(static |)[a-z_0-9 ]*[ *]" n "\\(" { f = 1 }
			!f && prev ~ "^(static |)[a-z_0-9 ]*$" && $0 ~ "^" n "\\(" { f = 1; print prev }
			f { print }
			f && /^}/ { exit }
			{ prev = $0 }' "$file" | grep -q . || { echo "missing $name" >&2; exit 1; }
		awk -v n="$name" '
			!f && $0 ~ "^(static |)[a-z_0-9 ]*[ *]" n "\\(" { f = 1 }
			!f && prev ~ "^(static |)[a-z_0-9 ]*$" && $0 ~ "^" n "\\(" { f = 1; print prev }
			f { print }
			f && /^}/ { exit }
			{ prev = $0 }' "$file"
	done
}

{
	cat "$here/shim.h"
	# The sideband header/rx structs and every request/reply body.
	awk '/^struct drm_dp_sideband_msg_hdr \{/,/^};/' "$header"
	awk '/^struct drm_dp_sideband_msg_rx \{/,/^};/' "$header"
	awk '/^struct drm_dp_nak_reply \{/{f=1} /^struct drm_dp_mst_topology_mgr;/{f=0} f' "$header"
	extract "$helper" drm_dp_bw_channel_coding_efficiency drm_dp_link_data_symbol_cycles \
		drm_dp_link_symbol_cycles drm_dp_bw_overhead
	extract "$topo" drm_dp_msg_header_crc4 drm_dp_msg_data_crc4 drm_dp_calc_sb_hdr_size \
		drm_dp_encode_sideband_msg_hdr drm_dp_decode_sideband_msg_hdr \
		drm_dp_encode_sideband_req drm_dp_crc_sideband_chunk_req \
		drm_dp_sideband_msg_set_header drm_dp_sideband_append_payload \
		drm_dp_sideband_parse_link_address drm_dp_sideband_parse_remote_dpcd_read \
		drm_dp_sideband_parse_remote_dpcd_write drm_dp_sideband_parse_remote_i2c_read_ack \
		drm_dp_sideband_parse_enum_path_resources_ack \
		drm_dp_sideband_parse_allocate_payload_ack drm_dp_sideband_parse_query_payload_ack \
		drm_dp_sideband_parse_power_updown_phy_ack \
		drm_dp_sideband_parse_query_stream_enc_status drm_dp_sideband_parse_reply \
		drm_dp_sideband_parse_connection_status_notify \
		drm_dp_sideband_parse_resource_status_notify drm_dp_sideband_parse_req \
		set_hdr_from_dst_qlock process_single_tx_qlock drm_dp_encode_sideband_reply \
		drm_dp_encode_up_ack_reply drm_dp_calc_pbn_mode
	cat "$here/harness.c"
} > "$work/mst.c"
cc -O1 -w -I"$here/../dcn401_dsc/include" -idirafter "$linux/include" "$work/mst.c" -o "$work/mst"

if [ $generate -eq 1 ]; then
	echo "# Linux DP MST sideband codec and PBN reference vectors; see check.sh."
	"$work/mst"
	exit 0
fi
"$work/mst" | diff -q - <(grep -v '^#' "$here/vectors.txt") >/dev/null || {
	"$work/mst" | diff - <(grep -v '^#' "$here/vectors.txt") | head -20 >&2
	echo "vectors.txt does not match Linux" >&2
	exit 1
}
echo "$(grep -vc '^#' "$here/vectors.txt") ok"
