#!/usr/bin/env bash
# Verify amdgpu_rdna4's per-die tables against the Linux tree:
#   drivers/gpu/tests/rdna4_family/check.sh [linux-tree]
#   drivers/gpu/tests/rdna4_family/check.sh --generate [linux-tree]
# --generate prints policy.txt and firmware.txt (separated by a marker) from
# Linux; the default mode diffs them against the checked-in copies and
# compiles layout.c against the Linux register/PMFW headers. The kernel test
# rdna4_tables_match_linux_policy_and_firmware (amdgpu_rdna4_tests.rs) holds
# the Rust tables to the same two files.
#
# DAL names the external-revision ranges the other way round from the IP
# versions (dal_asic_id.h: GC_12_0_0_A0 = 0x50, GC_12_0_1_A0 = 0x40), so
# every DC policy below is mapped back to a GC IP version through soc24.c's
# external_rev_id offset before it is printed.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
generate=0
if [ "${1:-}" = --generate ]; then
	generate=1
	shift
fi
linux=${1:-/usr/src/linux}
amd=$linux/drivers/gpu/drm/amd
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

fail() {
	echo "rdna4_family: $*" >&2
	exit 1
}

# soc24_common_early_init: per GC case, the external_rev_id offset and
# whether AMD_PG_SUPPORT_JPEG_DPG is in pg_flags.
awk '
	/^static int soc24_common_early_init/ { on = 1 }
	on && /case IP_VERSION\(12, 0, [01]\):/ {
		match($0, /12, 0, [01]/); gc = substr($0, RSTART, RLENGTH); gsub(", ", ".", gc)
	}
	on && gc != "" && /AMD_PG_SUPPORT_JPEG_DPG/ { dpg[gc] = 1 }
	on && gc != "" && /external_rev_id = adev->rev_id \+ 0x/ {
		match($0, /0x[0-9a-fA-F]+/); off[gc] = tolower(substr($0, RSTART, RLENGTH))
	}
	on && /^}/ { on = 0 }
	END {
		for (g in off) {
			print "external_rev_offset." g "=" off[g]
			print "jpeg_dpg." g "=" (g in dpg ? 1 : 0)
		}
	}
' "$amd/amdgpu/soc24.c" | sort > "$work/soc24"
[ "$(wc -l < "$work/soc24")" -eq 4 ] || fail "soc24.c per-GC cases not found"

# dal_asic_id.h range starts, mapped to the GC whose external rev they hold.
dal_gc() { # $1 = DAL enum name
	local start
	start=$(sed -n "s/^[[:space:]]*$1 = \(0x[0-9a-fA-F]*\),.*/\1/p" "$amd/display/include/dal_asic_id.h" | tr A-F a-f)
	[ -n "$start" ] || fail "dal_asic_id.h $1 missing"
	sed -n "s/^external_rev_offset\.\(.*\)=$start$/\1/p" "$work/soc24"
}
gc_of_0_0=$(dal_gc GC_12_0_0_A0)
gc_of_0_1=$(dal_gc GC_12_0_1_A0)
[ -n "$gc_of_0_0" ] && [ -n "$gc_of_0_1" ] || fail "DAL range does not start at a soc24 external rev"
dal_map() { # ASICREV macro suffix -> GC version
	case $1 in
	GC_12_0_0_A0) echo "$gc_of_0_0" ;;
	GC_12_0_1_A0) echo "$gc_of_0_1" ;;
	*) fail "unknown DAL macro $1" ;;
	esac
}

# Every "ASICREV_IS_GC_12_0_x_A0(...)" condition in a DCN401 file, with the
# next numeric literal of interest on the same or the following lines.
asicrev() { # $1 file, $2 function, $3 regex of the value line, $4 key
	awk -v fn="$2" -v re="$3" -v key="$4" '
		$0 ~ "^[a-z].*" fn "\\(" { on = 1 }
		on && match($0, /ASICREV_IS_GC_12_0_[01]_A0/) { mac = substr($0, RSTART + 11, 12) }
		on && mac != "" && match($0, re) {
			v = substr($0, RSTART, RLENGTH); sub(/.*(>=|>|=)[[:space:]]*/, "", v); sub(/[;)?].*/, "", v)
			print key " " mac " " tolower(v); mac = ""
		}
		on && /^}/ { on = 0 }
	' "$1"
}
{
	asicrev "$amd/display/dc/resource/dcn401/dcn401_resource.c" dcn401_calc_num_avail_chans_for_mall \
		'num_available_chans > [0-9]+' mall_channel_limit
	asicrev "$amd/display/dc/resource/dcn401/dcn401_resource.c" dcn401_resource_construct \
		'dcc_plane_width_limit = [0-9]+' dcc_plane_width_limit
	asicrev "$amd/display/dc/clk_mgr/dcn401/dcn401_clk_mgr.c" dcn401_is_ppclk_idle_dpm_enabled \
		'smu_ver >= 0x[0-9a-fA-F]+' idle_dpm_min_smu
	asicrev "$amd/display/dc/clk_mgr/dcn401/dcn401_clk_mgr.c" dcn401_is_df_throttle_opt_enabled \
		'smu_ver >= 0x[0-9a-fA-F]+' df_throttle_min_smu
} > "$work/dc"
while read -r key mac value; do
	echo "$key.$(dal_map "$mac")=$value"
done < "$work/dc" | sort > "$work/dc_mapped"
[ "$(wc -l < "$work/dc_mapped")" -eq 6 ] || fail "DCN401 per-ASIC branches changed shape"

# kfd_device.c gfx_target_version per GC.
awk '
	/case IP_VERSION\(12, 0, [01]\):/ { match($0, /12, 0, [01]/); gc = substr($0, RSTART, RLENGTH); gsub(", ", ".", gc) }
	gc != "" && /gfx_target_version = [0-9]+;/ { match($0, /[0-9]+;/); print "gfx_target_version." gc "=" substr($0, RSTART, RLENGTH - 1); gc = "" }
	/case IP_VERSION\(/ && !/12, 0, [01]/ { gc = "" }
' "$amd/amdkfd/kfd_device.c" | sort -u > "$work/kfd"
[ "$(wc -l < "$work/kfd")" -eq 2 ] || fail "kfd gfx_target_version cases not found"

# amdgpu_ucode.c kicker_device_list.
awk '
	/kicker_device_list\[\] = \{/ { on = 1; next }
	on && /\};/ { on = 0 }
	on && match($0, /0x[0-9a-fA-F]+, *0x[0-9a-fA-F]+/) {
		v = tolower(substr($0, RSTART, RLENGTH)); gsub(/ /, "", v); print "kicker=" v
	}
' "$amd/amdgpu/amdgpu_ucode.c" > "$work/kicker"
[ -s "$work/kicker" ] || fail "kicker_device_list not found"

# One SMU driver interface for both MP1 revisions: amdgpu_smu.c gives
# 14.0.2 and 14.0.3 the same ppt funcs, which set this version.
grep -A2 'case IP_VERSION(14, 0, 2):' "$amd/pm/swsmu/amdgpu_smu.c" | grep -q 'case IP_VERSION(14, 0, 3):' \
	|| fail "MP1 14.0.2/14.0.3 no longer share ppt funcs"
smu_if=$(sed -n 's/^#define SMU14_DRIVER_IF_VERSION_SMU_V14_0_2[[:space:]]*\(0x[0-9a-fA-F]*\).*/\1/p' \
	"$amd/pm/swsmu/smu14/smu_v14_0_2_ppt.c" | tr A-F a-f)
[ -n "$smu_if" ] || fail "SMU14 driver interface version not found"

# gfx_v12_0_init_golden_registers: both GC 12.0.x run golden_settings_gc_12_0,
# and golden_settings_gc_12_0_rev0 when the NBIO strap revision is zero.
grep -A3 'case IP_VERSION(12, 0, 0):' "$amd/amdgpu/gfx_v12_0.c" | grep -A2 'case IP_VERSION(12, 0, 1):' \
	| grep -q 'golden_settings_gc_12_0,' || fail "GC 12.0.0/12.0.1 golden sequences diverged"
offsets=$amd/include/asic_reg/gc/gc_12_0_0_offset.h
for table in golden_settings_gc_12_0 golden_settings_gc_12_0_rev0; do
	awk -v t="$table" '
		index($0, "static const struct soc15_reg_golden " t "[] = {") == 1 { on = 1; next }
		on && /^};/ { on = 0 }
		on && /SOC15_REG_GOLDEN_VALUE\(GC, 0,/ { gsub(/[(),]/, " "); print $4, $5, $6 }
	' "$amd/amdgpu/gfx_v12_0.c" | while read -r reg mask value; do
		off=$(sed -n "s/^#define $reg[[:space:]]*\(0x[0-9a-fA-F]*\)$/\1/p" "$offsets")
		idx=$(sed -n "s/^#define ${reg}_BASE_IDX[[:space:]]*\([0-9]*\)$/\1/p" "$offsets")
		[ -n "$off" ] && [ -n "$idx" ] || fail "$reg not in gc_12_0_0_offset.h"
		printf '%s.%s.%#x=%#x,%#x\n' "${table#golden_settings_}" "$idx" "$off" "$mask" "$value"
	done
done > "$work/golden"
[ "$(wc -l < "$work/golden")" -eq 4 ] || fail "GC12 golden tables changed size"

{
	cat "$work/soc24" "$work/dc_mapped" "$work/kfd" "$work/kicker" "$work/golden"
	echo "smu_driver_if=$smu_if"
} > "$work/policy"

# Every image the RDNA4 IP versions declare.
{
	grep -rh 'MODULE_FIRMWARE' "$amd/amdgpu" "$amd/pm" "$amd/display" | sed -n 's/.*MODULE_FIRMWARE("\([^"]*\)").*/\1/p'
	grep -rh '#define FIRMWARE_VCN5_0_0\b\|#define FIRMWARE_DCN_401_DMUB\b' "$amd/amdgpu" "$amd/display" \
		| sed -n 's/.*"\([^"]*\)".*/\1/p'
} | grep -E '/(gc_12_0_[01]|psp_14_0_[23]|smu_14_0_[23]|sdma_7_0_[01]|vcn_5_0_0|dcn_4_0_1)[_.]' \
	| sort -u > "$work/firmware"

if [ "$generate" = 1 ]; then
	cat "$work/policy"
	echo "----"
	cat "$work/firmware"
	exit 0
fi
diff -u <(grep -v '^#' "$here/policy.txt") "$work/policy" || fail "policy.txt differs from Linux"
diff -u <(grep -v '^#' "$here/firmware.txt") "$work/firmware" || fail "firmware.txt differs from Linux"

cc -Wall -Wextra -Werror '-D__counted_by(x)=' \
	-I"$amd/include" -I"$amd/include/asic_reg" \
	-I"$amd/pm/swsmu/inc/pmfw_if" -I"$amd/pm/swsmu/inc" \
	"$here/layout.c" -o "$work/layout"
"$work/layout"
echo "rdna4_family: policy, firmware and layout match $linux"
