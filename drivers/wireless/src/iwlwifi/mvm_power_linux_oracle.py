#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile actual Linux API77 v5 power layouts, independent of NARF encoders.

mvm/fw.c::iwl_mvm_sar_select_profile and mvm/mac80211.c::iwl_mvm_set_tx_power
select v5 when API change45 is present, adding common and pre-v9 per_band.
The values below are explicit test fixtures, not platform calibration data.
"""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
args = parser.parse_args()
root = args.linux / "drivers/net/wireless/intel/iwlwifi"
header = (root / "fw/api/power.h").read_text()
source = """#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <endian.h>
#define __packed __attribute__((packed))
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;
"""
for macro in ["IWL_NUM_CHAIN_TABLES", "IWL_NUM_CHAIN_TABLES_V2", "IWL_NUM_CHAIN_LIMITS",
              "IWL_NUM_SUB_BANDS_V1", "IWL_NUM_SUB_BANDS_V2"]:
    found = re.search(r"^#define " + macro + r"\s+\d+", header, re.M)
    assert found, macro
    source += found[0] + "\n"
for kind, name in [("enum", "iwl_dev_tx_power_cmd_mode"),
                   ("struct", "iwl_dev_tx_power_common"),
                   ("struct", "iwl_dev_tx_power_cmd_v3"),
                   ("struct", "iwl_dev_tx_power_cmd_v4"),
                   ("struct", "iwl_dev_tx_power_cmd_v5"),
                   ("struct", "iwl_dev_tx_power_cmd_v8"),
                   ("struct", "iwl_dev_tx_power_cmd_per_band"),
                   ("struct", "iwl_dev_tx_power_cmd_v3_v8")]:
    found = re.search(kind + r"\s+" + name + r"\s*\{", header)
    assert found, name
    depth, end = 1, found.end()
    while depth:
        depth += (header[end] == "{") - (header[end] == "}")
        end += 1
    suffix = re.match(r"\s*(?:__packed)?;", header[end:])
    assert suffix, name
    source += header[found.start():end + suffix.end()] + "\n"
source += r"""
static void dump(const char *name,const void *data,size_t len) {
    printf("%s %zu ",name,len);
    for(size_t i=0;i<len;i++)printf("%02x",((const unsigned char*)data)[i]);
    puts("");
}
int main(void) {
    struct iwl_dev_tx_power_cmd_v3_v8 chains = {
        .common.set_mode=htole32(IWL_TX_POWER_MODE_SET_CHAINS),
    };
    const u8 limits[2][5]={{80,81,82,83,84},{72,73,74,75,76}};
    for(size_t chain=0;chain<2;chain++)
        for(size_t band=0;band<5;band++)
            chains.v5.per_chain[0][chain][band]=htole16(limits[chain][band]);
    size_t len=sizeof(chains.common)+sizeof(chains.per_band)+sizeof(chains.v5);
    _Static_assert(sizeof(chains.common)==10,"common extent changed");
    _Static_assert(sizeof(chains.per_band)==6,"legacy band prefix changed");
    _Static_assert(sizeof(chains.v5)==28,"native v5 extent changed");
    _Static_assert(offsetof(struct iwl_dev_tx_power_cmd_v3_v8,v5)==16,"v5 moved");
    dump("chains",&chains,len);
    struct iwl_dev_tx_power_cmd_v3_v8 link = {
        .common.set_mode=htole32(IWL_TX_POWER_MODE_SET_LINK),
        .common.link_id=htole32(0), /* pre-v9 MAC0, not a Gen3 link ID */
        .common.pwr_restriction=htole16(64),
    };
    dump("link-8dBm",&link,len);
    link.common.pwr_restriction=htole16((uint16_t)(int16_t)-16);
    dump("link-minus2dBm",&link,len);
    printf("offsets %zu %zu %zu %zu %zu %zu\n",
        offsetof(struct iwl_dev_tx_power_cmd_v3_v8,common.link_id),
        offsetof(struct iwl_dev_tx_power_cmd_v3_v8,common.pwr_restriction),
        offsetof(struct iwl_dev_tx_power_cmd_v3_v8,v5.per_chain),
        offsetof(struct iwl_dev_tx_power_cmd_v3_v8,v5.enable_ack_reduction),
        offsetof(struct iwl_dev_tx_power_cmd_v3_v8,v5.per_chain_restriction_changed),
        offsetof(struct iwl_dev_tx_power_cmd_v3_v8,v5.timer_period));
}
"""
with tempfile.TemporaryDirectory(prefix="narf-mvm-power-linux-") as directory:
    path = Path(directory)
    (path / "oracle.c").write_text(source)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    str(path / "oracle.c"), "-o", str(path / "oracle")], check=True)
    subprocess.run([str(path / "oracle")], check=True)
