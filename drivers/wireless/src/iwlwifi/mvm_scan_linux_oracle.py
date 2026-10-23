#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Reproduce native API77 scan fixtures from the actual local Linux headers.

No NARF builder is imported. Temporary C files stay outside the repository.
Usage: python3 mvm_scan_linux_oracle.py [--linux /usr/src/linux]
"""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
args = parser.parse_args()
linux = args.linux / "drivers/net/wireless/intel/iwlwifi/fw/api"
headers = "\n".join((linux / name).read_text() for name in
                    ["mac.h", "mac-cfg.h", "nvm-reg.h", "sf.h", "power.h", "scan.h"])
names = ["iwl_ac_qos", "iwl_he_backoff_conf", "iwl_npca_params",
         "iwl_mac_client_data", "iwl_mac_p2p_dev_data",
         "iwl_mac_wifi_gen_support_v2", "iwl_mac_wifi_gen_support",
         "iwl_mac_config_cmd_v3", "iwl_link_config_cmd", "iwl_sf_cfg_cmd",
         "iwl_beacon_filter_cmd", "iwl_mac_power_cmd_v2",
         "iwl_mcc_update_cmd", "iwl_mcc_update_resp_v3", "iwl_mcc_update_resp_v4",
         "iwl_mcc_update_resp_v8", "iwl_scan_channel_cfg_umac"]
source = """#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <endian.h>
#define AC_NUM 4
#define SF_TRANSIENT_STATES_NUMBER 2
#define SF_NUM_SCENARIO 5
#define SF_NUM_TIMEOUT_TYPES 2
#define __packed __attribute__((packed))
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;
"""
for name in names:
    found = re.search(r"struct\s+" + name + r"\s*\{", headers)
    assert found, name
    depth = 1
    end = found.end()
    while depth:
        depth += (headers[end] == "{") - (headers[end] == "}")
        end += 1
    suffix = re.match(r"\s*__packed;", headers[end:])
    assert suffix, name
    source += headers[found.start():end + suffix.end()] + "\n"
source += r"""
static void dump(const char *name, const void *data, size_t len) {
    printf("%s %zu ", name, len);
    for(size_t i=0;i<len;i++)printf("%02x",((const unsigned char*)data)[i]);
    puts("");
}
int main(void) {
    struct iwl_mac_config_cmd_v3 mac={0};
    mac.action=htole32(1);mac.mac_type=htole32(5);mac.filter_flags=htole32(12);
    for(int i=0;i<6;i++)mac.local_mld_addr[i]=2;
    dump("mac",&mac,sizeof(mac));
    struct iwl_link_config_cmd link={0};
    link.action=htole32(1);link.phy_id=htole32(0xffffffff);
    for(int i=0;i<6;i++)link.local_link_addr[i]=2;
    dump("link",&link,sizeof(link));
    struct iwl_sf_cfg_cmd sf={0};
    sf.state=htole32(3);sf.watermark[0]=htole32(4096);sf.watermark[1]=htole32(8192);
    for(int i=0;i<5;i++){
        for(int j=0;j<2;j++)sf.long_delay_timeouts[i][j]=htole32(1000000);
        sf.full_on_timeouts[i][0]=htole32(400);sf.full_on_timeouts[i][1]=htole32(160);
    }
    dump("sf",&sf,sizeof(sf));
    struct iwl_beacon_filter_cmd bf={0};dump("bf",&bf,sizeof(bf));
    struct iwl_mac_power_cmd_v2 power={0};power.keep_alive_seconds=htole16(25);
    dump("power",&power,sizeof(power));
    struct iwl_mcc_update_cmd q={.mcc=htole16(0x5a5a),.source_id=0x10};
    dump("query",&q,sizeof(q));
    printf("mcc3 %zu %zu\nmcc4 %zu %zu\nmcc8 %zu %zu\n",
        sizeof(struct iwl_mcc_update_resp_v3),offsetof(struct iwl_mcc_update_resp_v3,n_channels),
        sizeof(struct iwl_mcc_update_resp_v4),offsetof(struct iwl_mcc_update_resp_v4,n_channels),
        sizeof(struct iwl_mcc_update_resp_v8),offsetof(struct iwl_mcc_update_resp_v8,n_channels));
    for(int version=15;version<=17;version+=2){
        struct iwl_scan_channel_cfg_umac c={0};c.channel_num=1;
        c.v2.iter_count=1;
        if(version<17)c.v2.band=1;
        else {c.flags=htole32(1u<<30);c.v5.psd_20=127;}
        dump(version==15?"channel15":"channel17",&c,sizeof(c));
    }
}
"""
with tempfile.TemporaryDirectory(prefix="narf-mvm-scan-oracle-") as directory:
    build = Path(directory)
    c_file = build / "oracle.c"
    binary = build / "oracle"
    c_file.write_text(source)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(c_file),
                    "-o", str(binary)], check=True)
    print(subprocess.check_output([str(binary)], text=True), end="")
