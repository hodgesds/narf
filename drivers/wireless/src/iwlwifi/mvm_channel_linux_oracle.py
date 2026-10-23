#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Emit API77 inactive PHY/link payloads compiled from actual Linux structs."""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
args = parser.parse_args()
linux = args.linux / "drivers/net/wireless/intel/iwlwifi/fw/api"
headers = "\n".join((linux / name).read_text() for name in ["mac.h", "mac-cfg.h", "datapath.h"])
source = """#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#define AC_NUM 4
#define __packed __attribute__((packed))
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;
"""
source += '#include "' + str(linux / "phy-ctxt.h") + '"\n'
for name in ["iwl_ac_qos", "iwl_he_backoff_conf", "iwl_npca_params", "iwl_link_config_cmd", "iwl_rlc_properties", "iwl_sad_properties", "iwl_rlc_config_cmd"]:
    found = re.search(r"struct\s+" + name + r"\s*\{", headers)
    assert found, name
    depth, end = 1, found.end()
    while depth:
        depth += (headers[end] == "{") - (headers[end] == "}")
        end += 1
    suffix = re.match(r"\s*__packed;", headers[end:])
    assert suffix, name
    source += headers[found.start():end + suffix.end()] + "\n"
source += r"""
static void dump(const char *name,const void *data,size_t len) {
    printf("%s %zu ",name,len);
    for(size_t i=0;i<len;i++)printf("%02x",((const unsigned char*)data)[i]);
    puts("");
}
int main(void) {
    for(int extended=0;extended<=1;extended++)
    for(int channel=1;channel<=36;channel+=35)
    for(int chains=1;chains<=3;chains++)
    for(int action=1;action<=3;action+=2) {
        struct iwl_phy_context_cmd_v1 phy={.action=htole32(action)};
        struct iwl_fw_channel_info_v1 old={.channel=channel,.band=(channel<=14)};
        int count=(chains&1)+((chains>>1)&1);
        phy.tail.txchain_info=htole32(chains);
        phy.tail.rxchain_info=htole32((chains<<PHY_RX_CHAIN_VALID_POS) |
            (count<<PHY_RX_CHAIN_CNT_POS) | (count<<PHY_RX_CHAIN_MIMO_CNT_POS));
        char name[64];snprintf(name,sizeof(name),"phy-%d-%d-%d-%d",extended,channel,chains,action);
        if(extended) {
            phy.ci.channel=htole32(channel);phy.ci.band=channel<=14;
            dump(name,&phy,sizeof(phy));
        } else {
            unsigned char bytes[sizeof(phy)-sizeof(phy.ci)+sizeof(old)]={0};
            memcpy(bytes,&phy,offsetof(struct iwl_phy_context_cmd_v1,ci));
            memcpy(bytes+offsetof(struct iwl_phy_context_cmd_v1,ci),&old,sizeof(old));
            memcpy(bytes+offsetof(struct iwl_phy_context_cmd_v1,ci)+sizeof(old),&phy.tail,sizeof(phy.tail));
            dump(name,bytes,sizeof(bytes));
        }
    }
    for(int chains=1;chains<=3;chains++) {
        struct iwl_rlc_config_cmd rlc={0};
        int count=(chains&1)+((chains>>1)&1);
        rlc.rlc.rx_chain_info=htole32((chains<<PHY_RX_CHAIN_VALID_POS) |
            (count<<PHY_RX_CHAIN_CNT_POS) | (count<<PHY_RX_CHAIN_MIMO_CNT_POS));
        char name[32];snprintf(name,sizeof(name),"rlc-%d",chains);
        dump(name,&rlc,sizeof(rlc));
    }
    struct iwl_link_config_cmd link={.action=htole32(2)};
    for(int i=0;i<6;i++)link.local_link_addr[i]=2;
    dump("bind",&link,sizeof(link));
    link.phy_id=htole32(0xffffffff);
    dump("unbind",&link,sizeof(link));
}
"""
with tempfile.TemporaryDirectory(prefix="narf-mvm-channel-linux-") as directory:
    path = Path(directory)
    (path / "oracle.c").write_text(source)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(path / "oracle.c"), "-o", str(path / "oracle")], check=True)
    subprocess.run([str(path / "oracle")], check=True)
