#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile the retained disabled API77 peer fields against real Linux headers.

The struct is copied only by name and balanced C definition from fw/api/sta.h;
constants are the actual enum from that header. This script does not consult
NARF's encoders. Linux sta.c::iwl_mvm_add_sta_cmd_size selects this struct for
new RX API, including ADD_STA v12's LMAC interpretation of mac_id_n_color.
"""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
args = parser.parse_args()
header = (args.linux / "drivers/net/wireless/intel/iwlwifi/fw/api/sta.h").read_text()
source = """#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#define BIT(n) (1U << (n))
#define ETH_ALEN 6
#define __packed __attribute__((packed))
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;
"""
for kind, name in [("enum", "iwl_sta_flags"), ("struct", "iwl_mvm_add_sta_cmd"),
                   ("struct", "iwl_mvm_rm_sta_cmd")]:
    found = re.search(kind + r"\s+" + name + r"\s*\{", header)
    assert found, name
    depth, end = 1, found.end()
    while depth:
        depth += (header[end] == "{") - (header[end] == "}")
        end += 1
    suffix = re.match(r"\s*" + ("__packed" if kind == "struct" else "") + ";", header[end:])
    assert suffix, name
    source += header[found.start():end + suffix.end()] + "\n"
source += r"""
static void dump(const char *name,const void *data,size_t len) {
    printf("%s %zu ",name,len);
    for(size_t i=0;i<len;i++)printf("%02x",((const unsigned char*)data)[i]);
    puts("");
}
int main(void) {
    struct iwl_mvm_add_sta_cmd add = {
        .tid_disable_tx = htole16(0xffff),
        .addr = {2,4,6,8,10,12},
        .station_flags = htole32(STA_FLG_DISABLE_TX),
        .station_flags_msk = htole32(STA_FLG_DISABLE_TX | STA_FLG_RTS_MIMO_PROT |
            STA_FLG_FAT_EN_MSK | STA_FLG_MIMO_EN_MSK),
    };
    struct iwl_mvm_rm_sta_cmd remove = {0};
    _Static_assert(sizeof(add)==48,"ADD_STA v12 new-RX body changed");
    _Static_assert(sizeof(remove)==4,"REMOVE_STA v2 body changed");
    dump("add",&add,sizeof(add));
    dump("remove",&remove,sizeof(remove));
    printf("offsets %zu %zu %zu %zu\n",offsetof(struct iwl_mvm_add_sta_cmd,addr),
        offsetof(struct iwl_mvm_add_sta_cmd,sta_id),
        offsetof(struct iwl_mvm_add_sta_cmd,station_flags),
        offsetof(struct iwl_mvm_add_sta_cmd,station_flags_msk));
}
"""
with tempfile.TemporaryDirectory(prefix="narf-mvm-peer-linux-") as directory:
    path = Path(directory)
    (path / "oracle.c").write_text(source)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    str(path / "oracle.c"), "-o", str(path / "oracle")], check=True)
    subprocess.run([str(path / "oracle")], check=True)
