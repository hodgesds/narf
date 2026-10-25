#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile API77 native queue layouts from original Linux definitions.

Uses datapath.h's v3 operation/union, txq.h's allocation response and the
management TID definition from iwl-trans.h. No NARF encoder is consulted.
Linux mvm/ops.c selects queue command3; mvm/sta.c maps management TID15 and
removes that station/TID before transport retirement.
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
headers = "\n".join((root / "fw/api" / name).read_text()
                    for name in ["datapath.h", "txq.h"])
source = """#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#define __packed __attribute__((packed))
typedef uint8_t u8;typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t __le64;
"""
tid = re.search(r"^#define IWL_MGMT_TID\s+\d+", (root / "iwl-trans.h").read_text(), re.M)
assert tid
source += tid[0] + "\n"
for kind, name in [("enum", "iwl_scd_queue_cfg_operation"),
                   ("struct", "iwl_scd_queue_cfg_cmd"),
                   ("struct", "iwl_tx_queue_cfg_rsp")]:
    found = re.search(kind + r"\s+" + name + r"\s*\{", headers)
    assert found, name
    depth, end = 1, found.end()
    while depth:
        depth += (headers[end] == "{") - (headers[end] == "}")
        end += 1
    suffix = re.match(r"\s*" + ("__packed" if kind == "struct" else "") + ";", headers[end:])
    assert suffix, name
    source += headers[found.start():end + suffix.end()] + "\n"
source += r"""
static void dump(const char *name,const void *data,size_t len) {
    printf("%s %zu ",name,len);
    for(size_t i=0;i<len;i++)printf("%02x",((const unsigned char*)data)[i]);
    puts("");
}
int main(void) {
    struct iwl_scd_queue_cfg_cmd add = {
        .operation = htole32(IWL_SCD_QUEUE_ADD),
        .u.add = {
            .sta_mask = htole32(1), .tid = IWL_MGMT_TID,
            .cb_size = htole32(4), /* log2(128)-3 */
            .bc_dram_addr = htole64(0x1122334455667000ULL),
            .tfdq_dram_addr = htole64(0x8877665544332000ULL),
        },
    };
    struct iwl_scd_queue_cfg_cmd remove;
    /* The full union is transmitted, including the inactive ADD tail. */
    memset(&remove,0,sizeof(remove));
    remove.operation=htole32(IWL_SCD_QUEUE_REMOVE);
    remove.u.remove.sta_mask=htole32(1);
    remove.u.remove.tid=htole32(IWL_MGMT_TID);
    struct iwl_tx_queue_cfg_rsp response = {
        .queue_number = htole16(23), .write_pointer = htole16(0x45),
    };
    struct iwl_tx_queue_cfg_rsp removed = {.queue_number = htole16(23)};
    _Static_assert(sizeof(add)==36,"native v3 queue body changed");
    _Static_assert(sizeof(response)==8,"native allocation response changed");
    dump("add",&add,sizeof(add));
    dump("remove",&remove,sizeof(remove));
    dump("response",&response,sizeof(response));
    dump("remove-response",&removed,sizeof(removed));
    removed.flags=htole16(1);
    dump("failed-remove-response",&removed,sizeof(removed));
    printf("offsets %zu %zu %zu %zu %zu %zu\n",
        offsetof(struct iwl_scd_queue_cfg_cmd,u.add.sta_mask),
        offsetof(struct iwl_scd_queue_cfg_cmd,u.add.tid),
        offsetof(struct iwl_scd_queue_cfg_cmd,u.add.flags),
        offsetof(struct iwl_scd_queue_cfg_cmd,u.add.cb_size),
        offsetof(struct iwl_scd_queue_cfg_cmd,u.add.bc_dram_addr),
        offsetof(struct iwl_scd_queue_cfg_cmd,u.add.tfdq_dram_addr));
    printf("response-offsets %zu %zu %zu %zu\n",
        offsetof(struct iwl_tx_queue_cfg_rsp,queue_number),
        offsetof(struct iwl_tx_queue_cfg_rsp,flags),
        offsetof(struct iwl_tx_queue_cfg_rsp,write_pointer),
        offsetof(struct iwl_tx_queue_cfg_rsp,reserved));
}
"""
with tempfile.TemporaryDirectory(prefix="narf-mvm-queue-linux-") as directory:
    path = Path(directory)
    (path / "oracle.c").write_text(source)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    str(path / "oracle.c"), "-o", str(path / "oracle")], check=True)
    subprocess.run([str(path / "oracle")], check=True)
