#!/usr/bin/env python3
"""Extract Linux AX DMA-stop/index/BDRAM helpers into an inert C trace oracle.

Only internal partition writes from reset_trx_rings are replayed: no original
Linux ring sizes or system DMA bases are asserted to have been provisioned.
The original helper/table text is hashed. Nothing reads NARF's Rust constants.
"""
from pathlib import Path
import argparse
import hashlib
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
root = args.linux / "drivers/net/wireless/realtek/rtw89"
source = (root / "pci.c").read_text()


def block(text, marker, prefix=""):
    start = text.index(marker)
    if prefix:
        start = text.rfind(prefix, 0, start)
    opening = text.index("{", start)
    cursor, depth = opening + 1, 1
    while depth:
        depth += (text[cursor] == "{") - (text[cursor] == "}")
        cursor += 1
    return text[start:cursor]


names = ["rtw89_pci_ctrl_dma_trx", "rtw89_pci_ctrl_dma_io", "rtw89_pci_ctrl_dma_all",
         "rtw89_pci_poll_txdma_ch_idle_ax", "rtw89_pci_poll_rxdma_ch_idle_ax",
         "rtw89_pci_poll_dma_all_idle", "rtw89_pci_clr_idx_all_ax",
         "rtw89_pci_init_wp_16sel", "rtw89_pci_rst_bdram_ax", "rtw89_pci_ctrl_txdma_ch_ax"]
helpers = "\n".join(block(source, name + "(", "\nstatic ") if name != "rtw89_pci_ctrl_dma_all"
                    else block(source, "void " + name + "(") for name in names)
tables = "\n".join(block(source, "const struct rtw89_pci_bd_ram " + name) + ";"
                   for name in ["rtw89_bd_ram_table_dual", "rtw89_bd_ram_table_single"])
partition = block(source, "if (addr_bdram && bd_ram)")
channel_enum = block((root / "txrx.h").read_text(), "enum rtw89_tx_channel") + ";"
fields = ["init_cfg_reg", "rxhci_en_bit", "txhci_en_bit", "dma_io_stop", "dma_stop1",
          "dma_stop2", "dma_busy1", "dma_busy2_reg", "dma_busy3_reg", "rxbd_rwptr_clr_reg",
          "txbd_rwptr_clr2_reg", "wp_sel_addr", "tx_dma_ch_mask", "bd_ram_table"]
profiles = []
for model in ["8852a", "8852b", "8852c", "8851b"]:
    text = (root / ("rtw" + model + "e.c")).read_text()
    entries = []
    for field in fields:
        value = re.search(r"\." + field + r"\s*=\s*(.*?),\n", text, re.S).group(1)
        entries.append("." + field + "=" + value)
    # The AX address sets use symbolic R_AX_<channel>_BDRAM_CTRL[_V1].
    # Pull their channel/member identities from the original Linux initializer.
    table_name = "rtw89_pci_ch_dma_addr_set" + ("_v1" if model == "8852c" else "")
    address_set = block(source, "const struct rtw89_pci_ch_dma_addr_set " + table_name + " =")
    addresses = []
    for channel, suffix in re.findall(r"DEF_TXCHADDRS(?:_TYPE1)?\(info, (\w+)(?:, (\w+))?\)", address_set):
        addresses.append(f"[RTW89_TXCH_{channel}]=R_AX_{channel}_BDRAM_CTRL{suffix}")
    profiles.append("static const struct rtw89_pci_info p" + model + "={" + ",".join(entries)
                    + ",.bdram={" + ",".join(addresses) + "}};")

# Preserve header macro continuation lines and resolve only referenced macros.
definitions = {}
for name in ["pci.h", "reg.h"]:
    lines = iter((root / name).read_text().splitlines())
    for line in lines:
        match = re.match(r"#define\s+(\w+)\s+", line)
        if not match:
            continue
        body = [line]
        while body[-1].endswith("\\"):
            body.append(next(lines))
        definitions[match.group(1)] = "\n".join(body)
needed = set(re.findall(r"\b(?:[RB]_AX_|DMA_BUSY|BDRAM_|RTW89_PCI_POLL_)[A-Z0-9_]+\b",
                        helpers + tables + partition + "\n".join(profiles)))
needed.update(["R_AX_PCIE_DMA_STOP1", "B_AX_STOP_WPDMA", "R_AX_PCIE_INIT_CFG1"])
while True:
    more = set()
    for name in needed:
        more.update(token for token in re.findall(r"\b[A-Z][A-Z0-9_]+\b", definitions.get(name, ""))
                    if token in definitions)
    if more <= needed:
        break
    needed |= more
defs = "\n".join(definitions[name] for name in sorted(needed))
pre = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define MASKBYTE0 0xffU
#define MASKBYTE1 0xff00U
#define MASKBYTE2 0xff0000U
#define MASKBYTE3 0xff000000U
#define FIELD_PREP(mask,val) (((u32)(val)<<__builtin_ctz(mask))&(mask))
#define u32_encode_bits(val,mask) FIELD_PREP(mask,val)
#define rtw89_err(...) ((void)0)
#define read_poll_timeout(op,v,condition,interval,budget,delay,...) ({v=op(__VA_ARGS__);(condition)?0:-110;})
#define read_poll_timeout_atomic read_poll_timeout
enum rtw89_core_chip_id {RTL8852A,RTL8852B,RTL8852C,RTL8851B};
struct rtw89_reg_def {u32 addr,mask;};
struct rtw89_pci_bd_ram {u32 start_idx,max_num,min_num;};
'''
types = r'''
struct rtw89_pci_info {
 u32 init_cfg_reg,rxhci_en_bit,txhci_en_bit;
 struct rtw89_reg_def dma_io_stop,dma_stop1,dma_stop2,dma_busy1;
 u32 dma_busy2_reg,dma_busy3_reg,rxbd_rwptr_clr_reg,txbd_rwptr_clr2_reg;
 u32 wp_sel_addr,tx_dma_ch_mask,bdram[RTW89_TXCH_NUM];
 const struct rtw89_pci_bd_ram (*bd_ram_table)[RTW89_TXCH_NUM];
};
struct chip {enum rtw89_core_chip_id chip_id;};
struct rtw89_dev {const struct rtw89_pci_info *pci_info;struct chip *chip;};
static u32 mem[16384];
static u32 rtw89_read32(struct rtw89_dev*d,u32 a) {
 if(a==0x1000)mem[a/4]&=~8;
 return mem[a/4];
}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v) {
 printf("(0x%x,0x%x),",a,v);mem[a/4]=v;
}
static void rtw89_write32_set(struct rtw89_dev*d,u32 a,u32 mask) {rtw89_write32(d,a,rtw89_read32(d,a)|mask);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 mask) {rtw89_write32(d,a,rtw89_read32(d,a)&~mask);}
'''
partition_wrapper = r'''
static void internal_partitions(struct rtw89_dev *rtwdev) {
 const struct rtw89_pci_info *info=rtwdev->pci_info;
 const struct rtw89_pci_bd_ram *table=*info->bd_ram_table;
 for(int i=0;i<RTW89_TXCH_NUM;i++) {
  if(info->tx_dma_ch_mask&BIT(i))continue;
  const struct rtw89_pci_bd_ram *bd_ram=&table[i];
  u32 addr_bdram=info->bdram[i],val32;
''' + partition + "\n }\n}\n"
main = r'''
int main(void) {
 const struct rtw89_pci_info *profiles[]={&p8852a,&p8852b,&p8852c,&p8851b};
 const char *names[]={"Rtl8852A","Rtl8852B","Rtl8852C","Rtl8851B"};
 for(int n=0;n<4;n++)for(int seed=0;seed<2;seed++) {
  const struct rtw89_pci_info *p=profiles[n];struct chip chip={n};struct rtw89_dev dev={p,&chip};
  memset(mem,seed?0xa5:0,sizeof(mem));
  mem[p->dma_busy1.addr/4]=0;mem[p->dma_busy3_reg/4]=0;
  if(p->dma_busy2_reg)mem[p->dma_busy2_reg/4]=0;
  printf("Case{chip:ChipId::%s,seed:%d,trace:&[",names[n],seed?0xa5:0);
  rtw89_write32_set(&dev,p->dma_stop1.addr,B_AX_STOP_WPDMA);
  rtw89_pci_ctrl_dma_all(&dev,false);
  if(rtw89_pci_poll_dma_all_idle(&dev))return 2;
  rtw89_pci_clr_idx_all_ax(&dev);
  internal_partitions(&dev);rtw89_pci_init_wp_16sel(&dev);
  if(rtw89_pci_rst_bdram_ax(&dev))return 3;
  rtw89_pci_ctrl_txdma_ch_ax(&dev,false);
  printf("]},\n");
 }
 return 0;
}
'''
original = helpers + tables + partition + channel_enum + "\n".join(profiles) + defs
with tempfile.TemporaryDirectory() as td:
    path = Path(td)
    (path / "oracle.c").write_text("\n".join([pre, channel_enum, types, defs, tables,
                                              helpers, "\n".join(profiles), partition_wrapper, main]))
    subprocess.run(["cc", "-O2", "-o", str(path / "oracle"), str(path / "oracle.c")], check=True)
    traces = subprocess.check_output([str(path / "oracle")]).decode()
output = ("// Extracted Linux AX BDRAM helper/table/config SHA256 "
          + hashlib.sha256(original.encode()).hexdigest() + "\n#[rustfmt::skip]\nconst CASES: &[Case] = &[\n"
          + traces + "];\n")
destination = Path(__file__).with_name("golden.rs")
if args.check:
    assert destination.read_text() == output, "stale Linux BDRAM golden"
else:
    destination.write_text(output)
print("Linux AX BDRAM oracle: eight profile/seed traces verified" if args.check else "Linux AX BDRAM oracle generated")
