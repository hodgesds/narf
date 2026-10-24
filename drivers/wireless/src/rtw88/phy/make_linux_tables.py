"""Select RTL8822C tables with the original Linux conditional-table parser.

Keep only the supported PCIe package profile (Linux pkg0 -> condition15).
All seven silicon cuts and RFE0..6 are evaluated; identical resulting tables
are interned. Selection is performed by compiled original C, never a second
Python implementation of the conditions. No board calibration is generated.
"""
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88')
HERE = Path(__file__).parent


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


phy, main = (BASE / 'phy.c').read_text(), (BASE / 'main.h').read_text()
tables = (BASE / 'rtw8822c_table.c').read_text()
names = ['bb', 'agc', 'array_mp_cal_init', 'rf_b', 'rf_a']
body = '\n'.join(block(main, 'struct ' + n + ' {') + ';' for n in ['rtw_phy_cond', 'rtw_phy_cond2'])
body += '\n' + block(phy, 'struct phy_cfg_pair {') + ';\n' + block(phy, 'union phy_table_tile {') + ';\n'
rf_helpers = '\n'.join(block(phy, marker) for marker in [
    'u32 rtw_phy_read_rf(', 'bool rtw_phy_write_rf_reg_sipi(',
    'bool rtw_phy_write_rf_reg(', 'bool rtw_phy_write_rf_reg_mix('])
callbacks = '\n'.join(block(phy, marker) for marker in [
    'void rtw_phy_cfg_agc(', 'void rtw_phy_cfg_bb(', 'void rtw_phy_cfg_rf('])
for name in names:
    body += block(tables, 'static const u32 rtw8822c_' + name + '[] = {') + ';\n'
for marker in ['void rtw_phy_setup_phy_cond(', 'static bool check_positive(', 'void rtw_parse_tbl_phy_cond(']:
    body += block(phy, marker) + '\n'
pre = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define __packed __attribute__((packed))
#define __LITTLE_ENDIAN 1
#define BUILD_BUG_ON(x) _Static_assert(!(x), "Linux table layout")
#define EXPORT_SYMBOL(...)
#define rtw_dbg(...)
#define RTW_HCI_TYPE_PCIE 0
#define RTW_HCI_TYPE_USB 1
#define RTW_HCI_TYPE_SDIO 2
#define RTW_CHIP_TYPE_8812A 1
#define RTW_CHIP_TYPE_8821A 2
#define RFREG_MASK 0x000fffff
#define INV_RF_DATA 0xffffffff
#define rtw_err(...)
#define lockdep_assert_held(...)
#define __ffs(v) __builtin_ctz(v)
'''
# The actual condition types must precede the structures that embed them.
condition_end = body.index('struct phy_cfg_pair')
conditions, body = body[:condition_end], body[condition_end:]
pre += conditions + r'''
struct rtw_dev;struct rtw_table;
enum rtw_rf_path{RF_PATH_A,RF_PATH_B,RF_PATH_C,RF_PATH_D};
struct rf_ops{u32(*read_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32);};
struct rtw_chip_info{u32 id,rf_base_addr[2],rf_sipi_addr[2];const struct rf_ops*ops;};
struct rtw_hal{u8 cut_version,rf_phy_num;struct rtw_phy_cond phy_cond;struct rtw_phy_cond2 phy_cond2;};
struct rtw_efuse{u8 rfe_option,ext_lna_2g,ext_pa_2g,ext_lna_5g,ext_pa_5g,btcoex,alna_type,glna_type,apa_type,gpa_type;};
struct rtw_dev{const struct rtw_chip_info*chip;struct rtw_hal hal;struct rtw_efuse efuse;};
struct rtw_table{const void*data;u32 size;void(*do_cfg)(struct rtw_dev*,const struct rtw_table*,u32,u32);enum rtw_rf_path rf_path;};
static int rtw_hci_type(struct rtw_dev*d){return RTW_HCI_TYPE_PCIE;}
static void output(struct rtw_dev*d,const struct rtw_table*t,u32 a,u32 b){printf("%u %u\n",a,b);}
static u8 regs[0x5000];static uint64_t hash;
static void record(u8 kind,u32 reg,u32 value){hash^=kind;hash*=1099511628211ULL;for(int i=0;i<4;i++){hash^=(reg>>(i*8))&255;hash*=1099511628211ULL;}for(int i=0;i<4;i++){hash^=(value>>(i*8))&255;hash*=1099511628211ULL;}}
static u32 rtw_read32(struct rtw_dev*d,u32 reg){u32 v;record(0,reg,0);memcpy(&v,regs+reg,4);return v;}
static void rtw_write32(struct rtw_dev*d,u32 reg,u32 value){record(1,reg,value);memcpy(regs+reg,&value,4);}
static u32 rtw_read32_mask(struct rtw_dev*d,u32 reg,u32 mask){return (rtw_read32(d,reg)&mask)>>__ffs(mask);}
static void rtw_write32_mask(struct rtw_dev*d,u32 reg,u32 mask,u32 value){u32 old=rtw_read32(d,reg);rtw_write32(d,reg,(old&~mask)|((value<<__ffs(mask))&mask));}
static void udelay(u32 us){record(2,0,us);}static void msleep(u32 ms){udelay(ms*1000);}static void mdelay(u32 ms){udelay(ms*1000);}static void usleep_range(u32 lo,u32 hi){udelay(lo);}
'''
body += '\n' + rf_helpers
body += '\nstatic void rtw_write_rf(struct rtw_dev*d,enum rtw_rf_path path,u32 addr,u32 mask,u32 value){rtw_phy_write_rf_reg_mix(d,path,addr,mask,value);}\n'
body += '\n' + callbacks
post = r'''
int main(){const struct rf_ops ops={rtw_phy_read_rf};const struct rtw_chip_info chip={.id=3,.rf_base_addr={0x3c00,0x4c00},.rf_sipi_addr={0x1808,0x4108},.ops=&ops};for(int cut=0;cut<7;cut++){for(int rfe=0;rfe<7;rfe++){
struct rtw_dev d={.chip=&chip,.hal={.cut_version=cut,.rf_phy_num=2},.efuse={.rfe_option=rfe}};rtw_phy_setup_phy_cond(&d,0);
'''
for index, name in enumerate(names):
    cfg = ['rtw_phy_cfg_bb','rtw_phy_cfg_agc','rtw_phy_cfg_bb','rtw_phy_cfg_rf','rtw_phy_cfg_rf'][index]
    path = 1 if index == 3 else 0
    post += f'printf("TABLE %d %d {index}\\n",cut,rfe);struct rtw_table t{index}={{rtw8822c_{name},sizeof(rtw8822c_{name})/4,output,{path}}};rtw_parse_tbl_phy_cond(&d,&t{index});printf("END\\n");\n'
    post += f'for(int i=0;i<sizeof(regs);i++)regs[i]=(u8)(i*17+7);hash=14695981039346656037ULL;t{index}.do_cfg={cfg};rtw_parse_tbl_phy_cond(&d,&t{index});printf("HASH %d %d {index} %llu\\n",cut,rfe,(unsigned long long)hash);\n'
post += '}}return 0;}\n'
with tempfile.TemporaryDirectory() as temp:
    source, exe = Path(temp) / 'tables.c', Path(temp) / 'tables'
    source.write_text(pre + body + post)
    subprocess.run(['cc', '-O2', '-o', str(exe), str(source)], check=True)
    output = subprocess.check_output([str(exe)]).decode()
pool, selection = {}, {}
for cut, rfe, kind, rows in re.findall(r'TABLE (\d+) (\d+) (\d+)\n(.*?)END\n', output, re.S):
    rows = tuple(tuple(map(int, row.split())) for row in rows.splitlines())
    if any(address > 65535 for address, _ in rows):
        raise ValueError('selected table address exceeds native RTL8822C profile')
    index = pool.setdefault(rows, len(pool))
    selection[(int(cut), int(rfe), int(kind))] = index
source = '// SPDX-License-Identifier: GPL-2.0-or-later\n// Selected by original Linux phy.c parser from rtw8822c_table.c; regenerate with make_linux_tables.py.\n'
for rows, index in pool.items():
    source += f'const TABLE_{index}: &[(u16,u32)] = &[\n'
    source += ''.join(f'(0x{a:x},0x{v:x}),\n' for a, v in rows) + '];\n'
source += 'pub(super) fn select(cut:u8,rfe:u8,kind:usize)->Option<&\'static[(u16,u32)]>{\n'
source += 'if cut>6 || rfe>6 || kind>4{return None;}\n'
source += 'const PROFILES:[[[u8;5];7];7]=[\n'
for cut in range(7):
    source += '[' + ','.join('[' + ','.join(str(selection[(cut,rfe,kind)]) for kind in range(5)) + ']' for rfe in range(7)) + '],\n'
source += '];\nmatch PROFILES[cut as usize][rfe as usize][kind]{\n'
source += ''.join(f'{index}=>Some(TABLE_{index}),\n' for index in pool.values())
source += '_=>None,}}\n'
target = HERE / 'tables.rs'
target.write_text(source)
subprocess.run(['rustfmt', '--edition', '2021', str(target)], check=True)
hashes = {(int(c),int(r),int(k)):int(v) for c,r,k,v in re.findall(r'HASH (\d+) (\d+) (\d+) (\d+)',output)}
golden = '// Original Linux conditional parser, BB/AGC/RF callbacks and direct/SIPI RF accessors.\nconst LINUX_PHY_HASHES: [[[u64;5];7];7] = [\n'
for cut in range(7):
    golden += '[' + ','.join('[' + ','.join(hex(hashes[(cut,rfe,kind)]) for kind in range(5)) + ']' for rfe in range(7)) + '],\n'
golden += '];\n'
(HERE/'golden.rs').write_text(golden)
subprocess.run(['rustfmt','--edition','2021',str(HERE/'golden.rs')],check=True)
print(f'{len(pool)} unique tables, {sum(map(len,pool))} selected operations, 49 exact cut/RFE profiles')
