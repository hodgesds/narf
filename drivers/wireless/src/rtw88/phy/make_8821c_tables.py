"""Select RTL8821C tables with the original Linux conditional-table parser.

Evaluate both source package profiles (pkg0 -> condition15, pkg1 ->1),
seven silicon cuts, and the original valid RFE definitions0/2/4/6; identical resulting tables
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
tables = (BASE / 'rtw8821c_table.c').read_text()
names = ['mac', 'bb', 'agc', 'agc_btg_type2', 'rf_a']
body = '\n'.join(block(main, 'struct ' + n + ' {') + ';' for n in ['rtw_phy_cond', 'rtw_phy_cond2'])
body += '\n' + block(phy, 'struct phy_cfg_pair {') + ';\n' + block(phy, 'union phy_table_tile {') + ';\n'
rf_helpers = '\n'.join(block(phy, marker) for marker in [
    'u32 rtw_phy_read_rf(', 'bool rtw_phy_write_rf_reg_sipi(',
    'bool rtw_phy_write_rf_reg(', 'bool rtw_phy_write_rf_reg_mix('])
callbacks = '\n'.join(block(phy, marker) for marker in [
    'void rtw_phy_cfg_mac(', 'void rtw_phy_cfg_agc(', 'void rtw_phy_cfg_bb(', 'void rtw_phy_cfg_rf('])
for name in names:
    body += block(tables, 'static const u32 rtw8821c_' + name + '[] = {') + ';\n'
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
struct rtw_chip_info{u32 id,rf_base_addr[2],rf_sipi_addr[2];const struct rf_ops*ops;const struct rtw_table *mac_tbl,*bb_tbl,*agc_tbl,*rf_tbl[1];};
struct rtw_hal{u8 cut_version,rf_phy_num,rf_path_num;u32 ch_param[3];struct rtw_phy_cond phy_cond;struct rtw_phy_cond2 phy_cond2;};
struct rtw_efuse{u8 crystal_cap,rfe_option,ext_lna_2g,ext_pa_2g,ext_lna_5g,ext_pa_5g,btcoex,alna_type,glna_type,apa_type,gpa_type;};
struct rtw_rfe_def{const struct rtw_table*agc_btg_tbl;};
struct rtw_dev{const struct rtw_rfe_def*rfe;const struct rtw_chip_info*chip;struct rtw_hal hal;struct rtw_efuse efuse;};
struct rtw_table{const void*data;u32 size;void(*do_cfg)(struct rtw_dev*,const struct rtw_table*,u32,u32);enum rtw_rf_path rf_path;};
static int rtw_hci_type(struct rtw_dev*d){return RTW_HCI_TYPE_PCIE;}
static void output(struct rtw_dev*d,const struct rtw_table*t,u32 a,u32 b){printf("%u %u\n",a,b);}
static u8 regs[0x5000];static uint64_t hash;
static void record(u8 kind,u32 reg,u32 value){hash^=kind;hash*=1099511628211ULL;for(int i=0;i<4;i++){hash^=(reg>>(i*8))&255;hash*=1099511628211ULL;}for(int i=0;i<4;i++){hash^=(value>>(i*8))&255;hash*=1099511628211ULL;}}
static u32 rtw_read32(struct rtw_dev*d,u32 reg){u32 v;record(0,reg,0);memcpy(&v,regs+reg,4);return v;}
static u8 rtw_read8(struct rtw_dev*d,u32 reg){record(4,reg,0);return regs[reg];}
static void rtw_write8(struct rtw_dev*d,u32 reg,u8 value){record(3,reg,value);regs[reg]=value;}
static void rtw_write32(struct rtw_dev*d,u32 reg,u32 value){record(1,reg,value);memcpy(regs+reg,&value,4);}
static u32 rtw_read32_mask(struct rtw_dev*d,u32 reg,u32 mask){return (rtw_read32(d,reg)&mask)>>__ffs(mask);}
static void rtw_write32_mask(struct rtw_dev*d,u32 reg,u32 mask,u32 value){u32 old=rtw_read32(d,reg);rtw_write32(d,reg,(old&~mask)|((value<<__ffs(mask))&mask));}
static void udelay(u32 us){record(2,0,us);}static void msleep(u32 ms){udelay(ms*1000);}static void mdelay(u32 ms){udelay(ms*1000);}static void usleep_range(u32 lo,u32 hi){udelay(lo);}
'''
body += '\n' + rf_helpers
body += '\nstatic void rtw_write_rf(struct rtw_dev*d,enum rtw_rf_path path,u32 addr,u32 mask,u32 value){rtw_phy_write_rf_reg_sipi(d,path,addr,mask,value);}\n'
body += '\n' + callbacks
# Evaluate the exact source prefix through its three retained channel-filter
# snapshots. Dynamic gain/power tracking/beamforming are later continuations.
chip_source = (BASE / 'rtw8821c.c').read_text()
prefix = block(chip_source, 'static void rtw8821c_phy_set_param(')
prefix = prefix[:prefix.index('\n\trtw_phy_init(rtwdev);')] + '\n}\n'
# Assert the source profile graph before constructing inert C adapters. These
# checks prevent the oracle from silently carrying C22 or guessed RFE choices.
rfe_defs = block(chip_source, 'static const struct rtw_rfe_def rtw8821c_rfe_defs[] = {')
assert re.findall(r'\[(\d+)\]\s*=', rfe_defs) == ['0','2','4','6']
assert re.findall(r'\[(\d+)\]\s*=\s*RTW_DEF_RFE_EXT\(8821c, 0, 0, 0, 2\)', rfe_defs) == ['2','4']
spec = block(chip_source, 'const struct rtw_chip_info rtw8821c_hw_spec = {')
for field,table in [('mac_tbl','mac'),('bb_tbl','bb'),('agc_tbl','agc')]:
    assert re.search(r'\.'+field+r'\s*=\s*&rtw8821c_'+table+r'_tbl',spec)
assert re.search(r'\.rf_tbl\s*=\s*\{\s*&rtw8821c_rf_a_tbl\s*\}',spec)
assert '.rfk_init_tbl' not in spec
assert re.search(r'\.write_rf\s*=\s*rtw_phy_write_rf_reg_sipi', chip_source)
for name in ['REG_SYS_FUNC_EN','REG_RF_CTRL','REG_WLRF1','REG_RXPSEL','REG_AFE_XTAL_CTRL','REG_AFE_PLL_CTRL','REG_CCK0_FAREPORT','BIT_FEN_PCIEA','BIT_FEN_BB_RSTB','BIT_FEN_BB_GLB_RST','BIT_RF_EN','BIT_RF_RSTB','BIT_RF_SDM_RSTB','BIT_RX_PSEL_RST']:
    match = re.search(r'^#define\s+'+name+r'\s+([^\n]+)', (BASE/'reg.h').read_text(), re.M)
    pre += '#define '+name+' '+match[1]+'\n'
for name in ['REG_TXSF2','REG_TXSF6','REG_TXFILTER']:
    match = re.search(r'^#define\s+'+name+r'\s+([^\n]+)', (BASE/'rtw8821c.h').read_text(), re.M)
    pre += '#define '+name+' '+match[1]+'\n'
pre += '#define MASKDWORD 0xffffffff\n'
body += '\nstatic void rtw_write32_clr(struct rtw_dev*d,u32 r,u32 m){rtw_write32(d,r,rtw_read32(d,r)&~m);}'
body += '\nstatic void rtw_write32_set(struct rtw_dev*d,u32 r,u32 m){rtw_write32(d,r,rtw_read32(d,r)|m);}'
body += '\nstatic const struct rtw_rfe_def*rtw_get_rfe_def(struct rtw_dev*d){return d->rfe;}'
body += '\nstatic void rtw_load_table(struct rtw_dev*d,const struct rtw_table*t){rtw_parse_tbl_phy_cond(d,t);}'
body += '\nstatic void rtw_load_rfk_table(struct rtw_dev*d){} // C21 chip has no rfk_init_tbl.\n'
body += block(phy,'void rtw_phy_load_tables(')+'\n'+prefix
post = r'''
int main(){const struct rf_ops ops={rtw_phy_read_rf};
'''
for index,name in enumerate(names):
    cfg=['rtw_phy_cfg_mac','rtw_phy_cfg_bb','rtw_phy_cfg_agc','rtw_phy_cfg_agc','rtw_phy_cfg_rf'][index]
    post += f'const struct rtw_table t{index}={{rtw8821c_{name},sizeof(rtw8821c_{name})/4,{cfg},0}};\n'
post += r'''
const struct rtw_chip_info chip={.id=3,.rf_base_addr={0x2800,0x2c00},.rf_sipi_addr={0xc90,0xe90},.ops=&ops,.mac_tbl=&t0,.bb_tbl=&t1,.agc_tbl=&t2,.rf_tbl={&t4}};
for(int cut=0;cut<7;cut++){for(int pkg=0;pkg<2;pkg++){for(int rfe=0;rfe<=6;rfe+=2){
const struct rtw_rfe_def r={.agc_btg_tbl=(rfe==2||rfe==4)?&t3:NULL};
struct rtw_dev d={.rfe=&r,.chip=&chip,.hal={.cut_version=cut,.rf_phy_num=1,.rf_path_num=1},.efuse={.crystal_cap=0x73,.rfe_option=rfe}};rtw_phy_setup_phy_cond(&d,pkg);
'''
for index,name in enumerate(names):
    post += f'printf("TABLE %d %d %d {index}\\n",cut,pkg,rfe);struct rtw_table out{index}=t{index};out{index}.do_cfg=output;if({index}!=3||rfe==2||rfe==4)rtw_parse_tbl_phy_cond(&d,&out{index});printf("END\\n");\n'
    post += f'for(int i=0;i<sizeof(regs);i++)regs[i]=(u8)(i*17+7);hash=14695981039346656037ULL;if({index}!=3||rfe==2||rfe==4)rtw_parse_tbl_phy_cond(&d,&t{index});printf("HASH %d %d %d {index} %llu\\n",cut,pkg,rfe,(unsigned long long)hash);\n'
post += r'''
for(int i=0;i<sizeof(regs);i++)regs[i]=(u8)(i*17+7);hash=14695981039346656037ULL;rtw8821c_phy_set_param(&d);
printf("PREFIX %d %d %d %llu %u %u %u\n",cut,pkg,rfe,(unsigned long long)hash,d.hal.ch_param[0],d.hal.ch_param[1],d.hal.ch_param[2]);
}}}return 0;}
'''
with tempfile.TemporaryDirectory() as temp:
    source, exe = Path(temp)/'tables.c', Path(temp)/'tables'
    source.write_text(pre+body+post)
    subprocess.run(['cc','-O2','-o',str(exe),str(source)],check=True)
    output=subprocess.check_output([str(exe)]).decode()
pool, selection = {}, {}
for cut,pkg,rfe,kind,rows in re.findall(r'TABLE (\d+) (\d+) (\d+) (\d+)\n(.*?)END\n',output,re.S):
    rows=tuple(tuple(map(int,row.split())) for row in rows.splitlines())
    kind=int(kind)
    if any(a>65535 for a,_ in rows): raise ValueError('C21 address exceeds u16')
    if kind<4 and any(a+4>0x2000 for a,_ in rows): raise ValueError('C21 table exceeds inactive native aperture')
    if kind==4 and any((a>255 or v>0xfffff or (a==0 and v!=0x10000)) for a,v in rows if a not in [0xfe,0xffe]):
        raise ValueError('Unexpected C21 RF-A address/data/mode')
    selection[tuple(map(int,[cut,pkg,rfe,kind]))]=pool.setdefault(rows,len(pool))
source='// SPDX-License-Identifier: GPL-2.0-or-later\n// Original Linux C21 conditional parser; regenerate with make_8821c_tables.py.\n'
for rows,index in pool.items():
    source+=f'const TABLE_{index}: &[(u16,u32)] = &[\n'+''.join(f'(0x{a:x},0x{v:x}),\n' for a,v in rows)+'];\n'
source+="pub(super) fn select(cut:u8,pkg:u8,rfe:u8,kind:usize)->Option<&'static[(u16,u32)]>{\nif cut>6||pkg>1||!matches!(rfe,0|2|4|6)||kind>4{return None;}\nconst PROFILES:[[[[u8;5];4];2];7]=[\n"
for cut in range(7):
    source+='['+','.join('['+','.join('['+','.join(str(selection[(cut,pkg,rfe,kind)]) for kind in range(5))+']' for rfe in [0,2,4,6])+']' for pkg in range(2))+'],\n'
source+='];match PROFILES[cut as usize][pkg as usize][rfe as usize/2][kind]{\n'+''.join(f'{i}=>Some(TABLE_{i}),\n' for i in pool.values())+'_=>None,}}\n'
(HERE/'rtl8821c_tables.rs').write_text(source)
hashes={tuple(map(int,[c,p,r,k])):int(v) for c,p,r,k,v in re.findall(r'HASH (\d+) (\d+) (\d+) (\d+) (\d+)',output)}
prefixes={tuple(map(int,[c,p,r])):tuple(map(int,[h,a,b,d])) for c,p,r,h,a,b,d in re.findall(r'PREFIX (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)',output)}
golden='// Original Linux C21 parser, callbacks, SIPI accessor and phy_set_param prefix.\nconst LINUX_C21_HASHES:[[[[u64;5];4];2];7]=[\n'
for cut in range(7):
    golden+='['+','.join('['+','.join('['+','.join(hex(hashes[(cut,pkg,rfe,k)]) for k in range(5))+']' for rfe in [0,2,4,6])+']' for pkg in range(2))+'],\n'
golden+='];\ntype C21Prefix = (u64,[u32;3]);\nconst LINUX_C21_PREFIX:[[[C21Prefix;4];2];7]=[\n'
for cut in range(7):
    golden+='['+','.join('['+','.join('('+hex(prefixes[(cut,pkg,rfe)][0])+',['+','.join(hex(v) for v in prefixes[(cut,pkg,rfe)][1:])+'])' for rfe in [0,2,4,6])+']' for pkg in range(2))+'],\n'
golden+='];\n'
(HERE/'rtl8821c_golden.rs').write_text(golden)
subprocess.run(['rustfmt','--edition','2021',str(HERE/'rtl8821c_tables.rs'),str(HERE/'rtl8821c_golden.rs')],check=True)
print(f'{len(pool)} unique C21 tables, {sum(map(len,pool))} interned operations, 56 exact cut/package/RFE profiles, original prefix snapshots')
