"""Conservative ch1/1Mbps factory ceilings using original Linux PG decoder.

The initial profile uses the minimum over every source regulatory row, so an
EEPROM country hint cannot promote a gain. These remain indices, not dBm.
"""
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88')
HERE = Path(__file__).parent


def block(source, marker):
    start = source.index(marker)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


phy, header, main = ((BASE / name).read_text() for name in ['phy.c','phy.h','main.h'])
chip, tables = ((BASE / name).read_text() for name in ['rtw8822c.c','rtw8822c_table.c'])
profiles = {int(rfe):(int(pg),int(lmt)) for rfe,pg,lmt,_ in re.findall(r'\[(\d+)\]\s*=\s*RTW_DEF_RFE\(8822c,\s*(\d+),\s*(\d+),\s*(\d+)\)',chip)}
assert set(profiles) == set(range(7))
body = block(main,'enum rtw_trx_desc_rate {') + ';\n'
body += block(header,'struct rtw_phy_pg_cfg_pair {') + ';\n' + block(header,'struct rtw_txpwr_lmt_cfg_pair {') + ';\n'
for pg in sorted({pg for pg,_ in profiles.values()}):
    body += block(tables,f'static const struct rtw_phy_pg_cfg_pair rtw8822c_bb_pg_type{pg}[] = {{') + ';\n'
for lmt in sorted({lmt for _,lmt in profiles.values()}):
    body += block(tables,f'static const struct rtw_txpwr_lmt_cfg_pair rtw8822c_txpwr_lmt_type{lmt}[] = {{') + ';\n'
types = '''struct rtw_chip_info{bool is_pwr_by_rate_dec;};
struct rtw_dev{const struct rtw_chip_info*chip;};
struct rtw_hal{s8 tx_pwr_by_rate_offset_2g[4][256],tx_pwr_by_rate_offset_5g[4][256],tx_pwr_by_rate_base_2g[4][16],tx_pwr_by_rate_base_5g[4][16];};
'''
functions = block(phy,'static u8 tbl_to_dec_pwr_by_rate(') + '\n'
functions += 'static void\n' + block(phy,'rtw_phy_get_rate_values_of_txpwr_by_rate(') + '\n'
functions += 'static void\n' + block(phy,'rtw_phy_tx_power_by_rate_config_by_path(') + '\n'
pre = '''#include <stdint.h>\n#include <stdbool.h>\n#include <stdio.h>\ntypedef uint8_t u8;typedef uint32_t u32;typedef int8_t s8;\n#define rtw_warn(...)\n#define bcd_to_dec_pwr_by_rate(v,i) ((((v>>((i)*8))&15)+10*((v>>((i)*8+4))&15)))\n'''
post = '\nint main(){const struct rtw_chip_info chip={false};struct rtw_dev dev={&chip};const u8 rates[]={DESC_RATE1M,DESC_RATE2M,DESC_RATE5_5M,DESC_RATE11M};\n'
for rfe,(pg,lmt) in sorted(profiles.items()):
    post += f'''{{struct rtw_hal hal={{0}};for(int i=0;i<sizeof(rtw8822c_bb_pg_type{pg})/sizeof(struct rtw_phy_pg_cfg_pair);i++){{
const struct rtw_phy_pg_cfg_pair*p=&rtw8822c_bb_pg_type{pg}[i];if(p->band||p->rf_path>1)continue;u8 rate[4]={{0}},power[4]={{0}},n=0;
rtw_phy_get_rate_values_of_txpwr_by_rate(&dev,p->addr,p->bitmask,p->data,rate,power,&n);for(int j=0;j<n;j++)hal.tx_pwr_by_rate_offset_2g[p->rf_path][rate[j]]=(s8)power[j];}}
for(int p=0;p<2;p++)rtw_phy_tx_power_by_rate_config_by_path(&hal,p,0,4,rates);
int minimum=127,count=0;for(int i=0;i<sizeof(rtw8822c_txpwr_lmt_type{lmt})/sizeof(struct rtw_txpwr_lmt_cfg_pair);i++){{const struct rtw_txpwr_lmt_cfg_pair*p=&rtw8822c_txpwr_lmt_type{lmt}[i];if(p->band||p->bw||p->rs||p->ch!=1)continue;if(p->txpwr_lmt<minimum)minimum=p->txpwr_lmt;count++;}}if(!count)return 1;
int limit=minimum-hal.tx_pwr_by_rate_base_2g[0][0];printf("[");for(int p=0;p<2;p++){{int byrate=hal.tx_pwr_by_rate_offset_2g[p][DESC_RATE1M];int adjust=byrate<limit?byrate:limit;if(adjust>0)adjust=0;printf("%d,",adjust);}}printf("],\\n");}}
'''
post += 'return 0;}\n'
with tempfile.TemporaryDirectory() as temp:
    source, exe = Path(temp)/'power.c',Path(temp)/'power'
    source.write_text(pre+body+types+functions+post)
    subprocess.run(['cc','-O2','-o',str(exe),str(source)],check=True)
    output = subprocess.check_output([str(exe)]).decode()
target = HERE/'power_values.rs'
target.write_text('// SPDX-License-Identifier: GPL-2.0-or-later\n// Original Linux PG decode/normalization and minimum over every ch1/CCK/20MHz region row.\npub(super) const CCK1_ADJUST: [[i16;2];7] = [\n'+output+'];\n')
subprocess.run(['rustfmt','--edition','2021',str(target)],check=True)
