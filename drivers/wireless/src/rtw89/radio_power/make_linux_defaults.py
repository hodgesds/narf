#!/usr/bin/env python3
"""Compile exact B static defaults and emit only the fixed WW/ch1/20 profile."""
from pathlib import Path
import re,subprocess,tempfile,hashlib,argparse
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;t=(a.linux/'rtw8852b_table.c').read_text();core=(a.linux/'core.h').read_text()
names=['rtw89_8852b_txpwr_byrate','rtw89_8852b_txpwr_lmt_2g','rtw89_8852b_txpwr_lmt_ru_2g','rtw89_8852b_tx_shape_lmt'];arrays='\n'.join(re.search(r'^(?:static\s+)?const (?:struct rtw89_txpwr_byrate_cfg|s8|u8) '+n+r'\[.*?^\};',t,re.M|re.S).group(0) for n in names)
enums='\n'.join(re.search(r'enum \w+ \{[^}]*\b'+n+r'\b[^}]*\};',core,re.S).group(0) for n in ['RTW89_WW','RTW89_RS_CCK','RTW89_RU26'])
pre='''#include <stdint.h>
#include <stdio.h>
typedef int8_t s8;typedef uint8_t u8;typedef uint32_t u32;
#define RTW89_2G_BW_NUM 2
#define RTW89_NTX_NUM 2
#define RTW89_BF_NUM 2
#define RTW89_2G_CH_NUM 14
#define RTW89_BAND_NUM 3
struct rtw89_txpwr_byrate_cfg{u8 band,nss,rs,shf,len;u32 data;};
'''
main='''int main(void){puts("pub(super) const DEFAULT:Plan=Plan{");s8 by[44]={},off[5]={};for(int k=0;k<sizeof(rtw89_8852b_txpwr_byrate)/sizeof(*rtw89_8852b_txpwr_byrate);k++){const struct rtw89_txpwr_byrate_cfg*e=&rtw89_8852b_txpwr_byrate[k];if(e->band)continue;int base=e->rs==0?0:e->rs==1?4:e->rs==2?(e->nss?28:12):e->rs==3?(e->nss?40:24):0;u32 data=e->data;for(int i=0;i<e->len;i++,data>>=8){if(e->rs==4)off[e->shf+i]=data;else by[base+e->shf+i]=data;}}
puts("byrate:[");for(int i=0;i<44;i++)printf("%d,",by[i]);puts("],offset:[");for(int i=0;i<5;i++)printf("%d,",off[i]);puts("],limits:[");for(int n=0;n<2;n++){puts("[");for(int x=0;x<4;x++)for(int bf=0;bf<2;bf++)printf("%d,",rtw89_8852b_txpwr_lmt_2g[x==1?1:0][n][x==0||x==1?0:x==2?1:2][bf][0][0]);puts("],");}puts("],ru:[");for(int n=0;n<2;n++){puts("[");for(int ru=0;ru<3;ru++)printf("%d,",rtw89_8852b_txpwr_lmt_ru_2g[ru][n][0][0]);puts("],");}printf("],shape:[%u,%u]};\\n",rtw89_8852b_tx_shape_lmt[0][0][0],rtw89_8852b_tx_shape_lmt[0][1][0]);}'''
with tempfile.TemporaryDirectory(prefix='rtw89-power-default-') as td:
 td=Path(td);(td/'o.c').write_text(pre+enums+arrays+main);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
out='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original B static power SHA256 '+hashlib.sha256((enums+arrays).encode()).hexdigest()+'\nuse super::Plan;\n'+out
out=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=out.encode()).decode()
if a.check:
 if (d/'defaults.rs').read_text()!=out:raise SystemExit('defaults differ')
else:(d/'defaults.rs').write_text(out)
