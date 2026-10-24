#!/usr/bin/env python3
"""Original B bb_sethw / MACID limits and retained post-table RPL readings."""
from pathlib import Path
import argparse,re,hashlib,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;s=(a.linux/'rtw8852b_common.c').read_text();reg=(a.linux/'reg.h').read_text();core=(a.linux/'core.h').read_text()
def f(n):
 m=re.search(r'^(?:static\s+)?void\s+'+n+r'\s*\(',s,re.M);e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]+'\n'
body=f('rtw8852bx_bb_macid_ctrl_init')+f('__rtw8852bx_bb_sethw');defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',reg,re.M)};names=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+)\b',body));regs='\n'.join(defs[n] for n in sorted(names))
layout=re.search(r'struct rtw89_phy_efuse_gain \{.*?^\};',core,re.M|re.S).group(0)
enums=''.join(re.search(r'enum \w+ \{[^}]*\b'+name+r'\b[^}]*\};',core,re.S).group(0)+'\n' for name in ['RTW89_GAIN_OFFSET_NR','RTW89_SUBBAND_NR'])
enums+=re.search(r'^#define RF_PATH_MAX[^\n]+',core,re.M).group(0)+'\n'
pre=r'''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define RTW89_PHY_0 0
enum rtw89_phy_idx{PHY0};
#define RTW89_PHY_NUM 2
'''+enums+layout+r'''
struct rtw89_dev{struct rtw89_phy_efuse_gain efuse_gain;u32 words[0x20000/4];};
static u64 hash;static u32 count;
static void val(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(i*8));hash*=1099511628211ULL;}}
static void write(struct rtw89_dev*d,u32 a,u32 v){d->words[a/4]=v;count++;val(4);val(a);val(v);}
static void rtw89_phy_write32_clr(struct rtw89_dev*d,u32 a,u32 m){a+=0x10000;write(d,a,d->words[a/4]&~m);}
static void rtw89_mac_txpwr_write32(struct rtw89_dev*d,int i,u32 a,u32 v){write(d,a,v);}
static u32 rtw89_phy_read32_mask(struct rtw89_dev*d,u32 a,u32 m){return (d->words[(a+0x10000)/4]&m)>>__builtin_ctz(m);}
'''
main=r'''int main(void){puts("pub(super) const CONTROLS: &[(u8,u32,u64,[i8;2])] = &[");for(int seed=0;seed<2;seed++){static struct rtw89_dev d;for(int i=0;i<0x20000/4;i++)d.words[i]=seed?0xa5a5a5a5:0;hash=14695981039346656037ULL;count=0;__rtw8852bx_bb_sethw(&d);printf("(%u,%u,0x%llx,[%d,%d]),\n",seed?165:0,count,(unsigned long long)hash,d.efuse_gain.offset_base[0],d.efuse_gain.rssi_base[0]);}puts("];" );}'''
source=pre+regs+'\n'+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-control-c-') as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
v='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B bb_sethw SHA256 '+hashlib.sha256((body+regs+layout+enums).encode()).hexdigest()+'\n'+out
if a.check:
 if (d/'control_golden.rs').read_text()!=v:raise SystemExit('B controls oracle differs')
else:(d/'control_golden.rs').write_text(v)
