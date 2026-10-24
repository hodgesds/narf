#!/usr/bin/env python3
"""Original B PMAC stop/routing and exact RF clock/reset shutdown prefix."""
from pathlib import Path
import argparse,re,hashlib,tempfile,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;s=(a.linux/'rtw8852b_common.c').read_text();rfk=(a.linux/'rtw8852b_rfk.c').read_text();h=(a.linux/'reg.h').read_text()
def f(n,src=s):
 m=re.search(r'^(?:static\s+)?(?:void|int|bool)\s+'+n+r'\s*\(',src,re.M);e=src.index('{',m.end())+1;depth=1
 while depth:depth+=(src[e]=='{')-(src[e]=='}');e+=1
 return src[m.start():e]+'\n'
body=f('rtw8852bx_stop_pmac_tx')+f('__rtw8852bx_bb_tx_mode_switch')
# Preserve original statements (no Rust encoder or duplicated source masks).
stop=f('__rtw8852bx_mac_disable_bb_rf');stop=stop[stop.index('rtw89_write32_clr'):stop.index('ret = rtw89_mac_read_xtal_si')];body+='static void clocks(struct rtw89_dev*rtwdev){'+stop+'}\n'
one=f('_iqk_one_shot',rfk);restore=f('_iqk_restore',rfk)
controls=re.search(r'\trtw89_phy_write32_mask\(rtwdev, R_P0_RFCTM, B_P0_RFCTM_EN, 0x0\);\n\n\treturn fail;',one).group(0).split('\n\n')[0]
for name in ['R_NCTL_N1','R_NCTL_RPT','R_KIP_SYSCFG']:
 controls+=re.search(r'\trtw89_phy_write32_mask\(rtwdev, '+name+r',.*?\);',restore,re.S).group(0)+'\n'
body+='static void nctl(struct rtw89_dev*rtwdev){'+controls+'}\n'
names=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+|MASKDWORD)\b',body));defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',h+'\n'+(a.linux/'core.h').read_text(),re.M)};todo=list(names)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in names:names.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(names))
pre=r'''#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define rtw89_debug(...) ((void)0)
enum rtw89_phy_idx{PHY0};enum{CONT_TX,PKTS_TX};struct rtw8852bx_bb_pmac_info{u8 mode;};struct rtw89_dev{u8 bytes[0x20000];};
static u64 hash;static u32 count;
static void value(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(i*8));hash*=1099511628211ULL;}}
static u32 read32(struct rtw89_dev*d,u32 a){u32 v;memcpy(&v,d->bytes+a,4);return v;}
static void write32(struct rtw89_dev*d,u32 a,u32 v){memcpy(d->bytes+a,&v,4);count++;value(4);value(a);value(v);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 m){write32(d,a,read32(d,a)&~m);}
static void rtw89_write8_clr(struct rtw89_dev*d,u32 a,u8 m){d->bytes[a]&=~m;count++;value(1);value(a);value(d->bytes[a]);}
static void rtw89_phy_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){a+=0x10000;write32(d,a,(read32(d,a)&~m)|((v<<__builtin_ctz(m))&m));}
static void rtw89_phy_write32_idx(struct rtw89_dev*d,u32 a,u32 m,u32 v,int i){rtw89_phy_write32_mask(d,a,m,v);}
'''
main='int main(void){puts("REGS");'+''.join('printf("pub(super) const '+n+': u32 = 0x%x;\\n",(u32)'+n+');\n' for n in sorted(names))+r'''
puts("CASES\npub(super) const CASES: &[(u8,u32,u64)] = &[");for(int seed=0;seed<2;seed++){static struct rtw89_dev d;memset(&d,seed?0xa5:0,sizeof(d));hash=14695981039346656037ULL;count=0;struct rtw8852bx_bb_pmac_info p={CONT_TX};rtw8852bx_stop_pmac_tx(&d,&p,0);p.mode=PKTS_TX;rtw8852bx_stop_pmac_tx(&d,&p,0);__rtw8852bx_bb_tx_mode_switch(&d,0,0);nctl(&d);clocks(&d);printf("(%u,%u,0x%llx),\n",seed?165:0,count,(unsigned long long)hash);}puts("];" );}'''
source=pre+regs+'\n'+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-radio-stop-c-') as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
r,g=out.removeprefix('REGS\n').split('CASES\n');comment='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B RF terminal controls SHA256 '+hashlib.sha256((body+regs).encode()).hexdigest()+'\n'
for name,value in [('regs.rs',comment+r),('golden.rs',comment+g)]:
 if a.check:
  if (d/name).read_text()!=value:raise SystemExit(name+' differs')
 else:(d/name).write_text(value)
