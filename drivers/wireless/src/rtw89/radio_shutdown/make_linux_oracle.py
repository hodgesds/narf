#!/usr/bin/env python3
"""Execute exact original B disable_bb_rf plus AX XTAL read/write callbacks."""
from pathlib import Path
import argparse,re,hashlib,tempfile,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;mac=(a.linux/'mac.c').read_text();chip=(a.linux/'rtw8852b_common.c').read_text();headers=(a.linux/'reg.h').read_text()+'\n'+(a.linux/'mac.h').read_text()
def f(n,s):
 m=re.search(r'^(?:static\s+)?int\s+'+n+r'\s*\(',s,re.M);e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]+'\n'
body=f('rtw89_mac_read_xtal_si_ax',mac)+f('rtw89_mac_write_xtal_si_ax',mac)+f('__rtw8852bx_mac_disable_bb_rf',chip)
names=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+|XTAL_SI_[A-Z0-9_]+|FULL_BIT_MASK)\b',body));defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)}
for n in ['XTAL_SI_WL_RFC_S0','XTAL_SI_WL_RFC_S1']:defs[n]='#define '+n+' '+re.search(r'\b'+n+r'\s*=\s*(0x[0-9a-fA-F]+)',headers).group(1)
todo=list(names)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in names:names.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(names))
pre=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define u32_get_bits(v,m) (((v)&(m))>>__builtin_ctz(m))
#define rtw89_warn(...) ((void)0)
#define RTW89_FLAG_UNPLUGGED 0
#define test_bit(...) false
#define rtw89_mac_read_xtal_si rtw89_mac_read_xtal_si_ax
#define rtw89_mac_write_xtal_si rtw89_mac_write_xtal_si_ax
struct rtw89_dev{u8 bytes[0x1000],xtal[256];u32 command,left,busy;};
static u64 hash;static u32 count;
static void value(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(i*8));hash*=1099511628211ULL;}}
static void record(u32 k,u32 a,u32 v){count++;value(k);value(a);value(v);}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){if(a==0x270){if(d->left){d->left--;return d->command;}u32 v=d->command&~BIT(31);u8 address=v;if(v&BIT(24))v=(v&~0xff00)|(d->xtal[address]<<8);else d->xtal[address]=v>>8;return v;}u32 v;memcpy(&v,d->bytes+a,4);return v;}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){memcpy(d->bytes+a,&v,4);record(4,a,v);if(a==0x270){d->command=v;d->left=d->busy;}}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 m){rtw89_write32(d,a,rtw89_read32(d,a)&~m);}
static void rtw89_write8_clr(struct rtw89_dev*d,u32 a,u8 m){d->bytes[a]&=~m;record(1,a,d->bytes[a]);}
static void udelay(u32 u){record(8,u,0);}
#define read_poll_timeout(op,v,cond,step,budget,pre,...) ({int err=-ETIMEDOUT;for(u32 t=0;t<=budget;t+=step){v=op(__VA_ARGS__);if(cond){err=0;break;}if(t<budget)udelay(step);}err;})
'''
main=r'''int main(void){puts("pub(super) const CASES: &[(u8,u8,u32,u64)] = &[");for(int seed=0;seed<2;seed++)for(int busy=0;busy<2;busy++){struct rtw89_dev d={.busy=busy};memset(d.bytes,seed?0xa5:0,sizeof(d.bytes));memset(d.xtal,seed?0xa5:0,sizeof(d.xtal));hash=14695981039346656037ULL;count=0;assert(!__rtw8852bx_mac_disable_bb_rf(&d));for(int a=0x80;a<=0x81;a++){u8 v;assert(!rtw89_mac_read_xtal_si_ax(&d,a,&v)&&!(v&7));}printf("(%u,%u,%u,0x%llx),\n",seed?165:0,busy,count,(unsigned long long)hash);}puts("];" );}'''
source=pre+regs+'\n'+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-shutdown-c-') as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
v='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B RF shutdown SHA256 '+hashlib.sha256((body+regs).encode()).hexdigest()+'\n'+out
if a.check:
 if (d/'golden.rs').read_text()!=v:raise SystemExit('B XTAL shutdown differs')
else:(d/'golden.rs').write_text(v)
