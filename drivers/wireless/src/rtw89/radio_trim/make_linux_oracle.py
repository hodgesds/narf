#!/usr/bin/env python3
"""Original B thermal and PA-bias trim callbacks, actual physical-byte semantics."""
from pathlib import Path
import argparse,re,tempfile,subprocess,hashlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;s=(a.linux/'rtw8852b_common.c').read_text()
def f(n):
 m=re.search(r'^static void '+n+r'\s*\(',s,re.M);e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]+'\n'
body=''.join(f(n)for n in ['rtw8852bx_thermal_trim','rtw8852bx_pa_bias_trim','__rtw8852bx_power_trim']);headers=(a.linux/'reg.h').read_text();defs={m.group(1):m.group(0)for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)};selected=set(re.findall(r'\b(?:RR_[A-Z0-9_]+)\b',body));regs='\n'.join(defs[n]for n in sorted(selected))
pre=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define RF_PATH_NUM_8852BX 2
#define rtw89_debug(...) ((void)0)
struct rtw89_power_trim_info{bool pg_thermal_trim,pg_pa_bias_trim;u8 thermal_trim[2],pa_bias_trim[2];};struct rtw89_dev{struct rtw89_power_trim_info pwr_trim;};
static u64 hash;static u32 count;
static void value(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(i*8));hash*=1099511628211ULL;}}
static void rtw89_write_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m,u32 v){count++;value(p);value(a);value(m);value(v);}
'''
main='''int main(void){puts("pub(super) const CASES:&[(u8,u32,u64)]=&[");for(int flags=0;flags<4;flags++){struct rtw89_dev d={.pwr_trim={.pg_thermal_trim=flags&1,.pg_pa_bias_trim=flags&2,.thermal_trim={0x5d,0x12},.pa_bias_trim={0xa3,0x7e}}};count=0;hash=14695981039346656037ULL;__rtw8852bx_power_trim(&d);printf("(%u,%u,0x%llx),\\n",flags,count,(unsigned long long)hash);}puts("];");puts("REGS");'''+''.join('printf("pub(super) const '+n+':u32=0x%x;\\n",(u32)'+n+');'for n in sorted(selected))+'''}'''
with tempfile.TemporaryDirectory(prefix='rtw89-trim-c-')as td:
 td=Path(td);(td/'o.c').write_text(pre+regs+'\n'+body+main);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
golden,regsout=out.split('REGS\n');digest=hashlib.sha256((body+regs).encode()).digest();comment='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original B trim SHA256 '+digest.hex()+'\n'
for n,v in [('golden.rs',comment+golden),('regs.rs',comment+regsout+'pub(super) const RECIPE:[u8;32]=['+','.join(map(str,digest))+'];')]:
 v=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=v.encode()).decode()
 if a.check:
  if (d/n).read_text()!=v:raise SystemExit(n+' differs')
 else:(d/n).write_text(v)
