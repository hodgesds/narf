#!/usr/bin/env python3
"""Compile original B RF-v1 analog/direct callbacks on a deterministic bus."""
from pathlib import Path
import argparse, hashlib, re, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
source=(a.linux/'phy.c').read_text()
def function(name):
    m=re.search(r'^(?:static )?(?:bool|u32)\s+'+name+r'\s*\(',source,re.M)
    if not m:raise RuntimeError(name)
    end=source.index('{',m.end())+1;depth=1
    while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[m.start():end]+'\n'
names=['rtw89_phy_check_swsi_busy','rtw89_phy_read_rf','rtw89_phy_read_rf_a','rtw89_phy_read_rf_v1',
    'rtw89_phy_write_rf','rtw89_phy_write_rf_a','rtw89_phy_write_rf_v1']
original=''.join(function(n) for n in names)
headers='\n'.join((a.linux/n).read_text() for n in ['reg.h','phy.h','core.h'])
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)}
needed=set(re.findall(r'\b(?:R_SWSI_\w+|B_SWSI_\w+|RFREG_MASK|RTW89_RF_ADDR_ADSEL_MASK|INV_RF_DATA|MASKDWORD)\b',original))
defines='\n'.join(defs[n] for n in sorted(needed))
base=re.search(r'rtw89_phy_gen_ax = \{\s*\.cr_base = (0x\w+)',source).group(1)
rfbase=re.search(r'\.rf_base_addr\s*=\s*\{([^}]+)\}',(a.linux/'rtw8852b.c').read_text()).group(1)
prefix='''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define __ffs(m) __builtin_ctz(m)
#define rtw89_err(...) ((void)0)
#define test_bit(...) 0
#define RTW89_FLAG_UNPLUGGED 0
enum rtw89_rf_path {RF_PATH_A,RF_PATH_B};
struct rtw89_chip_info {const u32 *rf_base_addr;u8 rf_path_num;};
struct rtw89_dev {const struct rtw89_chip_info *chip;u32 words[0x20000/4];};
static void udelay(u32 us){printf("(8,%u,0),",us);}
#define read_poll_timeout_atomic(op,val,condition,step,budget,pre,...) ({int err=-ETIMEDOUT;for(u32 t=0;t<=budget;t+=step){val=op(__VA_ARGS__);if(condition){err=0;break;}if(t<budget)udelay(step);}err;})
'''
shim=f'#define PHY_BASE {base}\n'+'''
static u32 rtw89_phy_read32_mask(struct rtw89_dev *d,u32 a,u32 m){u32 v=d->words[(a+PHY_BASE)/4];printf("(0,0x%x,0x%x),",a+PHY_BASE,v);return FIELD_GET(m,v);}
static void rtw89_phy_write32_mask(struct rtw89_dev *d,u32 a,u32 m,u32 v){
 u32 old=d->words[(a+PHY_BASE)/4];printf("(0,0x%x,0x%x),",a+PHY_BASE,old);
 u32 next=(old&~m)|FIELD_PREP(m,v);d->words[(a+PHY_BASE)/4]=next;printf("(4,0x%x,0x%x),",a+PHY_BASE,next);
 if(a==R_SWSI_READ_ADDR_V1)d->words[R_SWSI_V1/4+PHY_BASE/4]|=B_SWSI_R_DATA_DONE_V1;
}
'''
main=r'''int main(void){
 printf("type RfGolden = (bool,u8,u8,u32,u32,u32,&'static [(u8,u32,u32)]);\npub(super) const CASES: &[RfGolden] = &[\n");
 const u32 bases[]={RF_BASES};struct rtw89_chip_info chip={bases,2};
 for(u32 seed=0;seed<2;seed++)for(u32 wr=0;wr<2;wr++)for(u32 path=0;path<2;path++)for(u32 direct=0;direct<2;direct++)for(u32 mi=0;mi<3;mi++) {
  struct rtw89_dev dev={.chip=&chip};for(u32 i=0;i<0x20000/4;i++)dev.words[i]=seed?0xa5a5a5a5:0;
  dev.words[(PHY_BASE+R_SWSI_V1)/4]=0x45678;u32 masks[]={0xfffff,0xff00,0x103};u32 addr=0x55|(direct?0x10000:0);
  printf("(%s,%u,%u,0x%x,0x%x,",wr?"true":"false",seed?165:0,path,addr,masks[mi]);
  // Result prints after the trace so buffer it using a second identical run.
  printf("RESULT,&[");u32 result=wr?rtw89_phy_write_rf_v1(&dev,path,addr,masks[mi],0x789abc):rtw89_phy_read_rf_v1(&dev,path,addr,masks[mi]);
  printf("]), // value=%u\n",result);
 }
 printf("];\n");return 0;
}'''.replace('RF_BASES',rfbase)
code=prefix+defines+'\n'+shim+original+main
with tempfile.TemporaryDirectory(prefix='rtw89-rf-access-oracle-') as td:
    td=Path(td);(td/'oracle.c').write_text(code)
    subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True)
    result=subprocess.check_output([str(td/'oracle')]).decode()
result=re.sub(r'RESULT,(&\[.*?\])\), // value=(\d+)',lambda m:m.group(2)+','+m.group(1)+'),',result)
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux RF callbacks/macros SHA256 '+hashlib.sha256((original+defines+base+rfbase).encode()).hexdigest()+'\n'+result
path=d/'golden.rs'
if a.check:
    if path.read_text()!=value:raise SystemExit('RF oracle differs')
else:path.write_text(value)
