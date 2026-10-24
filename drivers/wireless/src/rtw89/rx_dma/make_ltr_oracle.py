#!/usr/bin/env python3
"""Compile the original AX LTR callback against an independent register bus."""
from pathlib import Path
import argparse, hashlib, re, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
source=(a.linux/'pci.c').read_text();m=re.search(r'^int rtw89_pci_ltr_set\(',source,re.M)
end=source.index('{',m.end())+1;depth=1
while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
original=source[m.start():end]
header=(a.linux/'reg.h').read_text()
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',header,re.M)}
names=set(re.findall(r'\b(?:R_AX_LTR_\w+|B_AX_LTR_\w+|PCI_LTR_\w+)\b',original))
defines='\n'.join(defs[n] for n in sorted(names))
code='''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
struct rtw89_dev {bool host;u32 words[4];};
static bool rtw89_pci_dev_ltr_enabled(struct rtw89_dev *dev){return dev->host;}
static bool rtw89_pci_ltr_is_err_reg_val(u32 v){return v==0xffffffff||v==0xeaeaeaea;}
static u32 rtw89_read32(struct rtw89_dev *dev,u32 a){return dev->words[(a-0x8410)/4];}
static void rtw89_write32(struct rtw89_dev *dev,u32 a,u32 v){dev->words[(a-0x8410)/4]=v;printf("(0x%x,0x%x),",a,v);}
static void rtw89_write32_set(struct rtw89_dev *d,u32 a,u32 v){rtw89_write32(d,a,rtw89_read32(d,a)|v);}
static void rtw89_write32_mask(struct rtw89_dev *d,u32 a,u32 m,u32 v){rtw89_write32(d,a,(rtw89_read32(d,a)&~m)|((v<<__builtin_ctz(m))&m));}
'''+defines+'\n'+original+r'''
int main(void){
 printf("type LtrGolden = (bool,u8,&'static [(u32,u32)]);\npub(super) const LTR: &[LtrGolden] = &[\n");
 for(u32 seed=0;seed<2;seed++)for(u32 host=0;host<2;host++) {
  u32 s=seed?0xa5a5a5a5:0;struct rtw89_dev dev={.host=host,.words={s,s,s,s}};
  printf("(%s,%u,&[",host?"true":"false",seed?165:0);if(rtw89_pci_ltr_set(&dev,true))return 1;printf("]),\n");
 }
 printf("];\n");return 0;
}'''
with tempfile.TemporaryDirectory(prefix='rtw89-ltr-oracle-') as td:
    td=Path(td);(td/'oracle.c').write_text(code)
    subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True)
    result=subprocess.check_output([str(td/'oracle')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux LTR callback/macros SHA256 '+hashlib.sha256((original+defines).encode()).hexdigest()+'\n'+result
path=d/'ltr_golden.rs'
if a.check:
    if path.read_text()!=value:raise SystemExit('LTR oracle differs')
else:path.write_text(value)
