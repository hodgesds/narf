#!/usr/bin/env python3
"""Compile actual runtime H2C header sequencing for B firmware RF pages."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args()
s=(a.linux/'fw.c').read_text();m=re.search(r'^void rtw89_h2c_pkt_set_hdr\(',s,re.M);end=s.index('{',m.end())+1;depth=1
while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
original=s[m.start():end];header=(a.linux/'fw.h').read_text();defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',header,re.M)}
names=set(re.findall(r'\bH2C_HDR_\w+\b',original));names.add('H2C_HEADER_LEN');definitions='\n'.join(defs[n] for n in sorted(names))
code='''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
typedef uint8_t u8;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define cpu_to_le32(v) (v)
#define RTW89_CHIP_AX 0
struct rtw89_chip_info {int chip_gen;};struct rtw89_dev {const struct rtw89_chip_info *chip;struct {u8 h2c_seq;}fw;};
struct fwcmd_hdr {u32 hdr0,hdr1;};struct sk_buff {u8 data[8];};
static void *skb_push(struct sk_buff *s,int n){return s->data;}
'''+definitions+'\n'+original+r'''
int main(void){
 puts("type HeaderGolden = (u8,u8,u8,u16,[u8;8]);\npub(super) const HEADERS: &[HeaderGolden] = &[");u8 seqs[]={0,1,4,255};u32 lens[]={4,2000};struct rtw89_chip_info chip={0};
 for(int s=0;s<4;s++)for(int path=0;path<2;path++)for(int page=0;page<3;page++)for(int l=0;l<2;l++) {
  struct rtw89_dev d={.chip=&chip,.fw.h2c_seq=seqs[s]};struct sk_buff skb={0};rtw89_h2c_pkt_set_hdr(&d,&skb,0,2,8+path,page,false,false,lens[l]);
  printf("(%u,%u,%u,%u,[",seqs[s],path,page,lens[l]);for(int i=0;i<8;i++)printf("%u,",skb.data[i]);puts("]),");
 }puts("];");return 0;
}'''
with tempfile.TemporaryDirectory(prefix='rtw89-radio-header-') as td:
 td=Path(td);(td/'oracle.c').write_text(code);subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True);result=subprocess.check_output([str(td/'oracle')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux runtime H2C header SHA256 '+hashlib.sha256((original+definitions).encode()).hexdigest()+'\n'+result
path=Path(__file__).with_name('header_golden.rs')
if a.check:
 if path.read_text()!=value:raise SystemExit('runtime RF header oracle differs')
else:path.write_text(value)
