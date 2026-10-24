#!/usr/bin/env python3
"""Execute original B initial-channel enter/leave helpers and AX PPDU callback."""
from pathlib import Path
import re,hashlib,tempfile,subprocess,argparse
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
chip=(a.linux/'rtw8852b.c').read_text();mac=(a.linux/'mac.c').read_text()
def f(n,s):
 m=re.search(r'^(?:static\s+)?(?:int|void)\s+'+n+r'\s*\(',s,re.M);e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]+'\n'
body=''.join(f(n,chip) for n in ['rtw8852b_bb_reset_en','rtw8852b_tssi_cont_en','rtw8852b_tssi_cont_en_phyidx','rtw8852b_adc_en'])+f('rtw89_mac_cfg_ppdu_status_ax',mac)+f('rtw8852b_set_channel_help',chip)
headers='\n'.join((a.linux/n).read_text() for n in ['reg.h','core.h','mac.h']);defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)};selected=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+)\b',body));todo=list(selected)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in selected:selected.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(selected))
pre=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m))&(m))
enum rtw89_rf_path{RF_PATH_A,RF_PATH_B};
#define RTW89_PHY_0 0
#define RTW89_MAC_0 0
#define RTW89_CMAC_SEL 1
#define RTW89_SCH_TX_SEL_ALL 0
#define RTW89_PRPT_DEST_HOST 2
enum rtw89_band{RTW89_BAND_2G};enum rtw89_phy_idx{PHY0};enum rtw89_mac_idx{MAC0};
struct rtw89_dev{bool dbcc_en;u32 words[0x20000/4];};struct rtw89_chan{enum rtw89_band band_type;};struct rtw89_channel_help_params{u32 tx_en;};
static u64 hash;static u32 count;static bool program;
static void value(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(i*8));hash*=1099511628211ULL;}}
static void record(u32 k,u32 a,u32 v){count++;value(k);value(a);value(v);}
static void entry(u32 k,u32 a,u32 m,u32 v){if(program)printf("Step(%u,0x%x,0x%x,0x%x),\n",k,a,m,v);}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){return d->words[a/4];}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){entry(0,a,~0U,v);d->words[a/4]=v;record(4,a,v);}
static void rtw89_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){entry(0,a,m,v);d->words[a/4]=(d->words[a/4]&~m)|FIELD_PREP(m,v);record(4,a,d->words[a/4]);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 m){rtw89_write32_mask(d,a,m,0);}
static void rtw89_phy_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_write32_mask(d,a+0x10000,m,v);}
static void rtw89_phy_write32_idx(struct rtw89_dev*d,u32 a,u32 m,u32 v,u8 i){assert(i==0);rtw89_phy_write32_mask(d,a,m,v);}
static u32 rtw89_mac_reg_by_idx(struct rtw89_dev*d,u32 a,u8 i){assert(i==0);return a;}
static int rtw89_mac_check_mac_en(struct rtw89_dev*d,u8 i,u8 s){assert(i==0&&s==1);return 0;}
static void fsleep(u32 u){entry(1,0,0,u);record(8,u,0);}
static void rtw89_chip_stop_sch_tx(struct rtw89_dev*d,u8 i,u32*saved,u8 all){assert(i==0&&all==0);entry(2,0,0,0);*saved=d->words[0xc348/4]&65535;record(32,0,*saved);}
static void rtw89_chip_resume_sch_tx(struct rtw89_dev*d,u8 i,u32 saved){assert(i==0);entry(3,0,0,0);record(64,0,saved);}
#define rtw89_mac_cfg_ppdu_status rtw89_mac_cfg_ppdu_status_ax
'''
main=r'''int main(void){struct rtw89_dev d={};struct rtw89_chan c={RTW89_BAND_2G};struct rtw89_channel_help_params p={};
program=true;puts("PROGRAM\npub(super) const ENTER:&[Step]=&[");rtw8852b_set_channel_help(&d,true,&p,&c,0,0);puts("];\npub(super) const LEAVE:&[Step]=&[");rtw8852b_set_channel_help(&d,false,&p,&c,0,0);puts("];");program=false;
puts("CASES\npub(super) const CASES:&[(u8,u32,u64)]=&[");for(int seed=0;seed<2;seed++){memset(&d,0,sizeof(d));for(int i=0;i<0x20000/4;i++)d.words[i]=seed?0xa5a5a5a5:0;hash=14695981039346656037ULL;count=0;rtw8852b_set_channel_help(&d,true,&p,&c,0,0);rtw8852b_set_channel_help(&d,false,&p,&c,0,0);printf("(%u,%u,0x%llx),\n",seed?165:0,count,(unsigned long long)hash);}puts("];");}'''
source=pre+regs+'\n'+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-transition-c-') as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
program,golden=out.removeprefix('PROGRAM\n').split('CASES\n');comment='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux channel helper SHA256 '+hashlib.sha256((body+regs).encode()).hexdigest()+'\n';recipe='pub(super) const RECIPE:[u8;32]=['+','.join(str(v) for v in hashlib.sha256((body+regs).encode()).digest())+'];\n'
for name,value in [('tables.rs',comment+'use super::Step;\n'+recipe+program),('golden.rs',comment+golden)]:
 value=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=value.encode()).decode()
 if a.check:
  if (d/name).read_text()!=value:raise SystemExit(name+' differs')
 else:(d/name).write_text(value)
