#!/usr/bin/env python3
"""Run original B channel1/20MHz RF synthesizer, including real LCK recovery."""
from pathlib import Path
import argparse,re,hashlib,tempfile,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;s=(a.linux/'rtw8852b_rfk.c').read_text();h=(a.linux/'reg.h').read_text()
def f(n):
 m=re.search(r'^(?:static\s+)?(?:void|bool)\s+'+n+r'\s*\(',s,re.M);e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]+'\n'
names=['_bw_setting','_ctrl_bw','_set_s0_arfc18','_lck_check','_set_ch','_ch_setting','_ctrl_ch','_set_rxbb_bw','_rxbb_bw','rtw8852b_ctrl_bw_ch']
body=''
for n in names:
 text=f(n)
 if n=='_lck_check':
  text=text.replace('_lck_check(', '_lck_check_original(',1)
  text+='static void _lck_check(struct rtw89_dev*d){_lck_check_original(d);assert(rtw89_read_rf(d,RF_PATH_A,RR_SYNFB,RR_SYNFB_LK));}\n'
 body+=text
names=set(re.findall(r'\b(?:RR_[A-Z0-9_]+|RFREG_MASK|INV_RF_DATA|CFGCH_[A-Z0-9_]+)\b',body));defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',h+'\n'+(a.linux/'core.h').read_text(),re.M)};todo=list(names)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in names:names.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(names))
pre=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
enum rtw89_rf_path{RF_PATH_A,RF_PATH_B};enum rtw89_phy_idx{PHY0};enum rtw89_band{BAND2G};enum rtw89_bandwidth{RTW89_CHANNEL_WIDTH_5,RTW89_CHANNEL_WIDTH_10,RTW89_CHANNEL_WIDTH_20,RTW89_CHANNEL_WIDTH_40,RTW89_CHANNEL_WIDTH_80};
#define RF_PATH_NUM_8852B 2
#define rtw89_debug(...) ((void)0)
struct rtw89_dev{u32 rf[2][512];u32 lock_after,lock_reads,busy,busy_left;};
static u64 hash;static u32 count;
static void byte(u8 v){hash^=v;hash*=1099511628211ULL;}
static void val(u32 v){for(int i=0;i<4;i++)byte(v>>(i*8));}
static void record(u32 k,u32 p,u32 a,u32 m,u32 v){count++;val(k);val(p);val(a);val(m);val(v);}
static u32 slot(u32 a){return (a&255)|((a&0x10000)?256:0);}
'''
shim=r'''static u32 rtw89_read_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m){u32 v=d->rf[p][slot(a)];if(a==RR_SYNFB&&m==RR_SYNFB_LK){d->lock_reads++;v=(v&~m)|(d->lock_reads>d->lock_after?m:0);}if(a==RR_LPF&&m==RR_LPF_BUSY){v=(v&~m)|(d->busy_left?m:0);if(d->busy_left)d->busy_left--;}v=FIELD_GET(m,v);record(32,p,a,m,v);return v;}
static bool rtw89_write_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m,u32 v){d->rf[p][slot(a)]=(d->rf[p][slot(a)]&~m)|FIELD_PREP(m,v);if(p==0&&a==RR_CFGCH)d->busy_left=d->busy;record(16,p,a,m,v);return true;}
static void udelay(u32 us){count++;val(8);val(us);}
static u8 _kpath(struct rtw89_dev*d,int p){assert(p==0);return 3;}
#define read_poll_timeout_atomic(op,v,cond,step,budget,pre,...) ({int err=-ETIMEDOUT;for(u32 t=0;t<=budget;t+=step){v=op(__VA_ARGS__);if(cond){err=0;break;}if(t<budget)udelay(step);}err;})
'''
main=r'''int main(void){puts("REGS");'''+''.join('printf("pub(super) const '+n+': u32 = 0x%x;\\n",(u32)'+n+');\n' for n in sorted(names))+r'''
puts("CASES\npub(super) const CASES: &[(u8,u8,u8,u32,u64)] = &[");for(int seed=0;seed<2;seed++)for(int lock=0;lock<4;lock++)for(int busy=0;busy<2;busy++){
 struct rtw89_dev d={.lock_after=lock,.busy=busy?2:0};for(int p=0;p<2;p++)for(int i=0;i<512;i++)d.rf[p][i]=seed?(0x5a5a5a&RFREG_MASK):0;
 hash=14695981039346656037ULL;count=0;rtw8852b_ctrl_bw_ch(&d,0,1,0,RTW89_CHANNEL_WIDTH_20);
 u32 mask=RR_CFGCH_CH|RR_CFGCH_BAND0|RR_CFGCH_BAND1|RR_CFGCH_BW|RR_CFGCH_BW2|RR_CFGCH_POW_LCK|RR_CFGCH_TRX_AH|RR_CFGCH_BCN;
 u32 expected=FIELD_PREP(RR_CFGCH_CH,1)|FIELD_PREP(RR_CFGCH_BW,CFGCH_BW_20M)|RR_CFGCH_BW2;
 for(int direct=0;direct<2;direct++)for(int p=0;p<2;p++){u32 value=rtw89_read_rf(&d,p,direct?RR_CFGCH_V1:RR_CFGCH,RFREG_MASK);assert((value&mask)==expected);}
 printf("(%u,%u,%u,%u,0x%llx),\n",seed?90:0,lock,busy?2:0,count,(unsigned long long)hash);
}puts("];" );}'''
source=pre+regs+'\n'+shim+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-rfchannel-c-') as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
reg_out,cases=out.removeprefix('REGS\n').split('CASES\n');comment='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B RF channel SHA256 '+hashlib.sha256((body+regs).encode()).hexdigest()+'\n'
for name,value in [('regs.rs',comment+reg_out),('golden.rs',comment+cases)]:
 if a.check:
  if (d/name).read_text()!=value:raise SystemExit(name+' differs')
 else:(d/name).write_text(value)
