#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Original Linux AR9285 calibration traces/numeric oracle; no golden rewrites."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux', type=Path, default=Path('/usr/src/linux'))
p.add_argument('--out', type=Path)
p.add_argument('--cc', default='cc')
args = p.parse_args()
temporary = tempfile.TemporaryDirectory(prefix='narf-ath9k-calibration-') if args.out is None else None
out = args.out if args.out is not None else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
root = args.linux/'drivers/net/wireless/ath/ath9k'
names = ['ar9002_calib.c','ar9002_hw.c','ar5008_phy.c','calib.c','hw.c',
         'ar9002_initvals.h','reg.h','ar9002_phy.h','phy.h','hw.h','calib.h','eeprom.h']
sources = {name:(root/name).read_text() for name in names}
def clean(s):
    return re.sub(r'/\*.*?\*/|//[^\n]*','',s,flags=re.S)
def block(s,pattern,semicolon=False):
    m=re.search(pattern,s)
    assert m,pattern
    at=m.end()
    depth=1
    while depth:
        depth+=(s[at]=='{')-(s[at]=='}')
        at+=1
    return s[m.start():s.index(';',at)+1 if semicolon else at]
owners = [('hw.c','ath9k_hw_synth_delay'),('ar5008_phy.c','ar5008_hw_init_bb'),
          ('ar9002_hw.c','ar9002_hw_configpcipowersave'),
          ('ar9002_calib.c','ar9285_hw_cl_cal'),('ar9002_calib.c','ar9285_hw_clc'),
          ('ar9002_calib.c','ar9285_hw_pa_cal'),
          ('calib.c','ath9k_hw_loadnf'),('calib.c','ath9k_hw_start_nfcal'),
          ('ar9002_calib.c','ar9002_hw_setup_calibration'),
          ('ar9002_calib.c','ar9002_hw_iqcal_collect'),('ar9002_calib.c','ar9002_hw_iqcalibrate')]
functions=[block(clean(sources[file]),r'(?:static\s+)?(?:inline\s+)?(?:void|int|bool)\s+'+name+r'\s*\([^)]*\)\s*\{') for file,name in owners]
array=block(clean(sources['ar9002_initvals.h']),r'static const u32 ar9280PciePhy_clkreq_always_on_L1_9280\[\]\[2\]\s*=\s*\{',True)
enums=block(clean(sources['ar9002_calib.c']),r'enum ar9002_cal_types\s*\{',True)
headers=clean('\n'.join(sources.values())).replace('\\\n',' ')
macros={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)([^\n]*)',headers,re.M)}
fixed={'BIT','ARRAY_SIZE','IS_CHAN_HT20','IS_CHAN_HT40','IS_CHAN_HALF_RATE','IS_CHAN_QUARTER_RATE',
       'AR_SREV_9280_20_OR_LATER','AR_SREV_9280','AR_SREV_9285','AR_SREV_9271','AR_SREV_9287','AR_SREV_9285E_20','AR_SREV_9340','AR_SREV_9300_20_OR_LATER',
       'REG_READ','REG_WRITE','REG_RMW','REG_RMW_FIELD','REG_SET_BIT','REG_CLR_BIT','SM','MS',
       'ENABLE_REGWRITE_BUFFER','REGWRITE_BUFFER_FLUSH','ENABLE_REG_RMW_BUFFER','REG_RMW_BUFFER_FLUSH',
       'INI_RA','EEP_TXGAIN_TYPE','NFCAL_PENDING','set_bit'}
selected=[]
seen=set()
def macro(name):
    if name in seen or name in fixed:return
    seen.add(name)
    if name not in macros:return
    body=macros[name]
    for dep in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b',body):
        if dep!=name:macro(dep)
    selected.append(body)
    if name+'_S' in macros:macro(name+'_S')
for name in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b','\n'.join(functions+[array,enums])):macro(name)
macro('AR_PHY_CCA')
prefix=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int16_t s16;typedef uint32_t u_int32_t;
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define SM(v,f) (((u32)(v)<<f##_S)&(f))
#define MS(v,f) (((v)&(f))>>f##_S)
#define IS_CHAN_HT20(c) 1
#define IS_CHAN_HT40(c) 0
#define IS_CHAN_HALF_RATE(c) 0
#define IS_CHAN_QUARTER_RATE(c) 0
#define AR_SREV_9280_20_OR_LATER(a) 1
#define AR_SREV_9285(a) 1
#define AR_SREV_9280(a) 0
#define AR_SREV_9271(a) 0
#define AR_SREV_9287(a) 0
#define AR_SREV_9340(a) 0
#define AR_SREV_9300_20_OR_LATER(a) 0
#define AR_SREV_9285E_20(a) ((a)->xe2)
#define ENABLE_REGWRITE_BUFFER(a) ((void)0)
#define REGWRITE_BUFFER_FLUSH(a) ((void)0)
#define ENABLE_REG_RMW_BUFFER(a) ((void)0)
#define REG_RMW_BUFFER_FLUSH(a) ((void)0)
#define ath_dbg(...) ((void)0)
#define EEP_TXGAIN_TYPE 0
#define NFCAL_PENDING 0
#define set_bit(...) ((void)0)
#define ETIMEDOUT 110
'''
model=r'''
struct ath_common{};struct ath9k_channel{};
struct ar5416IniArray{const u32 (*ia_array)[2];u32 ia_rows;};
#define INI_RA(a,r,c) ((a)->ia_array[r][c])
struct ath_hw;
struct eep_ops{u32(*get_eeprom)(struct ath_hw*,int);};
struct ath_nf_limits{s16 nominal,cal[6];};
struct ath9k_nfcal_hist{s16 privNF;};
struct cal_data{struct ath9k_nfcal_hist nfCalHist[6];unsigned cal_flags;};
struct ath9k_percal_data{u32 calType,calCountMax;};
struct ath9k_cal_list{struct ath9k_percal_data *calData;};
struct ath_hw {
 bool xe2,high;unsigned rxchainmask;struct eep_ops*eep_ops;struct ar5416IniArray iniPcieSerdes;
 struct{u32 pcie_waen;}config;struct{u32 prev_offset,max_skipcount,skipcount;}pacal_info;
 struct cal_data*caldata;s16 nf_override;u32 nf_regs[6];struct ath_nf_limits nf_2g;
 u32 totalPowerMeasI[3],totalPowerMeasQ[3],totalIqCorrMeas[3];
};
static struct ath_common*ath9k_hw_common(struct ath_hw*a){return NULL;}
static struct ath_nf_limits*ath9k_hw_get_nf_limits(struct ath_hw*a,struct ath9k_channel*c){return &a->nf_2g;}
static u32 eeprom(struct ath_hw*a,int id){return a->high;}
static u32 regs[0x10000/4];static bool retry;static unsigned spare,count;static uint64_t hash;
static void rec(u32 kind,u32 a,u32 b){count++;u32 v[]={kind,a,b};for(int j=0;j<3;j++)for(int i=0;i<4;i++)hash=(hash^((v[j]>>(8*i))&255))*UINT64_C(0x100000001b3);}
static u32 rd(u32 r){
 if(r==0x9860){u32 old=regs[r/4];regs[r/4]&=~3U;if((old&2)&&(old&0x8000))regs[0x9864/4]=(regs[0x9864/4]&~0x1ff00000U)|(((-115U)&511)<<20);}
 if(r==0x9920)regs[r/4]&=~0x10000U;
 if(r==0x7840){u32 bit=(0x5b>>(6-(spare++%7)))&1;return (regs[r/4]&~1U)|bit;}
 if(r>=0xa35c&&r<0xa39c)return retry?0:0x00410020;
 return regs[r/4];
}
static void wr(u32 r,u32 v){rec(0,r,v);if(r==0x7868)v=(v&~7U)|(regs[r/4]&7U);regs[r/4]=v;}
static void delay(u32 us){rec(1,us,0);}
#define REG_READ(a,r) rd(r)
#define REG_WRITE(a,r,v) wr(r,v)
#define REG_RMW(a,r,s,c) wr(r,(rd(r)&~(c))|(s))
#define REG_SET_BIT(a,r,b) wr(r,rd(r)|(b))
#define REG_CLR_BIT(a,r,b) wr(r,rd(r)&~(b))
#define REG_RMW_FIELD(a,r,f,v) wr(r,(rd(r)&~(f))|(((u32)(v)<<f##_S)&(f)))
#define udelay(us) delay(us)
static bool ath9k_hw_wait(struct ath_hw*a,u32 r,u32 mask,u32 expected,u32 timeout){return (rd(r)&mask)==expected;}
'''
main=r'''
int main(void){
 struct eep_ops ops={eeprom};struct ath9k_channel channel={};
 printf("pub const CALIBRATION_CASES:&[(bool,bool,bool,u32,u32,u32,u64)]=&[\n");
 for(int xe=0;xe<2;xe++)for(int high=0;high<2;high++)for(int redo=0;redo<2;redo++)for(int seedcase=0;seedcase<2;seedcase++)for(int negative=0;negative<2;negative++){
  struct ath_hw a={0};a.xe2=xe;a.high=high;a.rxchainmask=1;a.eep_ops=&ops;a.nf_2g.nominal=-118;a.nf_regs[0]=AR_PHY_CCA;
  a.iniPcieSerdes=(struct ar5416IniArray){ar9280PciePhy_clkreq_always_on_L1_9280,10};
  u32 seed=seedcase?0x5a93a5c3:0;
  for(unsigned i=0;i<ARRAY_SIZE(regs);i++)regs[i]=seed?seed^(i*4):0;
  regs[0x9860/4]&=~3U;regs[0x9920/4]&=~0x10000U;regs[0x7868/4]=(regs[0x7868/4]&~7U)|xe;
  regs[0xa274/4]=(regs[0xa274/4]&~0x7e000U)|(3<<13);
  for(unsigned i=0;i<4;i++)regs[(0xa300+i*4)/4]=(i<<1);
  regs[0x9c10/4]=20000;regs[0x9c14/4]=16000;regs[0x9c18/4]=negative?-1400:1400;
  retry=redo;spare=0;count=0;hash=UINT64_C(0xcbf29ce484222325);
  ar9002_hw_configpcipowersave(&a,false);
  ar5008_hw_init_bb(&a,&channel);
  if(!ar9285_hw_clc(&a,&channel))return 1;
  ar9285_hw_pa_cal(&a,true);
  if(ath9k_hw_loadnf(&a,&channel))return 2;
  ath9k_hw_start_nfcal(&a,true);
  if(!ath9k_hw_wait(&a,AR_PHY_AGC_CONTROL(&a),AR_PHY_AGC_CONTROL_NF,0,222000))return 3;
  struct ath9k_percal_data data={IQ_MISMATCH_CAL,10};struct ath9k_cal_list cal={&data};
  ar9002_hw_setup_calibration(&a,&cal);
  if(!ath9k_hw_wait(&a,AR_PHY_TIMING_CTRL4(0),AR_PHY_TIMING_CTRL4_DO_CAL,0,30000000))return 4;
  ar9002_hw_iqcal_collect(&a);ar9002_hw_iqcalibrate(&a,1);
  printf("(%s,%s,%s,0x%08x,0x%08x,%u,0x%016llx),\n",xe?"true":"false",high?"true":"false",redo?"true":"false",seed,negative?-1400U:1400U,count,(unsigned long long)hash);
 }
 printf("];\n");
 printf("pub const IQ_CASES:&[(u32,u32,u32,u8,u8)]=&[\n");
 u32 powers[][2]={{1280,8192},{16000,16000},{20000,16000},{16000,32768},{0xffffffff,64},{128,128},{32768,1024}};
 u32 correlations[]={0,1400,-1400U,0x80000000,0xffffffff};
 for(unsigned p=0;p<ARRAY_SIZE(powers);p++)for(unsigned c=0;c<ARRAY_SIZE(correlations);c++){
  struct ath_hw a={0};a.totalPowerMeasI[0]=powers[p][0];a.totalPowerMeasQ[0]=powers[p][1];a.totalIqCorrMeas[0]=correlations[c];
  regs[0x9920/4]=0;ar9002_hw_iqcalibrate(&a,1);
  printf("(0x%08x,0x%08x,0x%08x,%u,%u),\n",powers[p][0],powers[p][1],correlations[c],(regs[0x9920/4]>>5)&63,regs[0x9920/4]&31);
 }
 printf("];\n");return 0;
}
'''
code=prefix+'\n'.join(selected)+'\n'+array+'\n'+enums+model+'\n'.join(functions)+main
path=out/'calibration-oracle.c'
path.write_text(code)
subprocess.run([args.cc,'-std=gnu11','-O2','-fwrapv','-w',str(path),'-o',str(out/'calibration-oracle')],check=True)
result=subprocess.check_output([str(out/'calibration-oracle')],text=True)
(out/'golden.rs').write_text(result)
(out/'provenance.json').write_text(json.dumps({
    'sources':{name:hashlib.sha256(sources[name].encode()).hexdigest() for name in names},
    'functions':{name:hashlib.sha256(body.encode()).hexdigest() for (_,name),body in zip(owners,functions)},
    'profile':'AR9285 20MHz single-chain; xe2/high-gain/CLC retry/register seed/correlation sign, 32 cases; fast self-clearing completion model',
},indent=2)+'\n')
print(result,end='')
