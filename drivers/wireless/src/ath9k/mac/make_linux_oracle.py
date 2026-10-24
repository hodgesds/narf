#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile complete original Linux AR9285 MAC/DMA/queue functions."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux'))
p.add_argument('--out',type=Path)
args=p.parse_args()
scratch=tempfile.TemporaryDirectory(prefix='narf-ar9285-mac-') if args.out is None else None
out=args.out or Path(scratch.name)
out.mkdir(parents=True,exist_ok=True)
root=args.linux/'drivers/net/wireless/ath/ath9k'
sources={name:(root/name).read_text() for name in ['hw.c','mac.c','mac.h','hw.h','reg.h','../reg.h']}
def clean(s):return re.sub(r'/\*.*?\*/|//[^\n]*','',s,flags=re.S)
def block(s,pattern,semi=False):
 m=re.search(pattern,s);assert m,pattern
 end=m.end();depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[m.start():s.index(';',end)+1 if semi else end]
owners=[('mac.c','ath9k_hw_set_txq_interrupts'),('mac.c','ath9k_hw_clear_queue_interrupts'),
 ('mac.c','ath9k_hw_resettxqueue'),('hw.c','ath9k_hw_set_dma'),('hw.c','ath9k_hw_init_qos'),
 ('hw.c','ath9k_hw_set_operating_mode'),('hw.c','ath9k_hw_init_mfp')]
functions=[block(clean(sources[file]),r'(?:static\s+)?(?:inline\s+)?(?:void|bool)\s+'+name+r'\s*\([^)]*\)\s*\{')for file,name in owners]
header=clean(sources['mac.h'])
structs='\n'.join(block(header,r'(?:enum|struct) '+name+r'\s*\{',True)for name in ['ath9k_tx_queue','ath9k_tx_queue_flags','ath9k_tx_queue_info'])
headers=clean('\n'.join(sources.values())).replace('\\\n',' ')
macros={m.group(1):m.group(0)for m in re.finditer(r'^#define\s+(\w+)[^\n]*',headers,re.M)}
fixed={'BIT','SM','MS','AR_DEVID_7010','ENABLE_REGWRITE_BUFFER','REGWRITE_BUFFER_FLUSH','ENABLE_REG_RMW_BUFFER','REG_RMW_BUFFER_FLUSH',
 'REG_READ','REG_WRITE','REG_RMW','REG_RMW_FIELD','REG_SET_BIT','REG_CLR_BIT'}
selected=[];seen=set()
def macro(name):
 if name in seen or name in fixed or name.startswith('AR_SREV_'):return
 seen.add(name)
 if name not in macros:return
 for dep in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b',macros[name]):
  if dep!=name:macro(dep)
 selected.append(macros[name])
 if name+'_S' in macros:macro(name+'_S')
for name in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b','\n'.join(functions)+structs):macro(name)
srevs=set(re.findall(r'\bAR_SREV_\w+','\n'.join(functions+selected)))
prefix=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define SM(v,f) (((u32)(v)<<f##_S)&(f))
#define MS(v,f) (((v)&(f))>>f##_S)
#define ENABLE_REGWRITE_BUFFER(a) ((void)0)
#define REGWRITE_BUFFER_FLUSH(a) ((void)0)
#define ENABLE_REG_RMW_BUFFER(a) ((void)0)
#define REG_RMW_BUFFER_FLUSH(a) ((void)0)
#define ath_dbg(...) ((void)0)
#define ath_err(...) ((void)0)
#define fallthrough ((void)0)
#define NL80211_IFTYPE_ADHOC 1
#define NL80211_IFTYPE_OCB 2
#define NL80211_IFTYPE_MESH_POINT 3
#define NL80211_IFTYPE_AP 4
#define NL80211_IFTYPE_STATION 5
#define AR_DEVID_7010(a) 0
struct ath_common {u32 rx_bufsize;};
static struct ath_common common;
static struct ath_common*ath9k_hw_common(void*a){return &common;}
static u32 regs[0x10000/4],count;static uint64_t hash;
static u32 rd(u32 r){return regs[r/4];}
static void wr(u32 r,u32 v){count++;u32 vals[]={r,v};for(unsigned j=0;j<2;j++)for(unsigned i=0;i<4;i++)hash=(hash^((vals[j]>>(8*i))&255))*UINT64_C(0x100000001b3);regs[r/4]=v;}
#define REG_READ(a,r) rd(r)
#define REG_WRITE(a,r,v) wr(r,v)
#define REG_RMW(a,r,s,c) wr(r,(rd(r)&~(c))|(s))
#define REG_RMW_FIELD(a,r,f,v) wr(r,(rd(r)&~(f))|(((u32)(v)<<f##_S)&(f)))
#define REG_SET_BIT(a,r,b) wr(r,rd(r)|(b))
#define REG_CLR_BIT(a,r,b) wr(r,rd(r)&~(b))
'''
model=r'''
struct ath_hw {
 u32 txok_interrupt_mask,txerr_interrupt_mask,txdesc_interrupt_mask,txeol_interrupt_mask,txurn_interrupt_mask,imrs2_reg;
 u32 opmode,tx_trig_level;bool is_monitoring,sw_mgmt_crypto_tx,sw_mgmt_crypto_rx;
 struct{u32 rx_status_len;}caps;
 struct{u32 sw_beacon_response_time,dma_beacon_response_time;}config;
 struct ath9k_tx_queue_info txq[10];
};
static void ath9k_hw_set_rx_bufsize(struct ath_hw*a,u32 n){}
static void ath9k_hw_reset_txstatus_ring(struct ath_hw*a){}
'''
main=r'''
int main(void){
 printf("pub const MAC_CASES: &[(u8,u32,u32,u64)] = &[\n");
 for(unsigned kind=0;kind<5;kind++)for(unsigned seeded=0;seeded<2;seeded++){
  u32 seed=seeded?0x5a93a5c3:0;for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++)regs[i]=seed?seed^(i*4):0;
  count=0;hash=UINT64_C(0xcbf29ce484222325);struct ath_hw a={0};a.opmode=NL80211_IFTYPE_STATION;a.tx_trig_level=4;a.imrs2_reg=rd(AR_IMR_S2);
  a.txq[0]=(struct ath9k_tx_queue_info){.tqi_type=ATH9K_TX_QUEUE_DATA,.tqi_aifs=2,.tqi_cwmin=31,.tqi_cwmax=1023,.tqi_shretry=10};
  if(kind==0)ath9k_hw_resettxqueue(&a,0);
  if(kind==1)ath9k_hw_init_qos(&a);
  if(kind==2)ath9k_hw_set_dma(&a);
  if(kind==3)ath9k_hw_set_operating_mode(&a,a.opmode);
  if(kind==4)ath9k_hw_init_mfp(&a);
  printf("(%u,0x%08x,%u,0x%016llx),\n",kind,seed,count,(unsigned long long)hash);
 }printf("];\n");return 0;
}
'''
flags='\n'.join('#define '+name+'(a) '+('1'if name in {'AR_SREV_9285','AR_SREV_9280_20_OR_LATER'}else'0')for name in sorted(srevs))
unit=prefix+flags+'\n'+'\n'.join(selected)+'\n'+structs+'\n'+model+'\n'+'\n'.join(functions)+'\n'+main
(out/'original.c').write_text(unit)
subprocess.run(['cc','-std=gnu11','-Werror',str(out/'original.c'),'-o',str(out/'oracle')],check=True)
result=subprocess.run([str(out/'oracle')],check=True,capture_output=True,text=True)
(out/'golden.rs').write_text('// Extracted complete original Linux C; no Rust encoder is used.\n'+result.stdout)
(out/'provenance.json').write_text(json.dumps({'sources':{k:hashlib.sha256(v.encode()).hexdigest()for k,v in sources.items()},'functions':{name:hashlib.sha256(body.encode()).hexdigest()for(_,name),body in zip(owners,functions)}},indent=2)+'\n')
print(out/'golden.rs')
