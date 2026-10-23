#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent native C oracle; see ORACLE.md. Never writes checked-in goldens."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description="Reproduce the independent complete Linux AR9285 rate-power oracle")
parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
parser.add_argument("--out", type=Path, help="Preserve generated C, provenance and Rust literals here (default: temporary directory)")
parser.add_argument("--cc", default="cc")
args = parser.parse_args()
workspace = tempfile.TemporaryDirectory(prefix="narf-ath9k-rate-oracle-") if args.out is None else None
out = args.out if args.out is not None else Path(workspace.name)
out.mkdir(parents=True, exist_ok=True)
root = args.linux / "drivers/net/wireless/ath/ath9k"
def clean(s):return re.sub(r'/\*.*?\*/','',re.sub(r'//[^\n]*','',s),flags=re.S)
eep=clean((root/'eeprom.h').read_text());source=clean((root/'eeprom.c').read_text());four=clean((root/'eeprom_4k.c').read_text())
def block(text,pattern,post=False):
 m=re.search(pattern,text);assert m,pattern
 at=m.end();depth=1
 while depth:
  depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():text.index(';',at)+1 if post else at]
structs=[];done=set()
def add_struct(name):
 if name in done:return
 done.add(name);s=block(eep,r'struct\s+'+name+r'\s*\{',True)
 for dep in re.findall(r'\bstruct\s+(\w+)\s+\w+',s):
  if dep!=name:add_struct(dep)
 structs.append(s)
for n in ['ar5416_eeprom_4k','cal_data_per_freq','cal_data_per_freq_ar9287']:add_struct(n)
functions='\n'.join(block(source,r'(?:int16_t|u16|bool|void) '+name+r'\s*\([^)]*\)\s*\{') for name in ['ath9k_hw_interpolate','ath9k_hw_get_lower_upper_index','ath9k_hw_fill_vpd_table','ath9k_hw_get_gain_boundaries_pdadcs','ath9k_hw_get_legacy_target_powers','ath9k_hw_get_target_powers','ath9k_hw_get_max_edge_power'])
functions+='\n'+block(four,r'static void ath9k_hw_set_4k_power_cal_table\s*\([^)]*\)\s*\{')
functions+='\n'+block(four,r'static void ath9k_hw_set_4k_power_per_rate_table\s*\([^)]*\)\s*\{')
functions+='\n'+block(four,r'static void ath9k_hw_4k_set_txpower\s*\([^)]*\)\s*\{')
functions=block(eep,r'static inline u16 ath9k_hw_fbin2freq\s*\([^)]*\)\s*\{')+'\n'+functions
structs.append(block(eep,r'enum ar5416_rates\s*\{',True))
headers=clean('\n'.join((root/f).read_text()for f in ['eeprom.h','ar9002_phy.h','reg.h','phy.h','hw.h'])).replace('\\\n',' ')
macros={m.group(1):m.group(0)for m in re.finditer(r'^#define\s+(\w+)([^\n]*)',headers,re.M)}
fixed={'AR_SREV_9287','AR_SREV_9285','AR_SREV_9271','AR_SREV_9280_20_OR_LATER','IS_CHAN_2GHZ','IS_CHAN_HT40','BIT','FREQ2FBIN','MS','SM','REG_READ','REG_WRITE','REG_RMW_FIELD','ENABLE_REG_RMW_BUFFER','REG_RMW_BUFFER_FLUSH','ENABLE_REGWRITE_BUFFER','REGWRITE_BUFFER_FLUSH'}
selected=[];seen=set()
def add_macro(n):
 if n in seen or n in fixed:return
 seen.add(n)
 if n not in macros:return
 d=macros[n]
 for dep in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b',d):
  if dep!=n:add_macro(dep)
 selected.append(d)
 if n+'_S'in macros:add_macro(n+'_S')
for n in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b','\n'.join(structs)+functions):add_macro(n)
pre='''#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int16_t s16;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define SM(v,f) (((u32)(v)<<f##_S)&(f))
#define MS(v,f) (((v)&(f))>>f##_S)
#define AR_SREV_9287(ah) 0
#define AR_SREV_9285(ah) 1
#define AR_SREV_9271(ah) 0
#define AR_SREV_9280_20_OR_LATER(ah) 1
#define IS_CHAN_2GHZ(c) 1
#define IS_CHAN_HT40(c) 0
#define le16_to_cpu(x) (x)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define ar5416_get_ntxchains(m) ((((m)>>2)&1)+(((m)>>1)&1)+((m)&1))
#define FREQ2FBIN(f,b) ((f)-2300)
#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define ath_dbg(...) ((void)0)
'''
mock='''
struct ath9k_channel{u16 frequency;};struct chan_centers{u16 synth_center,ctl_center,ext_center;};
struct ath_regulatory{int max_power_level;};
struct ath_hw{struct{struct ar5416_eeprom_4k map4k;}eeprom;unsigned txchainmask;bool tpc_enabled;struct ath_regulatory regulatory;};struct ath_common{};
static struct ath_regulatory *ath9k_hw_regulatory(struct ath_hw *a){return &a->regulatory;}
static void ar5008_hw_init_rate_txpower(struct ath_hw*a,int16_t*r,struct ath9k_channel*c,int h){}
static struct ath_common *ath9k_hw_common(struct ath_hw *a){return NULL;}
static void ath9k_hw_get_channel_centers(struct ath_hw*a,struct ath9k_channel*c,struct chan_centers*d){d->synth_center=d->ctl_center=c->frequency;}
static u32 registers[0x10000/4];
static u32 rd(u32 r){return registers[r/4];}
static void wr(u32 r,u32 v){registers[r/4]=v;if(r==0x9934||r==0x9938||r==0x993c||r==0xa234||r==0xa238||r==0xa38c||r==0xa390)printf("[0x%04x,0x%08x],\\n",r,v);}
#define REG_READ(ah,r) rd(r)
#define REG_WRITE(ah,r,v) wr(r,v)
#define REG_RMW_FIELD(ah,r,f,v) wr(r,(rd(r)&~(f))|(((u32)(v)<<f##_S)&(f)))
#define ENABLE_REG_RMW_BUFFER(ah) do{}while(0)
#define REG_RMW_BUFFER_FLUSH(ah) do{}while(0)
#define ENABLE_REGWRITE_BUFFER(ah) do{}while(0)
#define REGWRITE_BUFFER_FLUSH(ah) do{}while(0)
static u32 get_unaligned_le32(const void *p){u32 v;memcpy(&v,p,4);return v;}
static u16 ath9k_hw_4k_get_eeprom_rev(struct ath_hw*ah){return ah->eeprom.map4k.baseEepHeader.version&0xfff;}
'''
main='''
int main(void){
 printf("//cck=%zu ofdm=%zu ht20=%zu ht40=%zu ctlIndex=%zu ctlData=%zu antenna=%zu\\n",offsetof(struct ar5416_eeprom_4k,calTargetPowerCck),offsetof(struct ar5416_eeprom_4k,calTargetPower2G),offsetof(struct ar5416_eeprom_4k,calTargetPower2GHT20),offsetof(struct ar5416_eeprom_4k,calTargetPower2GHT40),offsetof(struct ar5416_eeprom_4k,ctlIndex),offsetof(struct ar5416_eeprom_4k,ctlData),offsetof(struct ar5416_eeprom_4k,modalHeader.antennaGainCh));
 for(unsigned scenario=0;scenario<9;scenario++){
  struct ath_hw ah={.txchainmask=1};struct ath9k_channel channel={.frequency=(u16[]){2412,2422,2437,2442,2462,2467,2412,2407,2442}[scenario]};
  struct ar5416_eeprom_4k *e=&ah.eeprom.map4k;
  e->baseEepHeader.version=0xe002;e->baseEepHeader.txMask=1;e->baseEepHeader.regDmn[0]=0x64;
  e->modalHeader.xpdGain=12;e->modalHeader.pdGainOverlap=2;e->modalHeader.antennaGainCh[0]=scenario==8?6:0;
  for(unsigned p=0;p<3;p++){
   e->calFreqPier2G[p]=112+p*25;
   e->calTargetPowerCck[p].bChannel=112+p*25;e->calTargetPower2G[p].bChannel=112+p*25;
   e->calTargetPower2GHT20[p].bChannel=112+p*25;e->calTargetPower2GHT40[p].bChannel=255;
   for(unsigned r=0;r<4;r++){e->calTargetPowerCck[p].tPow2x[r]=32+p*2+r;e->calTargetPower2G[p].tPow2x[r]=36+p*2+r;}
   for(unsigned r=0;r<8;r++)e->calTargetPower2GHT20[p].tPow2x[r]=34+p*2+r;
   for(unsigned g=0;g<2;g++)for(unsigned i=0;i<5;i++){
    e->calPierData2G[0][p].pwrPdg[g][i]=8+g*20+i*4+p*2;
    e->calPierData2G[0][p].vpdPdg[g][i]=20+g*50+i*15+p*3;
   }
  }
  for(unsigned i=0;i<6;i++){
   e->ctlIndex[i]=(i<3?0x10:0x30)+(u8[]){1,2,5}[i%3];
   for(unsigned j=0;j<4;j++){
    e->ctlData[i].ctlEdges[0][j].bChannel=j<3?112+j*25:255;
    e->ctlData[i].ctlEdges[0][j].ctl=((i<3?18:6)+i*2+j*3)|(j==0?64:0);
   }
  }
  unsigned ctl=scenario==5||scenario==7?0xe2:0x12;
  unsigned limit=scenario==6?0:scenario==5?32:40;
  printf("const RATE_GOLDEN_%u:&[[u32;2]]=&[\\n",scenario);
  ath9k_hw_4k_set_txpower(&ah,&channel,ctl,e->modalHeader.antennaGainCh[0],limit,false);puts("];");
  printf("const RATE_EEPROM_%u:&[u8]=&[",scenario);for(size_t i=0;i<sizeof(*e);i++)printf("0x%02x,",((u8*)e)[i]);puts("];");
 }
}
'''
(out/'oracle.c').write_text(pre+'\n'.join(selected)+'\n'+'\n'.join(structs)+mock+functions+main)

# Hash the actual files and the complete mechanically extracted C functions.
# Comments are removed before extraction; algorithm bodies are not rewritten.
function_hashes = {}
for name in ["ath9k_hw_fbin2freq", "ath9k_hw_interpolate", "ath9k_hw_get_lower_upper_index", "ath9k_hw_fill_vpd_table", "ath9k_hw_get_gain_boundaries_pdadcs", "ath9k_hw_get_legacy_target_powers", "ath9k_hw_get_target_powers", "ath9k_hw_get_max_edge_power", "ath9k_hw_set_4k_power_cal_table", "ath9k_hw_set_4k_power_per_rate_table", "ath9k_hw_4k_set_txpower"]:
    match = re.search(r"\b" + name + r"\s*\([^;{]*\)\s*\{", functions)
    assert match, name
    end = match.end()
    depth = 1
    while depth:
        depth += (functions[end] == "{") - (functions[end] == "}")
        end += 1
    begin = functions.rfind("\n", 0, match.start()) + 1
    function_hashes[name] = hashlib.sha256(functions[begin:end].encode()).hexdigest()
provenance = {
    "reference": "local Linux drivers/net/wireless/ath/ath9k",
    "extraction": "Complete native C function bodies after mechanical comment removal; native packed structs and register/EEPROM macro dependencies.",
    "sources": {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ["eeprom.h", "eeprom.c", "eeprom_4k.c", "ar9002_phy.h", "reg.h", "phy.h", "hw.h"]},
    "extracted_function_sha256": function_hashes,
}
(out/'provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True)+'\n')
expected_provenance = Path(__file__).with_name('linux_oracle_provenance.json')
if expected_provenance.exists() and json.loads(expected_provenance.read_text()) != provenance:
    raise SystemExit("Linux source/function provenance changed; inspect generated provenance.json before updating reference literals")
subprocess.run([args.cc, '-std=gnu11', '-O2', str(out/'oracle.c'), '-o', str(out/'oracle')], check=True)
generated = subprocess.check_output([str(out/'oracle')], text=True)
(out/'golden.rs').write_text(generated)
expected = Path(__file__).with_name('golden.rs').read_text()
# Compare literal tokens, allowing rustfmt whitespace and provenance comments.
compact = lambda text: re.sub(r"\s+", "", clean(text))
if compact(generated) != compact(expected):
    raise SystemExit("Linux oracle output differs from checked-in golden.rs; generated literals are preserved only under --out")
print("PASS: all 9 native Linux rate/EEPROM scenarios match checked-in literals")
