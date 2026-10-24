#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile original Linux AR9285 channel functions; never overwrite goldens."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--linux', type=Path, default=Path('/usr/src/linux'))
parser.add_argument('--out', type=Path)
parser.add_argument('--cc', default='cc')
args = parser.parse_args()
temporary = tempfile.TemporaryDirectory(prefix='narf-ath9k-channel-') if args.out is None else None
out = args.out if args.out is not None else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
root = args.linux / 'drivers/net/wireless/ath/ath9k'
files = ['ar5008_phy.c', 'ar9002_phy.c', 'hw.c', 'eeprom_4k.c', 'eeprom.h',
         'ar9002_phy.h', 'reg.h', 'phy.h', 'hw.h']
original = {name: (root / name).read_text() for name in files}

def clean(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)

def block(text, pattern, declaration=False):
    match = re.search(pattern, text)
    assert match, pattern
    at = match.end()
    depth = 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():text.index(';', at) + 1 if declaration else at]

structures = []
seen_structs = set()
def structure(name):
    if name in seen_structs:
        return
    seen_structs.add(name)
    body = block(clean(original['eeprom.h']), r'struct\s+' + name + r'\s*\{', True)
    for dep in re.findall(r'\bstruct\s+(\w+)\s+\w+', body):
        if dep != name:
            structure(dep)
    structures.append(body)
structure('ar5416_eeprom_4k')

owners = [
    ('hw.c', 'ath9k_hw_get_delta_slope_vals'),
    ('hw.c', 'ath9k_hw_set11nmac2040'),
    ('eeprom_4k.c', 'ath9k_hw_4k_get_spur_channel'),
    ('ar5008_phy.c', 'ar5008_hw_cmn_spur_mitigate'),
    ('ar5008_phy.c', 'ar5008_hw_init_chain_masks'),
    ('ar5008_phy.c', 'ar5008_hw_override_ini'),
    ('ar5008_phy.c', 'ar5008_hw_set_channel_regs'),
    ('ar5008_phy.c', 'ar5008_hw_set_rfmode'),
    ('ar5008_phy.c', 'ar5008_hw_set_delta_slope'),
    ('ar9002_phy.c', 'ar9002_hw_set_channel'),
    ('ar9002_phy.c', 'ar9002_hw_spur_mitigate'),
]
functions = [block(clean(original[file]), r'(?:static\s+)?(?:void|int|u16)\s+' + name + r'\s*\([^)]*\)\s*\{')
             for file, name in owners]
headers = clean('\n'.join(original[name] for name in files if name.endswith('.h'))).replace('\\\n', ' ')
macros = {m.group(1): m.group(0) for m in re.finditer(r'^#define\s+(\w+)([^\n]*)', headers, re.M)}
fixed = {'IS_CHAN_2GHZ', 'IS_CHAN_5GHZ', 'IS_CHAN_HT40', 'IS_CHAN_HT40PLUS',
         'IS_CHAN_HALF_RATE', 'IS_CHAN_QUARTER_RATE', 'IS_CHAN_A_FAST_CLOCK',
         'REG_READ', 'REG_WRITE', 'REG_RMW', 'REG_RMW_FIELD', 'REG_SET_BIT',
         'REG_CLR_BIT', 'SM', 'MS', 'BIT', 'ARRAY_SIZE', 'REG_WRITE_ARRAY',
         'ENABLE_REGWRITE_BUFFER', 'REGWRITE_BUFFER_FLUSH', 'ENABLE_REG_RMW_BUFFER',
         'REG_RMW_BUFFER_FLUSH', 'AR_SREV_9280_20_OR_LATER', 'AR_SREV_9285_12_OR_LATER',
         'AR_SREV_9287_11_OR_LATER', 'AR_SREV_9271', 'AR_SREV_9100', 'AR_SREV_9160',
         'AR_SREV_REVISION_5416_10'}
selected = []
seen = set()
def macro(name):
    if name in seen or name in fixed:
        return
    seen.add(name)
    if name not in macros:
        return
    text = macros[name]
    for dep in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b', text):
        if dep != name:
            macro(dep)
    selected.append(text)
    if name + '_S' in macros:
        macro(name + '_S')
for name in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b', '\n'.join(structures + functions)):
    macro(name)

prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define SM(v,f) (((u32)(v)<<f##_S)&(f))
#define MS(v,f) (((v)&(f))>>f##_S)
#define AR_SREV_9280_20_OR_LATER(a) 1
#define AR_SREV_9285_12_OR_LATER(a) 1
#define AR_SREV_9287_11_OR_LATER(a) 0
#define AR_SREV_9271(a) 0
#define AR_SREV_9100(a) 0
#define AR_SREV_9160(a) 0
#define AR_SREV_REVISION_5416_10 0xff
#define IS_CHAN_2GHZ(c) 1
#define IS_CHAN_5GHZ(c) 0
#define IS_CHAN_HT40(c) 0
#define IS_CHAN_HT40PLUS(c) 0
#define IS_CHAN_HALF_RATE(c) 0
#define IS_CHAN_QUARTER_RATE(c) 0
#define IS_CHAN_A_FAST_CLOCK(a,c) 0
#define EEP_FRAC_N_5G 0
#define le16_to_cpu(v) (v)
#define fallthrough __attribute__((fallthrough))
#define REG_WRITE_ARRAY(...) ((void)0)
#define ENABLE_REGWRITE_BUFFER(a) ((void)0)
#define REGWRITE_BUFFER_FLUSH(a) ((void)0)
#define ENABLE_REG_RMW_BUFFER(a) ((void)0)
#define REG_RMW_BUFFER_FLUSH(a) ((void)0)
'''
model = r'''
struct ath9k_channel {u16 frequency;};
struct chan_centers {u16 synth_center,ctl_center,ext_center;};
struct ath_hw;
struct eep_ops {u16 (*get_spur_channel)(struct ath_hw*,u16,bool);u32 (*get_eeprom)(struct ath_hw*,int);};
struct ath_hw {
 struct {struct ar5416_eeprom_4k map4k;} eeprom;
 struct ath9k_channel *curchan;struct eep_ops *eep_ops;
 struct {int macVersion;} hw_version;struct {bool cwm_ignore_extcca;} config;
 u8 txchainmask,rxchainmask;
};
static u32 regs[0x10000/4];static uint64_t hash;static unsigned writes;
static u32 rd(u32 reg){return regs[reg/4];}
static void wr(u32 reg,u32 value){
 regs[reg/4]=value;writes++;
 for(int i=0;i<4;i++){hash=(hash^((reg>>(8*i))&255))*UINT64_C(0x100000001b3);}
 for(int i=0;i<4;i++){hash=(hash^((value>>(8*i))&255))*UINT64_C(0x100000001b3);}
}
#define REG_READ(a,r) rd(r)
#define REG_WRITE(a,r,v) wr(r,v)
#define REG_RMW(a,r,s,c) wr(r,(rd(r)&~(c))|(s))
#define REG_SET_BIT(a,r,b) wr(r,rd(r)|(b))
#define REG_CLR_BIT(a,r,b) wr(r,rd(r)&~(b))
#define REG_RMW_FIELD(a,r,f,v) wr(r,(rd(r)&~(f))|(((u32)(v)<<f##_S)&(f)))
static void ath9k_hw_get_channel_centers(struct ath_hw*a,struct ath9k_channel*c,struct chan_centers*d){d->synth_center=d->ctl_center=c->frequency;}
static void ath9k_hw_analog_shift_rmw(struct ath_hw*a,u32 r,u32 mask,u32 shift,u32 value){wr(r,(rd(r)&~mask)|((value<<shift)&mask));}
static u32 get_eeprom(struct ath_hw*a,int id){return 0;}
'''
main = r'''
int main(void){
 struct eep_ops ops={ath9k_hw_4k_get_spur_channel,get_eeprom};
 const u16 frequencies[]={2412,2437,2472};
 const int offsets[]={-10,-9,-3,0,3,9,10,100};
 printf("pub const SPUR_OFFSET:usize=%zu;\n",offsetof(struct ar5416_eeprom_4k,modalHeader.spurChans));
 printf("pub const CHANNEL_CASES:&[(u16,u16,u32,u32,u64)]=&[\n");
 for(unsigned f=0;f<3;f++)for(unsigned o=0;o<8;o++)for(unsigned s=0;s<2;s++){
  struct ath_hw ah={0};ah.txchainmask=1;ah.rxchainmask=1;ah.eep_ops=&ops;
  struct ath9k_channel channel={frequencies[f]};
  u16 spur=(frequencies[f]+offsets[o]-2300)*10;
  for(int i=0;i<5;i++)ah.eeprom.map4k.modalHeader.spurChans[i].spurChan=0x8000;
  ah.eeprom.map4k.modalHeader.spurChans[0].spurChan=spur;
  u32 seed=s?0x5a93a5c3:0;
  for(unsigned i=0;i<ARRAY_SIZE(regs);i++)regs[i]=seed?seed^(i*4):0;
  hash=UINT64_C(0xcbf29ce484222325);writes=0;
  ar5008_hw_override_ini(&ah,&channel);
  ar5008_hw_set_channel_regs(&ah,&channel);
  ar5008_hw_init_chain_masks(&ah);
  ar5008_hw_set_rfmode(&ah,&channel);
  ar9002_hw_set_channel(&ah,&channel);
  ar5008_hw_set_delta_slope(&ah,&channel);
  ar9002_hw_spur_mitigate(&ah,&channel);
  printf("(%u,%u,0x%08x,%u,0x%016llx),\n",frequencies[f],spur,seed,writes,(unsigned long long)hash);
 }
 printf("];\n");return 0;
}
'''
source = prefix + '\n'.join(selected + structures) + model + '\n'.join(functions) + main
path = out / 'channel-oracle.c'
path.write_text(source)
subprocess.run([args.cc, '-std=gnu11', '-O2', '-fwrapv', '-w', str(path), '-o', str(out/'channel-oracle')], check=True)
result = subprocess.check_output([str(out/'channel-oracle')], text=True)
(out/'golden.rs').write_text(result)
provenance = {
    'sources': {name: hashlib.sha256(original[name].encode()).hexdigest() for name in files},
    'functions': {name: hashlib.sha256(body.encode()).hexdigest() for (_, name), body in zip(owners, functions)},
    'profile': 'AR9285 one-chain 2GHz full-rate 20MHz, 3 channels x8 signed spur offsets x2 inherited seeds',
}
(out/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
print(result, end='')
