#!/usr/bin/env python3
"""Derive AX factory-field offsets from original packed Linux EFUSE types."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux'));p.add_argument('--check',action='store_true');a=p.parse_args()
root=a.linux/'drivers/net/wireless/realtek/rtw89'
headers=['rtw8852a.h','rtw8852b_common.h','rtw8852c.h','rtw8851b.h'];text='\n'.join((root/n).read_text() for n in headers)
def block(name):
    m=re.search(r'\bstruct\s+'+name+r'\s*\{',text);start=m.start();cur=m.end();depth=1
    while depth:depth+=(text[cur]=='{')-(text[cur]=='}');cur+=1
    return text[start:text.index(';',cur)+1]
seen=set();types=[]
def add(name):
    if name in seen:return
    seen.add(name);body=block(name)
    for dep in re.findall(r'\bstruct\s+(\w+)\s+\w+',body):add(dep)
    types.append(body)
models=['rtw8852a_efuse','rtw8852bx_efuse','rtw8852c_efuse','rtw8851b_efuse']
for model in models:add(model)
body='\n'.join(types)
core=(root/'core.h').read_text();defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',core,re.M)}
names=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',body));defines='\n'.join(defs[n] for n in sorted(names) if n in defs)
code='#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\ntypedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint16_t __le16;typedef uint32_t u32;typedef uint32_t __le32;\n#define __packed __attribute__((packed))\n#define ETH_ALEN 6\n'+defines+'\n'+body+'\nint main(void){\n'
for n,model in zip(['A','B','C','N51'],models):
    for field in ['rfe_type','xtal_k','country_code']:
        code+='printf("pub const '+n+'_'+field.upper()+': usize = 0x%zx;\\n",offsetof(struct '+model+','+field+'));\n'
for name,field in [
    ('TSSI_A','path_a_tssi'),('TSSI_B','path_b_tssi'),
    ('THERMAL_A','path_a_therm'),('THERMAL_B','path_b_therm'),
    ('GAIN_CCK','rx_gain_2g_cck'),('GAIN_OFDM','rx_gain_2g_ofdm'),
    ('GAIN_LOW','rx_gain_5g_low'),('GAIN_MID','rx_gain_5g_mid'),('GAIN_HIGH','rx_gain_5g_high'),
]:
    code+='printf("pub const B_'+name+': usize = 0x%zx;\\n",offsetof(struct rtw8852bx_efuse,'+field+'));\n'
for name,field in [('CCK','cck_tssi'),('MCS2G','bw40_tssi'),('MCS5G','bw40_1s_tssi_5g')]:
    code+='printf("pub const B_TSSI_'+name+': usize = 0x%zx;\\n",offsetof(struct rtw8852bx_tssi_offset,'+field+'));\n'
code+='return 0;}\n'
with tempfile.TemporaryDirectory() as td:
    td=Path(td);(td/'oracle.c').write_text(code);subprocess.run(['cc','-O2','-o',str(td/'oracle'),str(td/'oracle.c')],check=True);result=subprocess.check_output([str(td/'oracle')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux EFUSE type SHA256 '+hashlib.sha256(body.encode()).hexdigest()+'\n'+result
path=Path(__file__).with_name('golden.rs')
if a.check:
    if path.read_text()!=value:raise SystemExit('factory offsets differ')
else:path.write_text(value)
