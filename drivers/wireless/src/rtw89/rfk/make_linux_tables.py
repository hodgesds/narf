#!/usr/bin/env python3
"""Resolve actual B RFK reg5 programs and bind the full source recipe."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
s=(a.linux/'rtw8852b_rfk_table.c').read_text();phy=(a.linux/'phy.h').read_text()
blocks=re.findall(r'^static const struct rtw89_reg5_def (\w+)\[\] = \{.*?^\};',s,re.M|re.S)
arrays=[re.search(r'^static const struct rtw89_reg5_def '+name+r'\[\] = \{.*?^\};',s,re.M|re.S).group(0) for name in blocks]
enum=re.search(r'enum rtw89_rfk_flag \{.*?\};',phy,re.S).group(0)
macros=re.search(r'#define RTW89_DECL_RFK_WRF.*?\nvoid\nrtw89_rfk_parser',phy,re.S).group(0).split('\nvoid\n')[0]
code='''#include <stdint.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define RF_PATH_A 0
#define RF_PATH_B 1
struct rtw89_reg5_def {u8 flag,path;u32 addr,mask,data;};
'''+enum+'\n'+macros+'\n'+'\n'.join(arrays)+'\nint main(void){\n'
for name in blocks:
 label=name.removeprefix('rtw8852b_').upper()
 code+=f'printf("#[rustfmt::skip]\\npub(super) const {label}: &[Entry] = &[\\n");for(unsigned i=0;i<sizeof({name})/sizeof({name}[0]);i++){{const struct rtw89_reg5_def *p=&{name}[i];printf("Entry(%u,%u,0x%x,0x%x,0x%x),",p->flag,p->path,p->addr,p->mask,p->data);if(i%3==2)puts("");}}puts("\\n];");\n'
code+='return 0;}\n'
with tempfile.TemporaryDirectory(prefix='rtw89-rfk-tables-') as td:
 td=Path(td);(td/'tables.c').write_text(code);subprocess.run(['cc','-std=gnu11','-O2',str(td/'tables.c'),'-o',str(td/'tables')],check=True);result=subprocess.check_output([str(td/'tables')]).decode()
recipe=(a.linux/'rtw8852b_rfk.c').read_bytes()+(a.linux/'rtw8852b_common.c').read_bytes()+s.encode()+(a.linux/'reg.h').read_bytes()
sha=hashlib.sha256(recipe).digest();literal=','.join(str(v) for v in sha)
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Copyright(c) 2019-2022 Realtek Corporation\n// Original B RFK recipe SHA256 '+sha.hex()+'\nuse super::rfk::Entry;\n#[rustfmt::skip]\npub(super) const RECIPE: [u8;32] = ['+literal+'];\n'+result
path=d.parent/'rfk_tables.rs'
if a.check:
 if path.read_text()!=value:raise SystemExit('B RFK programs/recipe differ')
else:path.write_text(value)
