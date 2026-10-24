#!/usr/bin/env python3
"""Compile original packed firmware-element layouts for checked B overrides."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();s=(a.linux/'fw.h').read_text()
def structure(name):
 m=re.search(r'^struct '+name+r'\s*\{',s,re.M);end=m.end();depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[m.start():s.index(';',end)+1]
body='\n'.join(structure(n) for n in ['__rtw89_fw_txpwr_element','__rtw89_fw_regd_element','rtw89_fw_element_hdr','rtw89_mfw_info','rtw89_mfw_hdr'])
code='''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define DELTA_SWINGIDX_SIZE 30
'''+body+'\nint main(void){\n'
for name,expr in [('HEADER','sizeof(struct rtw89_fw_element_hdr)'),('SIZE','offsetof(struct rtw89_fw_element_hdr,size)'),('AID','offsetof(struct rtw89_fw_element_hdr,aid)'),('INDEX','offsetof(struct rtw89_fw_element_hdr,u.reg2.idx)'),('REGS','offsetof(struct rtw89_fw_element_hdr,u.reg2.regs)'),('POWER','offsetof(struct rtw89_fw_element_hdr,u.txpwr.content)'),('MFW','sizeof(struct rtw89_mfw_hdr)'),('INFO','sizeof(struct rtw89_mfw_info)')]:
 code+=f'printf("pub(super) const {name}: usize = %zu;\\n",(size_t)({expr}));\n'
code+='return 0;}\n'
with tempfile.TemporaryDirectory(prefix='rtw89-radio-assets-') as td:
 td=Path(td);(td/'oracle.c').write_text(code);subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True);result=subprocess.check_output([str(td/'oracle')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux packed MFW/PHY-element types SHA256 '+hashlib.sha256(body.encode()).hexdigest()+'\n'+result
path=Path(__file__).with_name('golden.rs')
if a.check:
 if path.read_text()!=value:raise SystemExit('radio asset layout differs')
else:path.write_text(value)
