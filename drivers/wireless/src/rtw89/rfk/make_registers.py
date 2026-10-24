#!/usr/bin/env python3
"""Resolve actual named B RFK register/field constants with the C compiler."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
rust=re.sub(r'//[^\n]*','',(d.parent/'rfk.rs').read_text());names=set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+|RFREG_MASK)\b',rust))
header=(a.linux/'reg.h').read_text()+'\n'+(a.linux/'core.h').read_text();header=header.replace('\\\n','');defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',header,re.M)}
selected=set(names);todo=list(selected)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in selected:selected.add(dep);todo.append(dep)
body='\n'.join(defs[n] for n in sorted(selected));code='''#include <stdio.h>
#define BIT(n) (1ULL<<(n))
#define GENMASK(h,l) ((~0ULL<<(l))&(~0ULL>>(63-(h))))
'''+body+'\nint main(void){\n'
for n in sorted(names):code+=f'printf("pub(super) const {n}: u32 = 0x%llx;\\n",(unsigned long long)({n}));\n'
code+='return 0;}\n'
with tempfile.TemporaryDirectory(prefix='rtw89-rfk-registers-') as td:
 td=Path(td);(td/'constants.c').write_text(code);subprocess.run(['cc','-std=gnu11',str(td/'constants.c'),'-o',str(td/'constants')],check=True);result=subprocess.check_output([str(td/'constants')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux RFK register macros SHA256 '+hashlib.sha256(body.encode()).hexdigest()+'\n'+result
path=d.parent/'rfk_regs.rs'
if a.check:
 if path.read_text()!=value:raise SystemExit('RFK register constants differ')
else:path.write_text(value)
