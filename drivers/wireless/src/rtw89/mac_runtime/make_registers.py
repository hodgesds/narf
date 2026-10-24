#!/usr/bin/env python3
"""Resolve the post-WCPU owner's named Linux register macros with C."""
from pathlib import Path
import argparse, hashlib, re, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true');a=p.parse_args()
directory=Path(__file__).parent;rust=(directory.parent/'mac_runtime.rs').read_text()
rust=re.sub(r'//[^\n]*','',rust)
names=set(re.findall(r'\b[A-Z][A-Z_0-9]+\b',rust))-{'MAX'}
text='\n'.join((a.linux/n).read_text() for n in ['reg.h','mac.h','pci.h'])
text=re.sub(r'/\*.*?\*/','',text,flags=re.S).replace('\\\n','')
definitions={m.group(1):m.group(0) for m in re.finditer(r'^\s*#define\s+(\w+)\s+[^\n]+',text,re.M)}
for name,value in re.findall(r'\b([A-Z][A-Z_0-9]+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*[,}]',text):
    definitions.setdefault(name,'#define '+name+' '+value)
missing=names-definitions.keys()
if missing:raise SystemExit('unknown Linux constants: '+','.join(sorted(missing)))
todo=list(names);selected=set()
while todo:
    name=todo.pop()
    if name in selected:continue
    selected.add(name)
    todo.extend(n for n in re.findall(r'\b[A-Z][A-Z_0-9]+\b',definitions[name]) if n in definitions and n not in selected)
prefix='''#include <stdio.h>
#include <stdint.h>
#define BIT(n) (1ULL<<(n))
#define BIT_ULL(n) BIT(n)
#define GENMASK(h,l) ((~0ULL<<(l))&(~0ULL>>(63-(h))))
#define GENMASK_ULL(h,l) GENMASK(h,l)
#define FIELD_PREP_CONST(m,v) (((uint64_t)(v)<<__builtin_ctzll(m))&(m))
'''
body='\n'.join(definitions[n] for n in sorted(selected))
code=prefix+body+'\nint main(void){\n'
for name in sorted(names):code+=f'printf("pub(super) const {name}: u32 = 0x%llx;\\n",(unsigned long long)({name}));\n'
code+='return 0;}\n'
with tempfile.TemporaryDirectory(prefix='rtw89-mac-registers-') as td:
    td=Path(td);(td/'constants.c').write_text(code)
    subprocess.run(['cc','-std=gnu11',str(td/'constants.c'),'-o',str(td/'constants')],check=True)
    result=subprocess.check_output([str(td/'constants')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Linux macro SHA256 '+hashlib.sha256(body.encode()).hexdigest()+'\n'+result
path=directory.parent/'mac_runtime_regs.rs'
if a.check:
    if path.read_text()!=value:raise SystemExit('post-WCPU register constants differ')
else:path.write_text(value)
