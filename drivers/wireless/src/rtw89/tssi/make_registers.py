#!/usr/bin/env python3
"""Resolve only actual Linux register masks used by this TSSI port."""
from pathlib import Path
import hashlib
import re
import subprocess
import tempfile

directory = Path(__file__).parent
linux = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89')
rust = '\n'.join(p.read_text() for p in [directory.parent / 'tssi.rs', directory / 'pmac.rs'])
rust = re.sub(r'//[^\n]*', '', rust)
names = set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+)\b', rust))
header = ((linux / 'reg.h').read_text() + '\n' + (linux / 'core.h').read_text()).replace('\\\n', '')
definitions = {m[1]: m[0] for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+', header, re.M)}
selected = set(names)
todo = list(selected)
while todo:
    name = todo.pop()
    for dependency in re.findall(r'\b[A-Z][A-Z0-9_]+\b', definitions[name]):
        if dependency in definitions and dependency not in selected:
            selected.add(dependency)
            todo.append(dependency)
body = '\n'.join(definitions[name] for name in sorted(selected))
program = '#include <stdio.h>\n#define BIT(n) (1ULL<<(n))\n#define GENMASK(h,l) ((~0ULL<<(l))&(~0ULL>>(63-(h))))\n' + body + '\nint main(void){\n'
for name in sorted(names):
    program += f'printf("pub(super) const {name}:u32=0x%llx;\\n",(unsigned long long)({name}));\n'
program += '}\n'
with tempfile.TemporaryDirectory(prefix='narf-8852b-tssi-regs-') as temp:
    c, executable = Path(temp) / 'regs.c', Path(temp) / 'regs'
    c.write_text(program)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Werror', str(c), '-o', str(executable)], check=True)
    result = subprocess.check_output([str(executable)], text=True)
directory.joinpath('regs.rs').write_text('// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Linux masks SHA256 ' + hashlib.sha256(body.encode()).hexdigest() + '\n' + result)
