#!/usr/bin/env python3
"""Extract B's real PMAC PLCP program/default tracking curves and bind recipe."""
from pathlib import Path
import hashlib
import re

linux = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89')
common = (linux / 'rtw8852b_common.c').read_text()
table = (linux / 'rtw8852b_table.c').read_text()
program = re.search(r'static const struct rtw89_reg3_def rtw8852bx_pmac_ht20_mcs7_tbl\[\] = \{(.*?)\n\};', common, re.S)[1]
rows = re.findall(r'\{(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+)\}', program)
value = '// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Extracted from actual Linux B common/table source.\n'
digest = hashlib.sha256(b''.join((linux / name).read_bytes() for name in ['rtw8852b_rfk.c', 'rtw8852b_common.c', 'rtw8852b_rfk_table.c', 'rtw8852b_table.c', 'reg.h'])).digest()
value += 'pub(super) const RECIPE: [u8;32] = [' + ','.join(str(b) for b in digest) + '];\n'
value += 'pub(super) const PMAC_PLCP: &[(u32,u32,u32)] = &[\n'
for row in rows:
    value += '(' + ','.join(row) + '),\n'
value += '];\n'
for path in 'ab':
    for sign in 'np':
        match = re.search(r'static const s8 _txpwr_track_delta_swingidx_2g' + path + '_' + sign + r'\[\] = \{(.*?)\};', table, re.S)
        numbers = [int(n) for n in re.findall(r'-?\d+', match[1])]
        assert len(numbers) == 30
        value += 'pub(super) const ' + path.upper() + '_' + sign.upper() + ': [i8;30] = [' + ','.join(str(n) for n in numbers) + '];\n'
Path(__file__).with_name('tables.rs').write_text(value)
