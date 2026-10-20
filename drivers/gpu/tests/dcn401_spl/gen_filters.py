#!/usr/bin/env python3
"""Regenerate drivers/gpu/src/amdgpu_dcn401_spl_filters.rs from Linux SPL.

    drivers/gpu/tests/dcn401_spl/gen_filters.py [linux-tree] > \
        drivers/gpu/src/amdgpu_dcn401_spl_filters.rs

Every polyphase table dc_spl_scl_filters.c defines, and the S1.12 EASF
tables of dc_spl_scl_easf_filters.c (the ones spl_dscl_get_easf_filter_coeffs_64p
returns), verbatim. check.sh fails when the checked-in file differs.
"""
import re
import sys

linux = sys.argv[1] if len(sys.argv) > 1 else '/usr/src/linux'
sspl = linux + '/drivers/gpu/drm/amd/display/dc/sspl/'


def arrays(path, keep):
    src = open(sspl + path).read()
    out = []
    for m in re.finditer(r'static const uint16_t (\w+)\[(\d+)\] = \{(.*?)\};', src, re.S):
        name, n, body = m.group(1), int(m.group(2)), m.group(3)
        if not keep(name):
            continue
        vals = [int(v, 16) for v in re.findall(r'0x[0-9a-fA-F]+', body)]
        assert len(vals) == n, (name, len(vals), n)
        out.append((name, vals))
    return out


scl = arrays('dc_spl_scl_filters.c', lambda n: True)
easf = arrays('dc_spl_scl_easf_filters.c', lambda n: n.endswith('_s1_12'))
print('//! Generated from Linux drivers/gpu/drm/amd/display/dc/sspl/dc_spl_scl_filters.c')
print('//! and dc_spl_scl_easf_filters.c (the S1.12 EASF tables) by')
print('//! drivers/gpu/tests/dcn401_spl/gen_filters.py; do not edit. Each table is')
print('//! 33 phases of `taps` S1.12 coefficients.')
for name, vals in scl + easf:
    print(f'pub static {name.upper()}: [u16; {len(vals)}] = [')
    for i in range(0, len(vals), 12):
        print('    ' + ', '.join(f'0x{v:04x}' for v in vals[i:i + 12]) + ',')
    print('];')
