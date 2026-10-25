"""Evaluate original Linux RTL8821CE packed factory geometry and raw FW header.

Only the firmware's64-byte format header is retained; instructions/calibration
are omitted. A zero-filled geometry replay is never a deployable image.
"""
from pathlib import Path
import hashlib
import re
import subprocess
import tempfile

BASE = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88')
HERE = Path(__file__).parent

def structure(source, name):
    match = re.search(r'struct ' + name + r'\s*\{', source)
    start, end, depth = match.start(), match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:source.index(';', end) + 1]

main = (BASE / 'main.h').read_text()
chip = (BASE / 'rtw8821c.h').read_text()
names = ['rtw_2g_1s_pwr_idx_diff', 'rtw_2g_ns_pwr_idx_diff', 'rtw_2g_txpwr_idx',
         'rtw_5g_ht_1s_pwr_idx_diff', 'rtw_5g_ht_ns_pwr_idx_diff', 'rtw_5g_ofdm_ns_pwr_idx_diff',
         'rtw_5g_vht_ns_pwr_idx_diff', 'rtw_5g_txpwr_idx', 'rtw_txpwr_idx']
body = '\n'.join(structure(main, name) for name in names)
body += '\n' + '\n'.join(structure(chip, name) for name in
    ['rtw8821cu_efuse', 'rtw8821ce_efuse', 'rtw8821cs_efuse', 'rtw8821c_efuse'])
fields = ['txpwr_idx_table', 'channel_plan', 'xtal_k', 'thermal_meter',
          'rf_board_option', 'rf_bt_setting', 'rfe_option', 'country_code', 'e.mac_addr']
pre = '''#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t __le16;
#define __packed __attribute__((packed))
#define __LITTLE_ENDIAN 1
#define ETH_ALEN 6
'''
post = '\nint main(){\n' + ''.join(
    f'printf("(%zu,%zu),\\n",offsetof(struct rtw8821c_efuse,{f}),sizeof(((struct rtw8821c_efuse*)0)->{f}));\n'
    for f in fields) + '}\n'
with tempfile.TemporaryDirectory() as temp:
    source, exe = Path(temp) / 'factory.c', Path(temp) / 'factory'
    source.write_text(pre + body + post)
    subprocess.run(['cc', '-O2', '-o', str(exe), str(source)], check=True)
    rows = subprocess.check_output([str(exe)]).decode()
(HERE / 'rtl8821c_golden.rs').write_text(
    '// Original Linux rtw8821c.h/main.h packed sizeof/offsetof.\n'
    'const LINUX_8821C_FACTORY: &[(usize,usize)] = &[\n' + rows + '];\n')

raw = Path('/lib/firmware/rtw88/rtw8821c_fw.bin')
data = raw.read_bytes() if raw.exists() else subprocess.check_output(['zstd', '-dc', str(raw) + '.zst'])
digest = '2ef409bc418549fcf294061dd0cae1fc22fd9da79b60524950b25de18732f3f0'
if hashlib.sha256(data).hexdigest() != digest or len(data) != 139472:
    raise ValueError('installed RTL8821C image differs from pinned raw source')
target = HERE.parent / 'firmware' / 'rtl8821c_metadata.rs'
target.write_text('// Metadata only from raw rtw88/rtw8821c_fw.bin; no executable payload.\n'
    'const SOURCE_8821C_SHA256: &str = "' + digest + '";\n'
    'const SOURCE_8821C_LENGTH: usize = ' + str(len(data)) + ';\n'
    'const SOURCE_8821C_HEADER: &[u8] = &[' + ','.join(str(b) for b in data[:64]) + '];\n')
subprocess.run(['rustfmt', '--edition', '2021', str(HERE / 'rtl8821c_golden.rs'), str(target)], check=True)
