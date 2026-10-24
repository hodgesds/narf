"""Evaluate actual Linux packed RTL8822CE EFUSE geometry, without hardware."""
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88')


def structure(source, name):
    match = re.search(r'struct ' + name + r'\s*\{', source)
    start, end, depth = match.start(), match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:source.index(';', end) + 1]


main, chip = (BASE / 'main.h').read_text(), (BASE / 'rtw8822c.h').read_text()
trims = ['PPG_THERMAL_A','PPG_THERMAL_B','PPG_2GL_TXAB','PPG_2GM_TXAB','PPG_2GH_TXAB',
         'PPG_5GL1_TXA','PPG_5GL2_TXA','PPG_5GM1_TXA','PPG_5GM2_TXA','PPG_5GH1_TXA',
         'PPG_5GL1_TXB','PPG_5GL2_TXB','PPG_5GM1_TXB','PPG_5GM2_TXB','PPG_5GH1_TXB',
         'PPG_PABIAS_2GA','PPG_PABIAS_2GB','PPG_PABIAS_5GA','PPG_PABIAS_5GB']
names = ['rtw_2g_1s_pwr_idx_diff', 'rtw_2g_ns_pwr_idx_diff', 'rtw_2g_txpwr_idx',
         'rtw_5g_ht_1s_pwr_idx_diff', 'rtw_5g_ht_ns_pwr_idx_diff', 'rtw_5g_ofdm_ns_pwr_idx_diff',
         'rtw_5g_vht_ns_pwr_idx_diff', 'rtw_5g_txpwr_idx', 'rtw_txpwr_idx']
body = '\n'.join(structure(main, name) for name in names)
body += '\n' + '\n'.join(structure(chip, name) for name in ['rtw8822cu_efuse', 'rtw8822cs_efuse', 'rtw8822ce_efuse', 'rtw8822c_efuse'])
body += '\n' + '\n'.join(re.search(r'^#define '+name+r'\s+[^\n]+',chip,re.M).group(0) for name in trims)
lines = iter((BASE / 'efuse.h').read_text().splitlines())
for line in lines:
    if line.startswith('#define GET_EFUSE_HW_CAP_'):
        definition = line
        while definition.endswith('\\'):
            definition += '\n' + next(lines)
        body += '\n' + definition
fields = ['txpwr_idx_table', 'channel_plan', 'xtal_k', 'rf_board_option',
          'rf_bt_setting', 'rfe_option', 'country_code', 'path_a_thermal', 'path_b_thermal', 'e.mac_addr']
pre = '''#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n#include <string.h>\ntypedef uint8_t u8;typedef int8_t s8;typedef uint16_t __le16;typedef uint32_t __le32;\n#define __packed __attribute__((packed))\n#define __LITTLE_ENDIAN 1\n#define ETH_ALEN 6\n#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))\n#define le32_get_bits(v,m) (((v)&(m))>>__builtin_ctz(m))\n'''
post = '\nint main(){\n'
for field in fields:
    post += f'printf("(%zu,%zu),\\n",offsetof(struct rtw8822c_efuse,{field}),sizeof(((struct rtw8822c_efuse*)0)->{field}));\n'
post += 'printf("PATH %zu\\nTRIMS\\n",sizeof(struct rtw_txpwr_idx));\n'
post += ''.join(f'printf("%u,\\n",{name});\n' for name in trims)
post += '''printf("FEATURE\\n");
unsigned words[]={0,0xffffffffU,0x0c570002,0xa5a55a5a};for(int i=0;i<4;i++){u8 raw[13]={0};memcpy(raw+4,&words[i],4);printf("(0x%x,[%u,%u,%u,%u,%u]),\\n",words[i],GET_EFUSE_HW_CAP_HCI(raw),GET_EFUSE_HW_CAP_BW(raw),GET_EFUSE_HW_CAP_NSS(raw),GET_EFUSE_HW_CAP_ANT_NUM(raw),GET_EFUSE_HW_CAP_PTCL(raw));}
return 0;}\n'''
with tempfile.TemporaryDirectory() as temp:
    source, exe = Path(temp) / 'factory.c', Path(temp) / 'factory'
    source.write_text(pre + body + post)
    subprocess.run(['cc', '-O2', '-o', str(exe), str(source)], check=True)
    output = subprocess.check_output([str(exe)]).decode()
rows, path = output.split('PATH ')
path, rest = path.split('TRIMS\n')
trim_values, features = rest.split('FEATURE\n')
target = Path(__file__).with_name('golden.rs')
target.write_text('// sizeof/offsetof from actual Linux rtw8822c.h and main.h packed declarations.\nconst LINUX_FACTORY: &[(usize,usize)] = &[\n' + rows + '];\nconst LINUX_POWER_PATH: usize = ' + path.strip() + ';\nconst LINUX_TRIM_ADDRESSES: [u16;19] = [\n' + trim_values + '];\n// Original Linux efuse.h report field macros.\nconst LINUX_HW_FEATURES: &[(u32,[u8;5])] = &[\n' + features + '];\n')
subprocess.run(['rustfmt', '--edition', '2021', str(target)], check=True)
