#!/usr/bin/env python3
"""Run original initial B DPK after the original full TSSI/common program."""
from pathlib import Path
import importlib.util
import re
import subprocess
import tempfile

directory = Path(__file__).parent
spec = importlib.util.spec_from_file_location('narf_tssi_oracle', directory.parent / 'tssi/make_linux_oracle.py')
tssi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tssi)
rfk, core, linux = tssi.rfk, tssi.core, tssi.linux
names = ['_rfk_backup_bb_reg', '_rfk_backup_rf_reg', '_rfk_restore_bb_reg', '_rfk_restore_rf_reg', '_rfk_rf_direct_cntrl', '_rfk_drf_direct_cntrl', '_set_rx_dck']
names += re.findall(r'^static\s+(?:void|u8|u16|s8|bool)\s+(_dpk_\w+|_dpk)\s*\(', rfk[:rfk.index('static void _dpk_track')], re.M)
names += ['rtw8852b_dpk']


def function(name):
    match = re.search(r'^(?:static\s+)?(?:void|u8|u16|u32|s8|bool)\s+' + name + r'\s*\(', rfk, re.M)
    end, depth = rfk.index('{', match.end()) + 1, 1
    while depth:
        depth += (rfk[end] == '{') - (rfk[end] == '}')
        end += 1
    return match.start(), rfk[match.start():end]


functions = '\n'.join(value for _, value in sorted(function(name) for name in names))
defs = tssi.defs
needed = set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+|RFREG_MASK\w*|MASK[A-Z0-9_]+|DPK_TXAGC_\w+|RTW8852B_DPK_\w+|RTW89_DPK_BKUP_NUM)\b', functions))
selected, todo = set(needed), list(needed)
while todo:
    name = todo.pop()
    for dependency in re.findall(r'\b[A-Z][A-Z0-9_]+\b', defs[name]):
        if dependency in defs and dependency not in selected:
            selected.add(dependency)
            todo.append(dependency)
definitions = '\n'.join(defs[name] for name in sorted(selected) if name not in tssi.selected)
program = tssi.program[:tssi.program.index('int main(void)')]
program = program.replace('struct rtw89_hal{u8 antenna_rx,rx_nss;};', 'struct rtw89_hal{u8 antenna_rx,rx_nss,cv;};')
structures = r'''
struct rtw89_dpk_bkup {u8 band,ch,bw,txagc_dpk,gs,ther_dpk;u16 pwsf;bool path_ok;};
struct rtw89_dpk_info {bool is_dpk_enable,is_dpk_reload_en;u8 cur_idx[2],dpk_gs[2],corr_idx[2][2],corr_val[2][2];u16 dc_i[2][2],dc_q[2][2];struct rtw89_dpk_bkup bp[2][2];};
struct rtw89_fem_info{bool epa_2g,epa_5g,epa_6g;};
static bool dpk_mode,nctl_active;
'''
program = program.replace('struct rtw89_dev {', structures + '\nstruct rtw89_dev {struct rtw89_dpk_info dpk;struct rtw89_fem_info fem;')
program = program.replace('static u32 rtw89_phy_read32_mask', definitions + '\n#define CHIP_CAV 0\n#define RTW89_BAND_6G 2\n#define RTW89_CHANNEL_WIDTH_20 0\n#define RTW89_CHANNEL_WIDTH_40 1\n#define RTW89_CHANNEL_WIDTH_80 2\n#define BTC_WRFKT_DPK 2\n#define BTC_WRFK_START 0\n#define BTC_WRFK_STOP 1\n#define RTW8852B_RF_REL_VERSION 34\n#define abs(v) ((v)<0?-(v):(v))\n#define phy_div(a,b) ((b)?(a)/(b):0)\n#define mdelay(ms) udelay((ms)*1000)\nstatic u32 rtw89_phy_read32_mask')
program = program.replace('return(v&m)>>__builtin_ctz(m);}', '''
if(dpk_mode){if(a==0xbff8)v=nctl_active?0x55:0;if(a==0x80fc){u32 sel=(d->words[(0x10000+R_KIP_RPT1)/4]&B_KIP_RPT1_SEL)>>__builtin_ctz(B_KIP_RPT1_SEL);switch(sel){case 3:v=nctl_active?0x8000:0;break;case 0:v=(1500<<16)|(200<<8)|7;break;case 9:v=(0xff6<<16)|20;break;case 6:v=(d->words[(0x10000+R_DPK_CFG2)/4]&B_DPK_CFG2_ST)?2<<4:(d->words[(0x10000+R_DPK_CFG3)/4]>>24)?(100<<16)|100:(125<<16)|125;break;default:v=0;break;}}}
return(v&m)>>__builtin_ctz(m);}''')
program = program.replace('d->words[a/4]=v;write_trace(4,a,v);', 'd->words[a/4]=v;write_trace(4,a,v);if(a==0x18000)nctl_active=v!=0;if(a==0x18010&&!(v&255))nctl_active=false;')
program = program.replace('return(d->rf[p][a]&m)>>__builtin_ctz(m);', 'u32 v=d->rf[p][a];if(dpk_mode&&a==RR_TM)v=(v&~0x7e)|((p?35:31)<<1);return(v&m)>>__builtin_ctz(m);')
arrays = '\n'.join(re.search(r'static const u32 ' + name + r'\[\] = \{.*?\};', rfk, re.S)[0] for name in ['rtw8852b_backup_bb_regs', 'rtw8852b_backup_rf_regs'])
enums = '\n'.join(re.search(r'enum ' + name + r' \{.*?\};', rfk, re.S)[0] for name in ['rtw8852b_dpk_id', 'dpk_agc_step'])
program += '\n' + arrays + '\n#define BACKUP_BB_REGS_NR ARRAY_SIZE(rtw8852b_backup_bb_regs)\n#define BACKUP_RF_REGS_NR ARRAY_SIZE(rtw8852b_backup_rf_regs)\n' + enums + '\n' + functions
program += r'''
int main(void){
puts("type DpkGolden=(u32,u8,u8,u32,u64,[[u16;8];2]);\npub(super) const CASES:&[DpkGolden]=&[");
for(int seed=0;seed<2;seed++)for(int cut=0;cut<2;cut++)for(int high=0;high<2;high++){
 static struct rtw89_dev d;memset(&d,0,sizeof(d));u32 pattern=seed?0xa5a5a5a5:0;
 for(unsigned i=0;i<ARRAY_SIZE(d.words);i++)d.words[i]=pattern;
 for(int p=0;p<2;p++)for(unsigned a=0;a<ARRAY_SIZE(d.rf[p]);a++)d.rf[p][a]=pattern&0xfffff;
 d.hal.antenna_rx=RF_AB;d.hal.rx_nss=2;d.hal.cv=cut;d.tssi.thermal[0]=32;d.tssi.thermal[1]=34;
 d.efuse_gain.comp_valid=true;d.efuse_gain.offset_valid=true;d.efuse_gain.offset_base[0]=-30;d.efuse_gain.rssi_base[0]=46;
 for(int p=0;p<2;p++){d.tssi.tssi_cck[p][0]=p?5:-3;d.tssi.tssi_mcs[p][0]=p?11:-9;d.tssi.tssi_trim[p][0]=p?-4:2;d.efuse_gain.comp[p][0]=p?-5:7;d.efuse_gain.offset[p][0]=p?-2:3;d.efuse_gain.offset[p][1]=p?4:-6;}
 static const struct{u32 chip_id;}chip={1};d.chip=(const void*)&chip;
 dpk_mode=false;nctl_active=false;rtw8852b_tssi(&d,0,true,0);
 d.dpk.dpk_gs[0]=high?0x7f:0x5b;dpk_mode=true;hash=14695981039346656037ULL;count=now=0;rtw8852b_dpk(&d,0,0);
 printf("(%u,%u,%u,%u,%llu,[",pattern,cut,d.dpk.dpk_gs[0],count,(unsigned long long)hash);
 for(int p=0;p<2;p++){struct rtw89_dpk_bkup*b=&d.dpk.bp[p][0];printf("[%u,%u,%u,%u,%u,%u,%u,%u],",b->ther_dpk,b->txagc_dpk,b->pwsf,b->gs,d.dpk.corr_idx[p][0],d.dpk.corr_val[p][0],d.dpk.dc_i[p][0],d.dpk.dc_q[p][0]);}puts("]),");
}puts("];");
hash=14695981039346656037ULL;for(unsigned v=0;v<4096;v++)val((u8)_dpk_dgain_mapping(0,v));
printf("pub(super) const DGAIN_HASH:u64=%llu;\n",(unsigned long long)hash);
return 0;}
'''
with tempfile.TemporaryDirectory(prefix='narf-8852b-dpk-c-') as temporary:
    c, executable = Path(temporary) / 'oracle.c', Path(temporary) / 'oracle'
    c.write_text(program)
    subprocess.run(['cc', '-std=gnu11', '-O2', '-Wno-unused-function', str(c), '-o', str(executable)], check=True)
    output = subprocess.check_output([str(executable)], text=True)
directory.joinpath('golden.rs').write_text('// Unmodified Linux DPK following original full TSSI.\n' + output)
