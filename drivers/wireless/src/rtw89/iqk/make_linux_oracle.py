#!/usr/bin/env python3
"""Compile unmodified B IQK callbacks against explicit native measurement inputs.

Only MMIO/RF/clock/coexistence and fixed initial channel adapters are substituted.
Production register constants/tables are source extractions; dynamic golden
traces run the original C control flow independently of the Rust port.
"""
from pathlib import Path
import argparse
import hashlib
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux', type=Path, default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check', action='store_true')
a = p.parse_args()
d = Path(__file__).parent
source = (a.linux / 'rtw8852b_rfk.c').read_text()
core = (a.linux / 'core.h').read_text()


def function(name):
    m = re.search(r'^(?:static\s+)?(?:bool|u8|u32|void)\s+' + name + r'\s*\(', source, re.M)
    if not m:
        raise RuntimeError(name)
    end = source.index('{', m.end()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return m.start(), source[m.start():end]


names = ['_rfk_backup_bb_reg', '_rfk_backup_rf_reg', '_rfk_restore_bb_reg',
         '_rfk_restore_rf_reg', '_iqk_check_cal', '_kpath', '_iqk_rxk_setting',
         '_iqk_one_shot', '_rxk_group_sel', '_iqk_nbrxk', '_iqk_rxclk_setting',
         '_txk_group_sel', '_iqk_nbtxk', '_lok_res_table', '_lok_finetune_check',
         '_iqk_lok', '_iqk_txk_setting', '_iqk_txclk_setting', '_iqk_info_iqk',
         '_iqk_by_path', '_iqk_get_ch_info', '_iqk_start_iqk', '_iqk_restore',
         '_iqk_afebb_restore', '_iqk_preset', '_iqk_macbb_setting', '_iqk_init',
         '_wait_rx_mode', '_doiqk', '_iqk', 'rtw8852b_iqk']
functions = '\n'.join(v for _, v in sorted(function(n) for n in names))
arrays = ''
for name in re.findall(r'^static const u32 ([_ag]\w+|rtw8852b_backup_\w+)\[', source, re.M):
    if name in functions or name in ['rtw8852b_backup_bb_regs', 'rtw8852b_backup_rf_regs']:
        arrays += re.search(r'^static const u32 ' + name + r'\[.*?\};', source, re.M | re.S).group() + '\n'
tables = '\n'.join(re.findall(r'^static const struct rtw89_reg3_def rtw8852b_(?:set|restore)_nondbcc_path01\[\] = \{.*?^\};', source, re.M | re.S))
iqk_type = re.search(r'^struct rtw89_iqk_info \{.*?^\};', core, re.M | re.S).group()
iqk_enum = re.search(r'^enum rtw8852b_iqk_type \{.*?^\};', source, re.M | re.S).group()
headers = ((a.linux / 'reg.h').read_text() + '\n' + core + '\n' + source).replace('\\\n', '')
defs = {m.group(1): m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+', headers, re.M)}
needed = set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+|RFREG_MASK|MASK\w+|RTW8852B_\w+|RTW89_IQK_\w+|BACKUP_\w+)\b', functions + arrays + iqk_type))
needed.add('RF_PATH_MAX')
todo = list(needed)
while todo:
    name = todo.pop()
    for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b', defs[name]):
        if dep in defs and dep not in needed:
            needed.add(dep)
            todo.append(dep)
definitions = '\n'.join(defs[n] for n in sorted(needed))
prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int32_t s32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define rtw89_debug(...) ((void)0)
#define RTW89_PHY_0 0
#define RF_A 1
#define RF_B 2
#define RF_AB 3
#define RF_PATH_A 0
#define RF_PATH_B 1
#define RTW89_BAND_2G 0
#define RTW89_BAND_5G 1
#define RTW89_CHANNEL_WIDTH_80 2
#define BTC_WRFKT_IQK 0
#define BTC_WRFK_START 0
#define BTC_WRFK_STOP 1
#define BTC_WRFK_ONESHOT_START 2
#define BTC_WRFK_ONESHOT_STOP 3
#define RTW89_SCH_TX_SEL_ALL 0
enum rtw89_phy_idx {PHY0,PHY1};enum rtw89_chanctx_idx {CHAN0};
struct rtw89_reg3_def {u32 addr,mask,data;};
'''
shim = r'''
struct rtw89_rfk_mcc_info_data {u8 table_idx;};
struct rtw89_chan {u8 band_type,band_width,channel;};
struct rtw89_dev {bool dbcc_en;struct rtw89_iqk_info iqk;struct {struct rtw89_rfk_mcc_info_data *data;}rfk_mcc;u32 words[0x20000/4];u32 rf[2][0x10100];};
static u64 hash,now,ready_at;static u32 count,command;static int scenario,path,group;static u8 bias[2];static bool active_command;
static void value(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(i*8));hash*=1099511628211ULL;}}
static void three(u32 k,u32 a,u32 v){count++;value(k);value(a);value(v);}
static bool failed_command(void){u32 op=(command>>8)&15;
 if(scenario==3&&path==0&&op==1)return true;
 if(scenario==4&&path==1&&op==8&&group==2)return true;
 if(scenario==5&&path==0&&op==11&&group==3)return true;
 if(scenario==6&&path==1&&op==14)return true;
 return scenario==7&&path==0&&op==3;
}
static u32 read_word(struct rtw89_dev*d,u32 a){u32 v=d->words[a/4];u32 r=a-0x10000;
 if(r==0xbff8)v=active_command&&now>=ready_at?0x55:0;
 if(r==R_NCTL_N1&&active_command&&now>=ready_at)v=(v&~0xff)|0x55;
 if(r==R_NCTL_RPT)v=(v&~B_NCTL_RPT_FLG)|(failed_command()?B_NCTL_RPT_FLG:0);
 return v;}
static u32 rtw89_phy_read32_mask(struct rtw89_dev*d,u32 a,u32 m){return FIELD_GET(m,read_word(d,a+0x10000));}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){d->words[a/4]=v;three(4,a,v);
 if(a==0x10000+R_NCTL_N1&&!(v&0xff))active_command=false;
 if(a==0x10000+R_NCTL_CFG){active_command=true;command=v;path=(v&0x20)?1:0;group=FIELD_GET(B_CFIR_LUT_GP,d->words[(0x10000+R_CFIR_LUT+(path<<8))/4]);if(((v>>8)&15)==11)group=FIELD_GET(B_CFIR_LUT_GP_V1,d->words[(0x10000+R_CFIR_LUT+(path<<8))/4]);ready_at=now+(scenario==8?3:0);}}
static void rtw89_phy_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){u32 old=read_word(d,a+0x10000);rtw89_write32(d,a+0x10000,(old&~m)|FIELD_PREP(m,v));}
static u32 rtw89_read_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m){u32 v=d->rf[p][a];
 if(a==RR_TXMO){bool bad=scenario==2||(scenario==1&&bias[p]<3);v=FIELD_PREP(RR_TXMO_COI,bad?1:0x10)|FIELD_PREP(RR_TXMO_COQ,0x11);}
 if(a==RR_LOKVB)v=FIELD_PREP(RR_LOKVB_COI,0x20)|FIELD_PREP(RR_LOKVB_COQ,0x21);
 v=FIELD_GET(m,v);count++;value(32);value(p);value(a);value(m);value(v);return v;}
static bool rtw89_write_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m,u32 v){u32 old=d->rf[p][a];d->rf[p][a]=(old&~m)|FIELD_PREP(m,v);if(a==RR_LUTWD0&&m==RFREG_MASK)bias[p]=v;count++;value(36);value(p);value(a);value(m);value(v);return true;}
static void udelay(u32 us){three(8,us,0);now+=us;}
static u8 rtw89_btc_phymap(struct rtw89_dev*d,int p,int k,int c){return 0;}
static void rtw89_btc_ntfy_wl_rfk(struct rtw89_dev*d,int p,int kind,int event){three(48,kind,event);}
static void rtw89_chip_stop_sch_tx(struct rtw89_dev*d,int p,u32 *saved,int all){*saved=0x11223344;three(56,p,*saved);}
static void rtw89_chip_resume_sch_tx(struct rtw89_dev*d,int p,u32 saved){three(60,p,saved);}
static const struct rtw89_chan*rtw89_chan_get(struct rtw89_dev*d,int c){static const struct rtw89_chan chan={0,0,1};return &chan;}
#define read_poll_timeout_atomic(op,val,condition,step,budget,pre,...) ({int err=-ETIMEDOUT;for(u32 t=0;t<=budget;t+=step){val=op(__VA_ARGS__);if(condition){err=0;break;}if(t<budget)udelay(step);}err;})
'''
main = r'''
int main(void){puts("type Golden = (u8,u8,u32,u64,&'static [u32]);\npub(super) const CASES: &[Golden] = &[");
for(int seed=0;seed<2;seed++)for(scenario=0;scenario<9;scenario++){
 static struct rtw89_dev d;memset(&d,0,sizeof(d));static struct rtw89_rfk_mcc_info_data mcc;d.rfk_mcc.data=&mcc;
 u32 s=seed?0xa5a5a5a5:0;for(u32 i=0;i<0x20000/4;i++)d.words[i]=s;for(int p=0;p<2;p++)for(u32 a=0;a<0x10100;a++)d.rf[p][a]=s&0xfffff;
 memset(bias,0,sizeof(bias));hash=14695981039346656037ULL;count=0;now=0;ready_at=0;command=0;path=0;group=0;active_command=false;
 rtw8852b_iqk(&d,0,0);printf("(%u,%u,%u,0x%llx,&[",seed?165:0,scenario,count,(unsigned long long)hash);
 for(int p=0;p<2;p++){printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,",d.iqk.lok_cor_fail[0][p],d.iqk.lok_fin_fail[0][p],d.iqk.iqk_tx_fail[0][p],d.iqk.iqk_rx_fail[0][p],d.iqk.lok_idac[0][p],d.iqk.lok_vbuf[0][p],d.iqk.nb_txcfir[p],d.iqk.nb_rxcfir[p],d.iqk.bp_iqkenable[p],d.iqk.bp_txkresult[p],d.iqk.bp_rxkresult[p]);}
 printf("%u,%u,%u]),\n",d.iqk.iqk_times,d.iqk.iqk_fail_cnt,d.iqk.syn1to2);
}puts("];");return 0;}
'''
with tempfile.TemporaryDirectory(prefix='rtw89-iqk-oracle-') as td:
    td = Path(td)
    code = prefix + definitions + '\n' + iqk_type + '\n' + iqk_enum + '\n' + arrays + '\n' + tables + '\n' + shim + '\n' + functions + '\n' + main
    (td / 'oracle.c').write_text(code)
    subprocess.run(['cc', '-std=gnu11', '-O2', str(td / 'oracle.c'), '-o', str(td / 'oracle')], check=True)
    golden = subprocess.check_output([str(td / 'oracle')]).decode()
    # Evaluate only actual production-used source register macros in C.
    production = (d.parent / 'iqk.rs').read_text()
    constants = sorted(set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+|RFREG_MASK)\b', production)))
    (td / 'registers.c').write_text(prefix + definitions + '\nint main(void){' + ''.join(f'printf("pub(super) const {n}:u32=0x%x;\\n",(u32){n});' for n in constants) + '}')
    subprocess.run(['cc', '-std=gnu11', '-O2', str(td / 'registers.c'), '-o', str(td / 'registers')], check=True)
    registers = subprocess.check_output([str(td / 'registers')]).decode()
    (td / 'tables.c').write_text(prefix + arrays + tables + r'''
int main(void){puts("pub(super) const BACKUP_BB: &[u32]=&[");for(int i=0;i<ARRAY_SIZE(rtw8852b_backup_bb_regs);i++)printf("0x%x,",rtw8852b_backup_bb_regs[i]);puts("];\npub(super) const BACKUP_RF: &[u32]=&[");for(int i=0;i<ARRAY_SIZE(rtw8852b_backup_rf_regs);i++)printf("0x%x,",rtw8852b_backup_rf_regs[i]);puts("];");
const struct rtw89_reg3_def*defs[]={rtw8852b_set_nondbcc_path01,rtw8852b_restore_nondbcc_path01};int lengths[]={ARRAY_SIZE(rtw8852b_set_nondbcc_path01),ARRAY_SIZE(rtw8852b_restore_nondbcc_path01)};for(int k=0;k<2;k++){printf("pub(super) const %s:&[(u32,u32,u32)]=&[\n",k?"RESTORE":"SET");for(int i=0;i<lengths[k];i++)printf("(0x%x,0x%x,0x%x),\n",defs[k][i].addr,defs[k][i].mask,defs[k][i].data);puts("];");}return 0;}
''')
    # Array dimensions include original constants (do not replace them).
    (td / 'tables.c').write_text((td / 'tables.c').read_text().replace(prefix, prefix + definitions + '\n', 1))
    subprocess.run(['cc', '-std=gnu11', '-O2', str(td / 'tables.c'), '-o', str(td / 'tables')], check=True)
    rust_tables = subprocess.check_output([str(td / 'tables')]).decode()
digest = hashlib.sha256((functions + arrays + tables + definitions + iqk_type + iqk_enum).encode()).hexdigest()
recipe = 'pub(super) const RECIPE:[u8;32]=[' + ','.join(map(str, bytes.fromhex(digest))) + '];\n'
for filename, content in [('golden.rs', golden), ('registers.rs', registers), ('tables.rs', rust_tables), ('recipe.rs', recipe)]:
    value = '// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux RTL8852B IQK SHA256 ' + digest + '\n' + content
    if a.check:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / filename
            path.write_text(value)
            subprocess.run(['rustfmt', '--edition', '2021', str(path)], check=True)
            if (d / filename).read_text() != path.read_text():
                raise SystemExit(filename + ' differs')
    else:
        (d / filename).write_text(value)
        subprocess.run(['rustfmt', '--edition', '2021', str(d / filename)], check=True)
