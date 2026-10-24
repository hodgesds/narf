#!/usr/bin/env python3
"""Run original B TSSI + common PMAC code with explicit factory/CW inputs."""
from pathlib import Path
import re
import subprocess
import tempfile

directory = Path(__file__).parent
linux = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89')
rfk = (linux / 'rtw8852b_rfk.c').read_text()
common = (linux / 'rtw8852b_common.c').read_text()
core = (linux / 'core.h').read_text()
phy = (linux / 'phy.h').read_text()
table = (linux / 'rtw8852b_table.c').read_text()


def function(source, name):
    match = re.search(r'^(?:static\s+)?(?:bool|u8|u32|s8|void)\s+' + name + r'\s*\(', source, re.M)
    if not match:
        raise RuntimeError(name)
    end = source.index('{', match.end()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return match.start(), source[match.start():end]


tssi_names = re.findall(r'^static\s+(?:bool|u8|u32|s8|void)\s+(_tssi_\w+)\s*\(', rfk, re.M)
rfk_names = ['_kpath', '_wait_rx_mode', '_tmac_tx_pause'] + tssi_names + ['rtw8852b_tssi']
common_names = ['rtw8852bx_set_gain_offset', '__rtw8852bx_ctrl_btg_bt_rx', '__rtw8852bx_bb_ctrl_rx_path', '__rtw8852bx_bb_set_plcp_tx', 'rtw8852bx_stop_pmac_tx', 'rtw8852bx_start_pmac_tx', 'rtw8852bx_bb_set_pmac_tx', '__rtw8852bx_bb_set_pmac_pkt_tx', '__rtw8852bx_bb_set_power', '__rtw8852bx_bb_cfg_tx_path', '__rtw8852bx_bb_tx_mode_switch', '__rtw8852bx_bb_backup_tssi', '__rtw8852bx_bb_restore_tssi', 'rtw8852bx_bb_ctrl_rf_mode_rx_path', '__rtw8852bx_bb_cfg_txrx_path']
functions = '\n'.join(value for _, value in sorted(function(common, name) for name in common_names)) + '\n' + '\n'.join(value for _, value in sorted(function(rfk, name) for name in rfk_names))
arrays = '\n'.join(re.findall(r'^static const (?:u32|s8) _tssi_\w+[^;]+;', rfk, re.M))
for match in re.finditer(r'^static const s8 _txpwr_track_delta_swingidx_\w+\[.*?=\s*\{', table, re.M):
    end, depth = match.end(), 1
    while depth:
        depth += (table[end] == '{') - (table[end] == '}')
        end += 1
    arrays += '\n' + table[match.start():end + 1]
pmac_table = re.search(r'^static const struct rtw89_reg3_def rtw8852bx_pmac_ht20_mcs7_tbl\[\] = \{.*?^\};', common, re.M | re.S)[0]
rfk_tables = re.findall(r'^static const struct rtw89_reg5_def \w+\[\] = \{.*?^\};', (linux / 'rtw8852b_rfk_table.c').read_text(), re.M | re.S)
rfk_enum = re.search(r'enum rtw89_rfk_flag \{.*?\};', phy, re.S)[0]
rfk_macros = re.search(r'#define RTW89_DECL_RFK_WRF.*?\nvoid\nrtw89_rfk_parser', phy, re.S)[0].split('\nvoid\n')[0]
header = ((linux / 'reg.h').read_text() + '\n' + core + '\n' + rfk).replace('\\\n', '')
defs = {match[1]: match[0] for match in re.finditer(r'^#define\s+(\w+)\s+[^\n]+', header, re.M)}
names = set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+|RFREG_MASK|MASK[A-Z0-9_]+)\b', functions))
selected = set(names)
todo = list(names)
while todo:
    name = todo.pop()
    for dependency in re.findall(r'\b[A-Z][A-Z0-9_]+\b', defs[name]):
        if dependency in defs and dependency not in selected:
            selected.add(dependency)
            todo.append(dependency)
definitions = '\n'.join(defs[name] for name in sorted(selected))
enums = '\n'.join(re.search(r'enum ' + name + r' \{.*?\};', core, re.S)[0] for name in ['rtw89_rf_path', 'rtw89_rf_path_bit', 'rtw89_subband', 'rtw89_gain_offset'])
tracking_enum = re.search(r'enum rtw89_fw_txpwr_trk_type \{.*?\};', (linux / 'fw.h').read_text(), re.S)[0]
tracking_config = re.search(r'const struct rtw89_fw_txpwr_track_cfg rtw89_8852b_trk_cfg = \{.*?\};', table, re.S)[0]
prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef int8_t s8;typedef int16_t s16;typedef int32_t s32;typedef int64_t s64;typedef u64 ktime_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m))&(m))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define clamp_t(t,v,l,h) ((t)(v)<(l)?(l):(t)(v)>(h)?(h):(t)(v))
#define S8_MIN (-128)
#define S8_MAX 127
#define DELTA_SWINGIDX_SIZE 30
#define RF_PATH_NUM_8852B 2
#define RF_PATH_MAX 4
#define BB_PATH_NUM_8852BX 2
#define RTW8852B_TSSI_PATH_NR 2
#define RTW89_PHY_0 0
#define RTW89_PHY_1 1
#define RTW89_CHANCTX_0 0
#define RTW89_SCH_TX_SEL_ALL 0
#define BTC_WRFKT_IQK 0
#define BTC_WRFK_ONESHOT_START 0
#define BTC_WRFK_ONESHOT_STOP 1
#define TSSI_ALIMK_2G 0
#define TSSI_ALIMK_5GL 1
#define TSSI_ALIMK_5GM 2
#define TSSI_ALIMK_5GH 3
#define TSSI_EXTRA_GROUP_BIT BIT(31)
#define TSSI_EXTRA_GROUP(i) (TSSI_EXTRA_GROUP_BIT|(i))
#define IS_TSSI_EXTRA_GROUP(i) ((i)&TSSI_EXTRA_GROUP_BIT)
#define TSSI_EXTRA_GET_GROUP_IDX1(i) ((i)&~TSSI_EXTRA_GROUP_BIT)
#define TSSI_EXTRA_GET_GROUP_IDX2(i) (TSSI_EXTRA_GET_GROUP_IDX1(i)+1)
#define _TSSI_DE_MASK GENMASK(21,12)
#define RTL8852BT 99
#define rtw89_debug(...) ((void)0)
enum rtw89_phy_idx {PHY0,PHY1};enum rtw89_chanctx_idx {CHAN0};enum rtw89_band {RTW89_BAND_2G,RTW89_BAND_5G};
enum rtw8852bx_pmac_mode {NONE_TEST,PKTS_TX,PKTS_RX,CONT_TX};
struct rtw8852bx_bb_pmac_info {bool en_pmac_tx,is_cck;enum rtw8852bx_pmac_mode mode;u32 tx_cnt;u16 period,tx_time;};
struct rtw8852bx_bb_tssi_bak {u32 tx_path,rx_path,p0_rfmode,p0_rfmode_ftm,p1_rfmode,p1_rfmode_ftm;s32 tx_pwr;};
struct rtw89_chan {u8 channel,subband_type,band_type,band_width;};
struct rtw89_reg3_def {u32 addr,mask,data;};struct rtw89_reg5_def {u8 flag,path;u32 addr,mask,data;};struct rtw89_rfk_tbl {const struct rtw89_reg5_def *defs;u32 size;};
struct rtw89_fw_txpwr_track_cfg {const s8 (*delta[16])[30];};
struct rtw89_tssi_info {u8 thermal[2];s8 tssi_cck[2][6],tssi_mcs[2][19],tssi_trim[2][8];bool alignment_done[2][4],check_backup_aligmk[2][90];u32 alignment_value[2][4][4],alignment_backup_by_ch[2][90][4];u64 tssi_alimk_time;};
struct rtw89_phy_efuse_gain {bool comp_valid,offset_valid;s8 comp[2][8],offset[2][16],offset_base[2],rssi_base[2];};
struct rtw89_hal{u8 antenna_rx,rx_nss;};
struct rtw89_dev {struct{struct{const struct rtw89_fw_txpwr_track_cfg *txpwr_trk;}elm_info;}fw;struct rtw89_tssi_info tssi;struct rtw89_hal hal;struct rtw89_phy_efuse_gain efuse_gain;const struct{u32 chip_id;}*chip;bool is_tssi_mode[4],dbcc_en;u32 words[0x20000/4],rf[2][0x10100];};
static struct rtw89_chan channel={1,0,0,0};static u32 now,count;static u64 hash;
static void val(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(8*i));hash*=1099511628211ULL;}}
static void write_trace(u32 k,u32 a,u32 v){count++;val(k);val(a);val(v);}
static const struct rtw89_chan *rtw89_chan_get(struct rtw89_dev*d,int c){return &channel;}
static s32 sign_extend32(u32 v,int bit){return (s32)(v<<(31-bit))>>(31-bit);}
static u32 rtw89_phy_read32_mask(struct rtw89_dev*d,u32 a,u32 m){u32 v=d->words[(0x10000+a)/4];if(a==0x1c18||a==0x3c18){unsigned path=a==0x3c18;u32 p=(d->words[(0x10000+R_TXPWR)/4]&B_TXPWR_MSK)>>__builtin_ctz(B_TXPWR_MSK);u32 active=d->words[(0x10000+R_PMAC_TX_PRD)/4]&B_PMAC_PTX_EN;v=active?BIT(16)+(p==48?300:230)+path*17:0;}return(v&m)>>__builtin_ctz(m);}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){d->words[a/4]=v;write_trace(4,a,v);}
static void rtw89_phy_write32(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32(d,a+0x10000,v);}
static void rtw89_phy_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){u32 old=d->words[(a+0x10000)/4];rtw89_phy_write32(d,a,(old&~m)|FIELD_PREP(m,v));}
static void rtw89_phy_write32_set(struct rtw89_dev*d,u32 a,u32 m){rtw89_phy_write32(d,a,d->words[(a+0x10000)/4]|m);}
static void rtw89_phy_write32_clr(struct rtw89_dev*d,u32 a,u32 m){rtw89_phy_write32(d,a,d->words[(a+0x10000)/4]&~m);}
#define rtw89_phy_write32_idx(d,a,m,v,p) rtw89_phy_write32_mask(d,a,m,v)
#define rtw89_phy_read32_idx(d,a,m,p) rtw89_phy_read32_mask(d,a,m)
static u32 rtw89_read_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m){return(d->rf[p][a]&m)>>__builtin_ctz(m);}
static bool rtw89_write_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m,u32 v){d->rf[p][a]=(d->rf[p][a]&~m)|FIELD_PREP(m,v);count++;val(36);val(p);val(a);val(m);val(v);return true;}
static void udelay(u32 us){now+=us;write_trace(8,us,0);}
static ktime_t ktime_get(void){return now;}static s64 ktime_us_delta(ktime_t a,ktime_t b){return a-b;}
static u8 rtw89_btc_phymap(struct rtw89_dev*d,int p,int paths,int c){return 0;}
static void rtw89_btc_ntfy_wl_rfk(struct rtw89_dev*d,int p,int k,int s){}
static void rtw89_chip_stop_sch_tx(struct rtw89_dev*d,int p,u32 *saved,int all){*saved=0x11223344;write_trace(56,p,*saved);}
static void rtw89_chip_resume_sch_tx(struct rtw89_dev*d,int p,u32 saved){write_trace(60,p,saved);}
static int rtw89_subband_to_gain_offset_band_of_ofdm(int band){return 1;}
static void rtw8852bt_ext_loss_avg_update(struct rtw89_dev*d,s8 a,s8 b){}
static void rtw89_rfk_parser(struct rtw89_dev*d,const struct rtw89_rfk_tbl*t){for(u32 i=0;i<t->size;i++){const struct rtw89_reg5_def*r=t->defs+i;switch(r->flag){case 0:rtw89_write_rf(d,r->path,r->addr,r->mask,r->data);break;case 1:rtw89_phy_write32_mask(d,r->addr,r->mask,r->data);break;case 2:rtw89_phy_write32_set(d,r->addr,r->mask);break;case 3:rtw89_phy_write32_clr(d,r->addr,r->mask);break;case 4:udelay(r->data);break;}}}
#define RTW89_DECLARE_RFK_TBL(n) const struct rtw89_rfk_tbl n##_tbl={n,ARRAY_SIZE(n)}
#define rtw89_rfk_parser_by_cond(d,c,t,f) rtw89_rfk_parser(d,(c)?(t):(f))
#define read_poll_timeout_atomic(op,v,cond,step,budget,pre,...) ({int err=-ETIMEDOUT;for(u32 t=0;t<=budget;t+=step){v=op(__VA_ARGS__);if(cond){err=0;break;}if(t<budget)udelay(step);}err;})
'''
aliases = '\n'.join('#define rtw8852bx_' + name + ' __rtw8852bx_' + name for name in ['bb_ctrl_rx_path','bb_set_plcp_tx','bb_set_pmac_pkt_tx','bb_set_power','bb_cfg_tx_path','bb_tx_mode_switch','bb_backup_tssi','bb_restore_tssi','ctrl_btg_bt_rx'])
declarations = '\n'.join(t + '\nRTW89_DECLARE_RFK_TBL(' + re.search(r'rtw8852b_\w+', t)[0] + ');' for t in rfk_tables)
main = r'''
int main(void){
puts("type TssiGolden=(u32,bool,bool,u32,u64,[[u32;4];2]);\npub(super) const CASES:&[TssiGolden]=&[");
for(int seed=0;seed<2;seed++)for(int erased=0;erased<2;erased++)for(int custom=0;custom<2;custom++){
 static struct rtw89_dev d;memset(&d,0,sizeof(d));u32 pattern=seed?0xa5a5a5a5:0;
 for(unsigned i=0;i<ARRAY_SIZE(d.words);i++)d.words[i]=pattern;
 for(int p=0;p<2;p++)for(unsigned a=0;a<ARRAY_SIZE(d.rf[p]);a++)d.rf[p][a]=pattern&0xfffff;
 d.hal.antenna_rx=RF_AB;d.tssi.thermal[0]=erased?255:32;d.tssi.thermal[1]=erased?255:34;
 d.efuse_gain.comp_valid=true;d.efuse_gain.offset_valid=true;d.efuse_gain.offset_base[0]=-30;d.efuse_gain.rssi_base[0]=46;
 for(int p=0;p<2;p++){d.tssi.tssi_cck[p][0]=p?5:-3;d.tssi.tssi_mcs[p][0]=p?11:-9;d.tssi.tssi_trim[p][0]=p?-4:2;d.efuse_gain.comp[p][0]=p?-5:7;d.efuse_gain.offset[p][0]=p?-2:3;d.efuse_gain.offset[p][1]=p?4:-6;}
 static const struct{u32 chip_id;}chip={1};d.chip=(const void*)&chip;
 static s8 curves[16][4][30];static struct rtw89_fw_txpwr_track_cfg tracking;
 if(custom){for(int t=0;t<16;t++){tracking.delta[t]=curves[t];for(int g=0;g<4;g++)for(int i=0;i<30;i++)curves[t][g][i]=t*3+i-64;}d.fw.elm_info.txpwr_trk=&tracking;}
 hash=14695981039346656037ULL;count=now=0;rtw8852b_tssi(&d,0,true,0);
 printf("(%u,%s,%s,%u,%llu,[",pattern,erased?"true":"false",custom?"true":"false",count,(unsigned long long)hash);
 for(int p=0;p<2;p++){printf("[");for(int i=0;i<4;i++)printf("%s%u",i?",":"",d.tssi.alignment_value[p][0][i]);printf("],");}puts("]),");
}puts("];");
puts("pub(super) const RX_AB_CASES:&[(u32,u32,u64)]=&[");
for(int seed=0;seed<2;seed++){
 static struct rtw89_dev d;memset(&d,0,sizeof(d));u32 pattern=seed?0xa5a5a5a5:0;
 for(unsigned i=0;i<ARRAY_SIZE(d.words);i++)d.words[i]=pattern;
 d.hal.antenna_rx=RF_AB;d.hal.rx_nss=2;
 d.efuse_gain.comp_valid=true;d.efuse_gain.offset_valid=true;d.efuse_gain.offset_base[0]=-30;d.efuse_gain.rssi_base[0]=46;
 for(int p=0;p<2;p++){d.efuse_gain.comp[p][0]=p?-5:7;d.efuse_gain.offset[p][0]=p?-2:3;d.efuse_gain.offset[p][1]=p?4:-6;}
 static const struct{u32 chip_id;}chip={1};d.chip=(const void*)&chip;
 hash=14695981039346656037ULL;count=now=0;__rtw8852bx_bb_cfg_txrx_path(&d);
 printf("(%u,%u,%llu),\n",pattern,count,(unsigned long long)hash);
}puts("];");return 0;}
'''
program = prefix.split('static u32 rtw89_phy_read32_mask')[0] + '\n' + definitions + '\n' + prefix[prefix.index('static u32 rtw89_phy_read32_mask'):] + '\n' + enums + '\n' + tracking_enum + '\n' + rfk_enum + '\n' + rfk_macros + '\n' + arrays + '\n' + tracking_config + '\n' + pmac_table + '\n' + declarations + '\n' + aliases + '\n' + functions + '\n' + main
if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='narf-8852b-tssi-c-') as temporary:
        c, executable = Path(temporary) / 'oracle.c', Path(temporary) / 'oracle'
        c.write_text(program)
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wno-unused-function', str(c), '-o', str(executable)], check=True)
        output = subprocess.check_output([str(executable)], text=True)
    directory.joinpath('golden.rs').write_text('// Unmodified Linux B TSSI/common PMAC callbacks.\n' + output)
