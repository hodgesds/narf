#!/usr/bin/env python3
"""Original exact B MAC/BB channel1/20MHz, signed PG/gain/RPL compensation."""
from pathlib import Path
import argparse,re,hashlib,tempfile,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;s=(a.linux/'rtw8852b_common.c').read_text();core=(a.linux/'core.h').read_text();phyh=(a.linux/'phy.h').read_text();phyc=(a.linux/'phy.c').read_text()
def block(src,pat):
 m=re.search(pat,src,re.M);e=src.index('{',m.end())+1;depth=1
 while depth:depth+=(src[e]=='{')-(src[e]=='}');e+=1
 return src[m.start():e]
def f(n):return block(s,r'^(?:static\s+)?(?:void|u8)\s+'+n+r'\s*\(')+'\n'
names=['__rtw8852bx_set_channel_mac','rtw8852bx_ctrl_sco_cck','rtw8852bx_sco_mapping','rtw8852bx_set_gain_error','rtw8852bx_set_gain_offset','rtw8852bx_set_rxsc_rpl_comp','rtw8852bx_ctrl_ch','rtw8852b_bw_setting','rtw8852bx_ctrl_bw','rtw8852bx_ctrl_cck_en','rtw8852bx_5m_mask','__rtw8852bx_bb_reset_all','rtw8852bx_bb_set_pop','__rtw8852bx_set_channel_bb']
body=''.join(f(n) for n in names)
arrays=''.join(re.search(r'^static const u32 '+n+r'\[14\] = \{.*?^\};',s,re.M|re.S).group(0)+'\n' for n in ['rtw8852bx_sco_barker_threshold','rtw8852bx_sco_cck_threshold'])
arrays+=block(s,r'^struct rtw8852bx_bb_gain\s*')+';\n'
arrays+=''.join(re.search(r'^static const struct rtw8852bx_bb_gain '+n+r'\[.*?^\};',s,re.M|re.S).group(0)+'\n' for n in ['bb_gain_lna','bb_gain_tia'])
layouts=block(core,r'^struct rtw89_phy_bb_gain_info\s*')+';\n'+block(core,r'^struct rtw89_phy_efuse_gain\s*')+';\n'
enums=''.join(re.search(r'enum \w+ \{[^}]*\b'+n+r'\b[^}]*\};',core,re.S).group(0)+'\n' for n in ['RTW89_CH_2G','RTW89_GAIN_OFFSET_2G_OFDM','RTW89_BB_GAIN_BAND_2G'])
helpers=''.join(block(phyh,r'^(?:static inline\s+)?enum \w+\s+'+n+r'\s*\(')+'\n' for n in ['rtw89_subband_to_gain_offset_band_of_ofdm','rtw89_subband_to_bb_gain_band'])
# Exact source 2GHz channel-index expression; other bands are outside profile.
encode=block(phyc,r'^u8 rtw89_encode_chan_idx\s*\(');expr=re.search(r'case RTW89_BAND_2G:(.*?)return chan_idx;',encode,re.S).group(1)
helpers+='static u8 rtw89_encode_chan_idx(struct rtw89_dev*rtwdev,u8 central_ch,u8 band){assert(central_ch==1&&band==0);u8 chan_idx;'+expr+'return chan_idx;}\n'
headers=(a.linux/'reg.h').read_text()+'\n'+core+'\n'+phyh+'\n'+phyc
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)}
selected=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+|MASK[A-Z0-9_]*|RTW89_CH_(?:BASE_IDX_MASK|BASE_IDX_2G|OFFSET_MASK))\b',body+arrays+helpers));todo=list(selected)
# CH_BASE_IDX_2G belongs to a source enum.
if 'RTW89_CH_BASE_IDX_2G' not in defs:
 enums+=re.search(r'enum \w+ \{[^}]*\bRTW89_CH_BASE_IDX_2G\b[^}]*\};',phyc+'\n'+phyh,re.S).group(0)+'\n';selected.discard('RTW89_CH_BASE_IDX_2G');todo=list(selected)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in selected:selected.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(selected))
pre=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef int16_t s16;typedef uint32_t u32;typedef int32_t s32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m))&(m))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define u32_encode_bits(v,m) FIELD_PREP(m,v)
#define S8_MIN (-128)
#define S8_MAX 127
#define clamp_t(t,v,l,h) ((t)(v)<(t)(l)?(t)(l):((t)(v)>(t)(h)?(t)(h):(t)(v)))
#define RF_PATH_MAX 4
#define LNA_GAIN_NUM 7
#define TIA_GAIN_NUM 2
#define BB_PATH_NUM_8852BX 2
#define RTW89_BB_RXSC_NUM_40 9
#define RTW89_BB_RXSC_NUM_80 13
#define RTW89_BB_RXSC_NUM_160 15
#define RTW89_PHY_NUM 2
#define RF_A 1
#define RF_B 2
#define RF_AB 3
#define IEEE80211_CONF_MONITOR 1
#define RTW89_PHY_0 0
enum rtw89_core_chip_id{RTL8852B=1,RTL8852BT=2};
#define RTW89_BAND_2G 0
#define RTW89_BAND_5G 1
#define RTW89_BAND_6G 2
#define RTW89_SC_20_UPPER 1
#define RTW89_SC_20_LOWER 2
#define RTW89_SC_20_UPMOST 3
#define RTW89_SC_20_LOWEST 4
#define fallthrough __attribute__((fallthrough))
#define rtw89_warn(...) ((void)0)
enum rtw89_rf_path{RF_PATH_A,RF_PATH_B};enum rtw89_phy_idx{PHY0};enum{RTW89_CHANNEL_WIDTH_20,RTW89_CHANNEL_WIDTH_40,RTW89_CHANNEL_WIDTH_80,RTW89_CHANNEL_WIDTH_160,RTW89_CHANNEL_WIDTH_5,RTW89_CHANNEL_WIDTH_10};
struct rtw89_chan{u8 channel,primary_channel,subband_type,pri_ch_idx,band_width,band_type;u32 freq;};
struct rtw89_chip_info{int chip_id;};struct rtw89_hal{u8 antenna_rx;};
'''
shim=r'''struct rtw89_dev{struct rtw89_chip_info*chip;struct rtw89_hal hal;struct rtw89_phy_efuse_gain efuse_gain;struct{struct rtw89_phy_bb_gain_info ax;}bb_gain;struct{struct{u32 flags;}conf;}*hw;u32 words[0x20000/4];};
static u64 hash;static u32 count;
static void value(u32 v){for(int i=0;i<4;i++){hash^=(u8)(v>>(i*8));hash*=1099511628211ULL;}}
static void record(u32 k,u32 a,u32 v){count++;value(k);value(a);value(v);}
static u8 rtw89_read8(struct rtw89_dev*d,u32 a){return ((u8*)d->words)[a];}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){return d->words[a/4];}
static void rtw89_write8(struct rtw89_dev*d,u32 a,u8 v){((u8*)d->words)[a]=v;record(1,a,v);}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){d->words[a/4]=v;record(4,a,v);}
static void rtw89_write8_mask(struct rtw89_dev*d,u32 a,u8 m,u8 v){rtw89_write8(d,a,(rtw89_read8(d,a)&~m)|FIELD_PREP(m,v));}
static void rtw89_write8_set(struct rtw89_dev*d,u32 a,u8 m){rtw89_write8(d,a,rtw89_read8(d,a)|m);}
static void rtw89_write8_clr(struct rtw89_dev*d,u32 a,u8 m){rtw89_write8(d,a,rtw89_read8(d,a)&~m);}
static u32 rtw89_mac_reg_by_idx(struct rtw89_dev*d,u32 a,u8 i){assert(i==0);return a;}
static void rtw89_phy_write32(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32(d,a+0x10000,v);}
static void rtw89_phy_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){a+=0x10000;rtw89_write32(d,a,(rtw89_read32(d,a)&~m)|FIELD_PREP(m,v));}
static void rtw89_phy_write32_idx(struct rtw89_dev*d,u32 a,u32 m,u32 v,u8 i){assert(i==0);rtw89_phy_write32_mask(d,a,m,v);}
static void rtw89_phy_write32_clr(struct rtw89_dev*d,u32 a,u32 m){a+=0x10000;rtw89_write32(d,a,rtw89_read32(d,a)&~m);}
static u32 rtw89_phy_read32_idx(struct rtw89_dev*d,u32 a,u32 m,u8 i){assert(i==0);return FIELD_GET(m,rtw89_read32(d,a+0x10000));}
static u8 rtw89_phy_get_txsc(struct rtw89_dev*d,const struct rtw89_chan*c,u8 w){assert(0);return 0;}
static void rtw8852bt_ext_loss_avg_update(struct rtw89_dev*d,s8 a,s8 b){assert(0);}
static void rtw8852bt_adc_cfg(struct rtw89_dev*d,u8 b,u8 p){assert(0);}
static void rtw8852bt_set_csi_tone_idx(struct rtw89_dev*d,const struct rtw89_chan*c,u8 i){assert(0);}
static void fsleep(u32 us){record(8,us,0);}
'''
main=r'''int main(void){puts("REGS");'''+''.join('printf("pub(super) const '+n+': u32 = 0x%x;\\n",(u32)'+n+');\n' for n in sorted(selected))+r'''
puts("CASES\npub(super) const CASES: &[(u8,u8,u8,u32,u64)] = &[");for(int seed=0;seed<2;seed++)for(int rx=0;rx<4;rx++)for(int flags=0;flags<4;flags++){
 struct rtw89_chip_info chip={RTL8852B};static struct rtw89_dev d;memset(&d,0,sizeof(d));d.chip=&chip;d.hal.antenna_rx=RF_AB;typeof(*d.hw) hw={};d.hw=&hw;
 for(u32 i=0;i<0x20000/4;i++)d.words[i]=seed?0xa5a5a5a5:0;d.words[(R_CHBW_MOD_V1+0x10000)/4]=(d.words[(R_CHBW_MOD_V1+0x10000)/4]&~B_ANT_RX_SEG0)|FIELD_PREP(B_ANT_RX_SEG0,rx);
 for(int p=0;p<2;p++){for(int i=0;i<7;i++)d.bb_gain.ax.lna_gain[0][p][i]=(p?13:-9)-i*5;for(int i=0;i<2;i++)d.bb_gain.ax.tia_gain[0][p][i]=(p?35:-42)+i;d.bb_gain.ax.rpl_ofst_20[0][p]=-7+p;for(int i=0;i<9;i++)d.bb_gain.ax.rpl_ofst_40[0][p][i]=(p?5:-6)+i*3;for(int i=0;i<13;i++)d.bb_gain.ax.rpl_ofst_80[0][p][i]=(p?-1:2)-i*4;d.efuse_gain.offset[p][0]=p?7:-8;d.efuse_gain.offset[p][1]=p?-7:6;d.efuse_gain.comp[p][0]=p?7:-8;}
 d.efuse_gain.comp_valid=flags&1;d.efuse_gain.offset_valid=flags&2;d.efuse_gain.offset_base[0]=-91;d.efuse_gain.rssi_base[0]=101;
 struct rtw89_chan c={.channel=1,.primary_channel=1,.subband_type=RTW89_CH_2G,.band_width=RTW89_CHANNEL_WIDTH_20,.band_type=RTW89_BAND_2G,.freq=2412};hash=14695981039346656037ULL;count=0;__rtw8852bx_set_channel_mac(&d,&c,0);__rtw8852bx_set_channel_bb(&d,&c,0);
 printf("(%u,%u,%u,%u,0x%llx),\n",seed?165:0,rx,flags,count,(unsigned long long)hash);
}puts("];" );}'''
source=pre+enums+layouts+regs+'\n'+shim+helpers+arrays+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-bbchannel-c-') as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2','-fwrapv',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
r,g=out.removeprefix('REGS\n').split('CASES\n');comment='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B MAC/BB channel SHA256 '+hashlib.sha256((body+regs+arrays+layouts+helpers+enums).encode()).hexdigest()+'\n'
digest=hashlib.sha256((body+regs+arrays+layouts+helpers+enums).encode()).digest()
recipe='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\npub(super) const RECIPE:[u8;32]=['+','.join(map(str,digest))+'];\n'
recipe=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=recipe.encode()).decode()
for name,value in [('recipe.rs',recipe),('regs.rs',comment+r),('golden.rs',comment+g)]:
 if a.check:
  if (d/name).read_text()!=value:raise SystemExit(name+' differs')
 else:(d/name).write_text(value)
