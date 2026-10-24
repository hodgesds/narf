#!/usr/bin/env python3
"""Run original static B PHYSTS/DIG/CFO/EDCCA callbacks on fixed awake PHY0.

Only inert register/analog/channel adapters and software-only tracking helpers
are substituted. The selected B branches have no IGI/RFE/antdiv/BB-wrap port.
"""
from pathlib import Path
import argparse, hashlib, re, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true')
a=p.parse_args();d=Path(__file__).parent
phy=(a.linux/'phy.c').read_text();core=(a.linux/'core.h').read_text();ph=(a.linux/'phy.h').read_text();chip=(a.linux/'rtw8852b.c').read_text()
def function(name):
 m=re.search(r'^(?:static\s+)?(?:bool|u8|u32|void)\s+'+name+r'\s*\(',phy,re.M)
 if not m:raise RuntimeError(name)
 e=phy.index('{',m.end())+1;depth=1
 while depth:depth+=(phy[e]=='{')-(phy[e]=='}');e+=1
 return m.start(),phy[m.start():e]
names=['rtw89_physts_ie_page_valid','rtw89_phy_get_ie_bitmap_addr','rtw89_physts_get_ie_bitmap',
 'rtw89_physts_set_ie_bitmap','rtw89_physts_enable_fail_report','rtw89_physts_enable_hdr_2','__rtw89_physts_parsing_init',
 'rtw89_phy_dig_para_reset','rtw89_phy_dig_set_igi_cr','rtw89_phy_dig_sdagc_follow_pagc_config',
 'rtw89_phy_dig_cal_under_region','__rtw89_phy_dig_dyn_pd_th','rtw89_phy_dig_dyn_pd_th','rtw89_phy_dig_reset',
 'rtw89_phy_cfo_set_crystal_cap','rtw89_dcfo_comp_init','rtw89_phy_cfo_init','__rtw89_phy_edcca_init']
# Function is named sdagc_follow_pagc_config in this source release.
names=[n.replace('rtw89_phy_dig_sdagc_follow_pagc_config','rtw89_phy_dig_sdagc_follow_pagc_config') for n in names]
functions='\n'.join(v for _,v in sorted(function(n) for n in names))
def structure(name):
 return re.search(r'^struct '+name+r' \{.*?^\};',core,re.M|re.S).group()
types='\n'.join(structure(n) for n in ['rtw89_reg_def','rtw89_agc_gaincode_set','rtw89_dig_regs','rtw89_edcca_regs'])
enums='\n'.join(re.search(r'^enum '+n+r' \{.*?^\};',ph,re.M|re.S).group() for n in ['rtw89_phy_status_bitmap','rtw89_phy_status_ie_type'])
digregs=re.search(r'^static const struct rtw89_dig_regs rtw8852b_dig_regs = \{.*?^\};',chip,re.M|re.S).group()
edccaregs=re.search(r'^static const struct rtw89_edcca_regs rtw8852b_edcca_regs = \{.*?^\};',chip,re.M|re.S).group()
headers='\n'.join((a.linux/n).read_text() for n in ['reg.h','phy.h','mac.h','core.h'])
headers=headers.replace('\\\n','')
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)}
needed=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+|MASKDWORD|PD_TH_\w+|CCKPD_TH_MIN_RSSI|IGI_RSSI_MAX|[LTR]XB?_IDX_MAX|CFO_BOUND|XTAL_SC_X[IO]_MASK)\b',functions+digregs+edccaregs))
needed.update(['LNA_IDX_MAX','TIA_IDX_MAX','RXB_IDX_MAX'])
needed.update(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+)\b',(d.parent/'phy_operating.rs').read_text()))
todo=list(needed)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in needed:needed.add(dep);todo.append(dep)
definitions='\n'.join(defs[n] for n in sorted(needed))
prefix=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;typedef int32_t s32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define clamp_t(t,v,lo,hi) min_t(t,max_t(t,v,lo),hi)
#define rtw89_debug(...) ((void)0)
#define fallthrough ((void)0)
#define RTW89_PHY_0 0
#define RTW89_PHY_NUM 2
#define RTW89_CHIP_AX 0
#define RTL8852A 1
#define RTL8852B 2
#define RTL8851B 3
#define RTL8922A 4
#define CHIP_CAV 0
#define RTW89_DM_DIG_PD 0
#define IEEE80211_CONF_MONITOR 1
#define RTW89_CHANNEL_WIDTH_20 0
#define RTW89_CHANNEL_WIDTH_40 1
#define RTW89_CHANNEL_WIDTH_80 2
#define RTW89_CHANNEL_WIDTH_160 3
#define RTW89_TP_BASED_AVG_MODE 0
#define RTW89_PHY_DCFO_STATE_NORMAL 0
#define RTW89_CFO_UL_OFDMA_ACC_ENABLE 0
#define XTAL_SI_XTAL_SC_XI 4
#define XTAL_SI_XTAL_SC_XO 5
enum rtw89_phy_idx {PHY0};enum rtw89_bandwidth {BW0};
'''
shim=r'''
struct rtw89_physts_regs {u32 setting_addr,dis_trigger_fail_mask,dis_trigger_brk_mask;};
struct rtw89_cfo_regs {u32 comp,weighting_mask,comp_seg0,valid_0_mask;};
struct rtw89_phy_gen_def {u32 physt_bmp_start,physt_bmp_eht;u8 physt_gen;const struct rtw89_physts_regs*physts;const struct rtw89_cfo_regs*cfo;};
struct rtw89_chip_info {int chip_id,chip_gen;bool cfo_hw_comp;const struct rtw89_phy_gen_def*phy_def;const struct rtw89_dig_regs*dig_regs;const struct rtw89_edcca_regs*edcca_regs;};
struct rtw89_dig_info {struct rtw89_agc_gaincode_set cur_gaincode,force_gaincode;u8 dyn_igi_max,dyn_igi_min,dyn_pd_th_max,dyn_pd_th_max_unused,dyn_pd_max_cnt,pd_low_th_ofst,igi_rssi;bool is_linked_pre,bypass_dig;u32 bak_dig;};
struct rtw89_edcca_bak {u32 unused;};
struct rtw89_bb_ctx {u8 phy_idx;struct rtw89_dig_info dig;struct rtw89_edcca_bak edcca_bak;};
struct rtw89_cfo_tracking_info {u8 crystal_cap_default,crystal_cap,def_x_cap,x_cap_ub,x_cap_lb,lock_cnt,phy_cfo_trk_cnt;bool is_adjust,divergence_lock_en,apply_compensation,cfo_trig_by_timer_en;s8 x_cap_ofst;int rtw89_multi_cfo_mode,residual_cfo_acc,phy_cfo_status,cfo_ul_ofdma_acc_mode,cfo_timer_ms;};
struct rtw89_chan {u8 band_width;};struct rtw89_entity_conf {const struct rtw89_chan*chans[2];};
struct rtw89_hal{u8 cv;bool support_igi,support_cckpd;u32 disabled_dm_bitmap;u8 fixed_dig_pd_th,fixed_dig_cck_pd_th;};struct rtw89_efuse{u8 xtal_cap;};
struct rtw89_dev {const struct rtw89_chip_info*chip;struct{struct{u32 flags;}conf;}*hw;struct rtw89_hal hal;struct rtw89_efuse efuse;struct rtw89_cfo_tracking_info cfo_tracking;u32 words[0x20000/4];u8 xtal[256];};
static u32 count;static unsigned long long hash;
static void record(u32 k,u32 a,u32 v){count++;u32 words[]={k,a,v};for(int j=0;j<3;j++)for(int i=0;i<4;i++){hash^=(u8)(words[j]>>(i*8));hash*=1099511628211ULL;}}
static u32 rtw89_phy_read32_idx(struct rtw89_dev*d,u32 a,u32 m,int phy){return FIELD_GET(m,d->words[(0x10000+a)/4]);}
static void rtw89_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){d->words[a/4]=(d->words[a/4]&~m)|FIELD_PREP(m,v);record(4,a,d->words[a/4]);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 m){rtw89_write32_mask(d,a,m,0);}
static void rtw89_phy_write32_idx(struct rtw89_dev*d,u32 a,u32 m,u32 v,int phy){rtw89_write32_mask(d,a+0x10000,m,v);}
static void rtw89_phy_write32_idx_clr(struct rtw89_dev*d,u32 a,u32 m,int p){rtw89_phy_write32_idx(d,a,m,0,p);}
static void rtw89_phy_write32_idx_set(struct rtw89_dev*d,u32 a,u32 m,int p){rtw89_phy_write32_idx(d,a,m,1,p);}
static void rtw89_phy_set_phy_regs(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_phy_write32_idx(d,a,m,v,0);}
static void rtw89_entity_get_conf(struct rtw89_dev*d,struct rtw89_entity_conf*c){static struct rtw89_chan chan={0};c->chans[0]=&chan;}
static void rtw89_phy_dig_set_lna_idx(struct rtw89_dev*d,struct rtw89_bb_ctx*b,u8 v){__builtin_trap();}
static void rtw89_phy_dig_set_tia_idx(struct rtw89_dev*d,struct rtw89_bb_ctx*b,u8 v){__builtin_trap();}
static void rtw89_phy_dig_set_rxb_idx(struct rtw89_dev*d,struct rtw89_bb_ctx*b,u8 v){__builtin_trap();}
/* Updates only software fa/rssi arrays for a future periodic worker. */
static void rtw89_phy_dig_update_para(struct rtw89_dev*d,struct rtw89_bb_ctx*b){}
static void rtw89_phy_cfo_set_xcap_reg(struct rtw89_dev*d,bool x,u8 v){__builtin_trap();}
static u8 rtw89_phy_cfo_get_xcap_reg(struct rtw89_dev*d,bool x){__builtin_trap();}
static int rtw89_mac_write_xtal_si(struct rtw89_dev*d,u8 a,u8 v,u8 m){d->xtal[a]=(d->xtal[a]&~m)|(v&m);record(8,a,v);return 0;}
static int rtw89_mac_read_xtal_si(struct rtw89_dev*d,u8 a,u8*v){*v=d->xtal[a];record(9,a,*v);return 0;}
static const u8 rssi_nolink=22,pd_low_th_offset=16,dynamic_igi_min=0x20,igi_max_performance_mode=0x5a,dynamic_pd_threshold_max=0;
'''
main=r'''
int main(void){puts("type Golden=(u8,u8,u8,u32,u64,[u8;3]);\npub(super) const CASES:&[Golden]=&[");
u8 caps[]={0,0x33,0x7f,0x80};u8 cuts[]={0,1,15};
for(int seed=0;seed<2;seed++)for(int ci=0;ci<3;ci++)for(int xi=0;xi<4;xi++){
 const struct rtw89_physts_regs ps={R_PLCP_HISTOGRAM,B_STS_DIS_TRIG_BY_FAIL,B_STS_DIS_TRIG_BY_BRK};const struct rtw89_cfo_regs cfo={R_DCFO_WEIGHT,B_DCFO_WEIGHT_MSK,R_DCFO_OPT,B_DCFO_OPT_EN};
 const struct rtw89_phy_gen_def pg={R_PHY_STS_BITMAP_ADDR_START,0xfc,0,&ps,&cfo};const struct rtw89_chip_info chip={RTL8852B,RTW89_CHIP_AX,true,&pg,&rtw8852b_dig_regs,&rtw8852b_edcca_regs};
 static struct rtw89_dev dev;memset(&dev,0,sizeof(dev));typeof(*dev.hw)hw={0};dev.hw=&hw;dev.chip=&chip;dev.hal.cv=cuts[ci];dev.hal.support_cckpd=cuts[ci]>0;dev.efuse.xtal_cap=caps[xi];struct rtw89_bb_ctx bb={0};
 u32 s=seed?0xa5a5a5a5:0;for(int i=0;i<0x20000/4;i++)dev.words[i]=s;memset(dev.xtal,seed?0xa5:0,256);count=0;hash=14695981039346656037ULL;
 __rtw89_physts_parsing_init(&dev,0);rtw89_phy_dig_reset(&dev,&bb);rtw89_phy_cfo_init(&dev);__rtw89_phy_edcca_init(&dev,&bb);
 printf("(%u,%u,%u,%u,0x%llx,[%u,%u,%u]),\n",seed?165:0,cuts[ci],caps[xi],count,hash,dev.cfo_tracking.crystal_cap,dev.cfo_tracking.x_cap_lb,dev.cfo_tracking.x_cap_ub);
}puts("];");return 0;}
'''
with tempfile.TemporaryDirectory(prefix='rtw89-operating-') as td:
 td=Path(td);code=prefix+definitions+'\n'+types+'\n'+enums+'\n'+shim+'\n'+digregs+'\n'+edccaregs+'\n'+functions+'\n'+main
 (td/'o.c').write_text(code);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);golden=subprocess.check_output([str(td/'o')]).decode()
 production=(d.parent/'phy_operating.rs').read_text();constants=sorted(set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+)\b',production)))
 (td/'r.c').write_text(prefix+definitions+'\nint main(void){'+''.join(f'printf("pub(super) const {n}:u32=0x%x;\\n",(u32){n});' for n in constants)+'}')
 subprocess.run(['cc','-std=gnu11','-O2',str(td/'r.c'),'-o',str(td/'r')],check=True);registers=subprocess.check_output([str(td/'r')]).decode()
digest=hashlib.sha256((functions+types+enums+definitions+digregs+edccaregs).encode()).digest()
recipe='pub(super) const RECIPE:[u8;32]=['+','.join(map(str,digest))+'];\n'
for name,body in [('golden.rs',golden),('registers.rs',registers),('recipe.rs',recipe)]:
 value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux static B operating PHY SHA256 '+digest.hex()+'\n'+body
 value=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=value.encode()).decode()
 if a.check:
  if (d/name).read_text()!=value:raise SystemExit(name+' differs')
 else:(d/name).write_text(value)
