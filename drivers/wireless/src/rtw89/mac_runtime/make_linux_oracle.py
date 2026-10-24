#!/usr/bin/env python3
"""Compile original RTL8852B MAC callbacks against a deterministic register bus."""
from pathlib import Path
import argparse, hashlib, re, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true');a=p.parse_args()
d=Path(__file__).parent;mac=(a.linux/'mac.c').read_text();core=(a.linux/'core.h').read_text()
chip=(a.linux/'rtw8852b.c').read_text();common=(a.linux/'rtw8852b_common.c').read_text()
def structure(name):
    m=re.search(r'\bstruct '+name+r'\s*\{',core);start=m.start();end=m.end();depth=1
    while depth:depth+=(core[end]=='{')-(core[end]=='}');end+=1
    return core[start:core.index(';',end)+1]+'\n'
def function(name,source=mac):
    m=re.search(r'^(?:(?:static|inline)\s+)*(?:int|void|bool|u32|const struct \w+\s*\*)\s*'+name+r'\s*\(',source,re.M)
    if not m:raise RuntimeError(name)
    start=m.start();end=source.index('{',m.end())+1;depth=1
    while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]+'\n'
def data(name,source=chip):
    m=re.search(r'^static const struct \w+ '+name+r'(?:\[\])?\s*=\s*\{',source,re.M)
    start=m.start();end=m.end();depth=1
    while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:source.index(';',end)+1]+'\n'
functions=['cmac_func_en_ax','dmac_func_en_ax','chip_func_en_ax','sys_init_ax',
    'hfc_reset_param','hfc_ch_cfg_chk','hfc_pub_info_chk','hfc_pub_cfg_chk','hfc_ch_ctrl',
    'hfc_upd_ch_info','hfc_pub_ctrl','hfc_get_mix_info_ax','hfc_upd_mix_info','hfc_h2c_cfg_ax',
    'hfc_mix_cfg_ax','hfc_func_en_ax','rtw89_mac_hfc_init','get_dle_mem_cfg','dle_used_size',
    'dle_expected_used_size','dle_func_en_ax','dle_clk_en_ax','dle_mix_cfg_ax','chk_dle_rdy_ax',
    'wde_quota_cfg_ax','ple_quota_cfg_ax','dle_quota_cfg','rtw89_mac_dle_init',
    'preload_init_set_ax','is_qta_poh','rtw89_mac_preload_init','_patch_ss2f_path',
    'sta_sch_init_ax','mpdu_proc_init_ax','sec_eng_init_ax','dmac_init_ax','addr_cam_init_ax',
    'scheduler_init_ax','rtw89_mac_typ_fltr_opt_ax','rx_fltr_init_ax','_patch_dis_resp_chk',
    'cca_ctrl_init_ax','nav_ctrl_init_ax','spatial_reuse_init_ax','tmac_init_ax',
    'trxptcl_init_ax','rst_bacam','rmac_init_ax','cmac_com_init_ax','rtw89_mac_is_qta_dbcc',
    'ptcl_init_ax','cmac_dma_init_ax','cmac_init_ax','rtw89_wdrls_imr_enable',
    'rtw89_wsec_imr_enable','rtw89_mpdu_trx_imr_enable','rtw89_sta_sch_imr_enable',
    'rtw89_txpktctl_imr_enable','rtw89_wde_imr_enable','rtw89_ple_imr_enable',
    'rtw89_pktin_imr_enable','rtw89_dispatcher_imr_enable','rtw89_cpuio_imr_enable',
    'rtw89_bbrpt_imr_enable','rtw89_scheduler_imr_enable','rtw89_ptcl_imr_enable',
    'rtw89_cdma_imr_enable','rtw89_phy_intf_imr_enable','rtw89_rmac_imr_enable',
    'rtw89_tmac_imr_enable','enable_imr_ax','err_imr_ctrl_ax','set_host_rpr_ax',
    'rtw89_mac_write_xtal_si_ax']
original=[function(n) for n in functions]+[function('__rtw8852bx_mac_enable_bb_rf',common)]
code='''#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define BIT(n) (1ULL<<(n))
#define GENMASK(h,l) ((~0ULL<<(l))&(~0ULL>>(63-(h))))
#define FIELD_PREP(m,v) (((u64)(v)<<__builtin_ctzll(m))&(m))
#define FIELD_PREP_CONST(m,v) FIELD_PREP(m,v)
#define FIELD_GET(m,v) (((u64)(v)&(m))>>__builtin_ctzll(m))
#define u32_encode_bits(v,m) FIELD_PREP(m,v)
#define u32_replace_bits(o,v,m) (((o)&~(m))|FIELD_PREP(m,v))
#define u16_replace_bits(o,v,m) u32_replace_bits(o,v,m)
#define u32_get_bits(v,m) FIELD_GET(m,v)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define U16_MAX UINT16_MAX
#define rtw89_io_pack(...) ((void)0)
#define rtw89_io_unpack(...) ((void)0)
#define rtw89_err(...) ((void)0)
#define rtw89_warn(...) ((void)0)
#define test_bit(...) 0
#define EXPORT_SYMBOL(x)
enum rtw89_core_chip_id {RTL8852A,RTL8852B,RTL8852C,RTL8851B,RTL8852BT};
enum rtw89_qta_mode {RTW89_QTA_SCC,RTW89_QTA_DLFW,RTW89_QTA_WOW,RTW89_QTA_INVALID};
enum rtw89_mac_idx {RTW89_MAC_0,RTW89_MAC_1};
enum rtw89_mac_hwmod_sel {RTW89_DMAC_SEL,RTW89_CMAC_SEL};
enum rtw89_machdr_frame_type {RTW89_MGNT,RTW89_CTRL,RTW89_DATA};
enum rtw89_mac_fwd_target {RTW89_FWD_DONT_CARE,RTW89_FWD_TO_HOST,RTW89_FWD_TO_WLAN_CPU};
#define RTW89_HCI_TYPE_PCIE 0
#define RTW89_HCI_TYPE_USB 1
#define RTW89_DMA_CH_NUM 13
#define RTW89_DMA_ACH0 0
#define RTW89_DMA_B1HI 11
#define RTW89_DMA_H2C 12
#define RTW89_WDE_PG_64 64
#define RTW89_WDE_PG_128 128
#define RTW89_WDE_PG_256 256
#define RTW89_PLE_PG_64 64
#define RTW89_PLE_PG_128 128
#define RTW89_PLE_PG_256 256
#define DLE_BOUND_UNIT 8192
#define TRXCFG_WAIT_CNT 2000
#define CHIP_CBV 1
#define RTW89_RPR_MODE_POH 0
#define RTW89_RPR_MODE_STF 1
#define XTAL_SI_WL_RFC_S0 0x80
#define XTAL_SI_WL_RFC_S1 0x81
#define FULL_BIT_MASK 255
'''
code+='#include "'+str(a.linux/'reg.h')+'"\n'
mh=(a.linux/'mac.h').read_text().replace('\\\n','')
code+='\n'.join(line for line in mh.splitlines() if line.startswith('#define S_AX_WDE_PAGE_SEL_') or line.startswith('#define S_AX_PLE_PAGE_SEL_'))+'\n'
for n in ['rtw89_hfc_ch_cfg','rtw89_hfc_ch_info','rtw89_hfc_pub_cfg','rtw89_hfc_pub_info',
    'rtw89_hfc_prec_cfg','rtw89_hfc_param','rtw89_hfc_param_ini','rtw89_dle_size',
    'rtw89_wde_quota','rtw89_ple_quota','rtw89_rsvd_quota','rtw89_dle_rsvd_size',
    'rtw89_dle_input','rtw89_dle_mem','rtw89_reg3_def','rtw89_page_regs','rtw89_imr_info','rtw89_rrsr_cfgs']:
    code+=structure(n)
refs=['wde_size7','ple_size6','wde_qt7','ple_qt18','ple_qt58','hfc_preccfg_pcie']
code+='struct selected_mac_size{\n'
for n in refs:
    t='rtw89_hfc_prec_cfg' if n.startswith('hfc') else 'rtw89_dle_size' if '_size' in n else 'rtw89_wde_quota' if n.startswith('wde') else 'rtw89_ple_quota'
    code+='struct '+t+' '+n+';\n'
code+='};static const struct selected_mac_size rtw89_mac_size={\n'
for n in refs:code+=re.search(r'\.'+n+r'\s*=\s*\{.*?\}',mac,re.S).group()+',\n'
code+='};\n'
for n in ['rtw8852b_hfc_chcfg_pcie','rtw8852b_hfc_pubcfg_pcie','rtw8852b_page_regs','rtw8852b_imr_info','rtw8852b_rrsr_cfgs']:
    code+=data(n)
code+='''static const struct rtw89_hfc_param_ini param_ini[]={
 [RTW89_QTA_SCC]={rtw8852b_hfc_chcfg_pcie,&rtw8852b_hfc_pubcfg_pcie,&rtw89_mac_size.hfc_preccfg_pcie,0}};
static const struct rtw89_dle_mem dle_mem[]={
'''
block=data('rtw8852b_dle_mem_pcie');code+=re.search(r'\[RTW89_QTA_SCC\]\s*=\s*\{.*?\}',block,re.S).group()+',};\n'
code+='''struct rtw89_dev;
struct rtw89_mac_gen_def{
 void(*dle_func_en)(struct rtw89_dev*,bool);void(*dle_clk_en)(struct rtw89_dev*,bool);
 int(*dle_mix_cfg)(struct rtw89_dev*,const struct rtw89_dle_mem*);
 void(*wde_quota_cfg)(struct rtw89_dev*,const struct rtw89_wde_quota*,const struct rtw89_wde_quota*,u16);
 void(*ple_quota_cfg)(struct rtw89_dev*,const struct rtw89_ple_quota*,const struct rtw89_ple_quota*);
 int(*chk_dle_rdy)(struct rtw89_dev*,bool);void(*hfc_func_en)(struct rtw89_dev*,bool,bool);
 void(*hfc_h2c_cfg)(struct rtw89_dev*);void(*hfc_mix_cfg)(struct rtw89_dev*);void(*hfc_get_mix_info)(struct rtw89_dev*);
 int(*preload_init)(struct rtw89_dev*,u8,enum rtw89_qta_mode);
};
struct rtw89_qta_def{const struct rtw89_dle_mem*dle_mem[1];const struct rtw89_hfc_param_ini*hfc_param_ini[1];};
struct rtw89_chip_info{enum rtw89_core_chip_id chip_id;const struct rtw89_page_regs*page_regs;
 const struct rtw89_mac_gen_def*mac_def;const struct rtw89_imr_info*imr_info;const struct rtw89_rrsr_cfgs*rrsr_cfgs;
 u32 fifo_size,dle_scc_rsvd_size,dma_ch_mask;};
struct rtw89_mac_info{struct{const void*rsvd_qt,*dle_input;u16 ple_pg_size,ple_free_pg,c0_rx_qta,c1_rx_qta;u8 qta_mode;}dle_info;
 struct rtw89_hfc_param hfc_param;enum rtw89_qta_mode qta_mode;};
struct rtw89_dev{const struct rtw89_chip_info*chip;struct{int type,dle_type;}hci;
 struct rtw89_mac_info mac;struct{u8 cv;u32 rx_fltr;}hal;u64 flags[1];};
static const struct rtw89_qta_def qta_def={{dle_mem},{param_ini}};
static const struct rtw89_qta_def*rtw89_chip_get_qta_def(struct rtw89_dev*d){(void)d;return &qta_def;}
static bool rtw89_is_rtl885xb(struct rtw89_dev*d){return d->chip->chip_id==RTL8852B;}
static u8 registers[65536];
static u32 read_raw(u32 a,u32 n){u32 v=0;memcpy(&v,registers+a,n);return v;}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){(void)d;u32 v=read_raw(a,4);
 if(a==R_AX_WLAN_XTAL_SI_CTRL){v&=~B_AX_WL_XTAL_SI_CMD_POLL;memcpy(registers+a,&v,4);}
 if(a==R_AX_WDE_INI_STATUS)v=WDE_MGN_INI_RDY;
 if(a==R_AX_PLE_INI_STATUS)v=PLE_MGN_INI_RDY;
 if(a==R_AX_SS_CTRL)v|=B_AX_SS_INIT_DONE_1;
 if(a==R_AX_RESPBA_CAM_CTRL){v&=~B_AX_BACAM_RST_MASK;memcpy(registers+a,&v,4);}
 if(a==R_AX_PUB_PAGE_INFO1)v=0;
 if(a==R_AX_PUB_PAGE_INFO2)v=FIELD_PREP(B_AX_PUB_AVAL_PG_MASK,446);
 return v;}
static u16 rtw89_read16(struct rtw89_dev*d,u32 a){(void)d;u16 v=read_raw(a,2);
 if(a==R_AX_ADDR_CAM_CTRL){v&=~B_AX_ADDR_CAM_CLR;memcpy(registers+a,&v,2);}return v;}
static u8 rtw89_read8(struct rtw89_dev*d,u32 a){(void)d;return read_raw(a,1);}
static void write(struct rtw89_dev*d,u32 a,u32 v,u32 n){(void)d;printf("%u %x %x\\n",n,a,v);memcpy(registers+a,&v,n);}
#define rtw89_write8(d,a,v) write(d,a,(u8)(v),1)
#define rtw89_write16(d,a,v) write(d,a,(u16)(v),2)
#define rtw89_write32(d,a,v) write(d,a,(u32)(v),4)
#define WRAP_WIDTH(n) \\
static void rtw89_write##n##_set(struct rtw89_dev*d,u32 a,u32 m){rtw89_write##n(d,a,rtw89_read##n(d,a)|m);} \\
static void rtw89_write##n##_clr(struct rtw89_dev*d,u32 a,u32 m){rtw89_write##n(d,a,rtw89_read##n(d,a)&~m);} \\
static void rtw89_write##n##_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_write##n(d,a,u32_replace_bits(rtw89_read##n(d,a),v,m));}
WRAP_WIDTH(8) WRAP_WIDTH(16) WRAP_WIDTH(32)
static u32 rtw89_read32_mask(struct rtw89_dev*d,u32 a,u32 m){return FIELD_GET(m,rtw89_read32(d,a));}
static u32 rtw89_mac_reg_by_idx(struct rtw89_dev*d,u32 a,u8 i){(void)d;return a+i*0x2000;}
static int rtw89_mac_check_mac_en(struct rtw89_dev*d,u8 i,enum rtw89_mac_hwmod_sel s){
 return !(rtw89_read32(d,s==RTW89_DMAC_SEL?R_AX_DMAC_FUNC_EN:R_AX_CMAC_FUNC_EN+i*0x2000)&(s==RTW89_DMAC_SEL?B_AX_DMAC_FUNC_EN:B_AX_CMAC_EN));}
#define read_poll_timeout(fn,val,cond,interval,budget,delay,...) ({int result=-ETIMEDOUT;for(int retry=0;retry<3;retry++){val=fn(__VA_ARGS__);if(cond){result=0;break;}}result;})
#define read_poll_timeout_atomic read_poll_timeout
static void udelay(u32 us){printf("0 0 %x\\n",us);}
'''
code+='\n'.join(f[:f.index('{')].strip()+';' for f in original)+'\n'
code+='#define INVALID_QT_WCPU U16_MAX\n'
start=mac.index('#define SET_QUOTA_VAL');code+=mac[start:mac.index('static void wde_quota_cfg_ax',start)]
code+='\n'.join(original)
code+='''static const struct rtw89_mac_gen_def mac_def={dle_func_en_ax,dle_clk_en_ax,dle_mix_cfg_ax,wde_quota_cfg_ax,ple_quota_cfg_ax,chk_dle_rdy_ax,
 hfc_func_en_ax,hfc_h2c_cfg_ax,hfc_mix_cfg_ax,hfc_get_mix_info_ax,preload_init_set_ax};
static int rtw89_mac_write_xtal_si(struct rtw89_dev*d,u8 a,u8 v,u8 m){return rtw89_mac_write_xtal_si_ax(d,a,v,m);}
int main(int argc,char**argv){if(argc!=3)return 2;unsigned seed=atoi(argv[1]),cut=atoi(argv[2]);
 memset(registers,seed,sizeof(registers));
 struct rtw89_chip_info chip={RTL8852B,&rtw8852b_page_regs,&mac_def,&rtw8852b_imr_info,&rtw8852b_rrsr_cfgs,196608,98304,0xcf0};
 struct rtw89_dev dev={0};dev.chip=&chip;dev.hal.cv=cut;dev.hal.rx_fltr=DEFAULT_AX_RX_FLTR;
 dev.mac.qta_mode=RTW89_QTA_SCC;dev.mac.dle_info.qta_mode=RTW89_QTA_SCC;
 if(__rtw8852bx_mac_enable_bb_rf(&dev)||sys_init_ax(&dev)||dmac_init_ax(&dev,0)||cmac_init_ax(&dev,0)
 ||enable_imr_ax(&dev,0,RTW89_DMAC_SEL)||enable_imr_ax(&dev,0,RTW89_CMAC_SEL)||set_host_rpr_ax(&dev))return 3;
 return 0;}
'''
# Internal error masks precede RPQ configuration in the original trx_init_ax.
code=code.replace('||set_host_rpr_ax(&dev))return 3;',' )return 3;\n err_imr_ctrl_ax(&dev,true);if(set_host_rpr_ax(&dev))return 3;')
# Wrapper declaration is needed by the original per-chip callback.
code=code.replace('\n'.join(original),'static int rtw89_mac_write_xtal_si(struct rtw89_dev*,u8,u8,u8);\n'+'\n'.join(original))
with tempfile.TemporaryDirectory(prefix='rtw89-mac-oracle-') as td:
    td=Path(td);(td/'oracle.c').write_text(code)
    subprocess.run(['cc','-std=gnu11',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True)
    golden='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux callback SHA256 '+hashlib.sha256('\n'.join(original).encode()).hexdigest()+'\nconst CASES:&[Case]=&[\n'
    for seed in [0,0xa5]:
        for cut in [0,1]:
            out=subprocess.check_output([str(td/'oracle'),str(seed),str(cut)]).decode()
            golden+=f'Case{{seed:{seed},cut:{cut},trace:&[\n'
            for line in out.splitlines():
                width,addr,value=line.split();golden+=f'({width},0x{addr},0x{value}),\n'
            golden+=']},\n'
    golden+='];\n'
path=d/'golden.rs'
if a.check:
    if path.read_text()!=golden:raise SystemExit('post-WCPU MAC Linux traces differ')
else:path.write_text(golden)
