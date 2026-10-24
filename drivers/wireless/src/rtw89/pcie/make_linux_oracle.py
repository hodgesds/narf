#!/usr/bin/env python3
"""Extract Linux AX PCIe pre-init helpers/profiles into an inert C oracle.

Only pre-BDRAM policy and mode_op are traced. MDIO/PCI config transactions
are represented by logical addresses; their native protocols have independent
oracles. Rust constants are independently emitted from Linux header macros.
"""
from pathlib import Path
import argparse, hashlib, re, subprocess, tempfile
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux', type=Path, default=Path('/usr/src/linux'))
p.add_argument('--check', action='store_true')
a = p.parse_args()
root = a.linux/'drivers/net/wireless/realtek/rtw89'
src = (root/'pci.c').read_text()
def block(text, marker, prefix=''):
    start = text.index(marker)
    if prefix: start = text.rfind(prefix, 0, start)
    opening = text.index('{', start); cursor, depth = opening+1, 1
    while depth:
        depth += (text[cursor]=='{')-(text[cursor]=='}'); cursor += 1
    return text[start:cursor]
names = ['rtw89_pci_ber','rtw89_pci_rxdma_prefth','rtw89_pci_l1off_pwroff',
'rtw89_pci_deglitch_setting','rtw89_pci_l2_rxen_lat','rtw89_pci_aphy_pwrcut',
'rtw89_pci_hci_ldo','rtw89_pci_dphy_delay','rtw89_pci_autok_x',
'rtw89_pci_auto_refclk_cal','rtw89_pci_power_wake_ax','rtw89_pci_autoload_hang',
'rtw89_pci_l12_vmain','rtw89_pci_gen2_force_ib','rtw89_pci_l1_ent_lat',
'rtw89_pci_wd_exit_l1','rtw89_pci_set_sic','rtw89_pci_set_lbc',
'rtw89_pci_set_io_rcy','rtw89_pci_set_dbg','rtw89_pci_set_keep_reg','rtw89_pci_mode_op']
helpers = '\n'.join(block(src,n+'(', '\nstatic ') for n in names)
fields = ['txbd_trunc_mode','rxbd_trunc_mode','rxbd_mode','tag_mode','wd_dma_idle_intvl',
'wd_dma_act_intvl','tx_burst','rx_burst','multi_tag_num','lbc_en','lbc_tmr','io_rcy_en',
'io_rcy_tmr','init_cfg_reg','rxbd_mode_bit','exp_ctrl_reg','max_tag_num_mask']
profiles=[]
for chip in ['8852a','8852b','8852c','8851b']:
    text=(root/('rtw'+chip+'e.c')).read_text()
    entries=['.'+f+'='+re.search(r'\.'+f+r'\s*=\s*(.*?),\n',text,re.S).group(1) for f in fields]
    profiles.append('static const struct rtw89_pci_info p'+chip+'={'+','.join(entries)+'};')
header=(root/'pci.h').read_text()
enums='\n'.join(block(header,'enum '+n)+';' for n in ['mac_ax_bd_trunc_mode',
'mac_ax_rxbd_mode','mac_ax_tag_mode','mac_ax_tx_burst','mac_ax_rx_burst',
'mac_ax_wd_dma_intvl','mac_ax_multi_tag_num','mac_ax_lbc_tmr','mac_ax_pcie_func_ctrl',
'mac_ax_io_rcy_tmr'])
definitions={}
for file in ['pci.h','reg.h']:
    lines=iter((root/file).read_text().splitlines())
    for line in lines:
        match=re.match(r'#define\s+(\w+)\s+',line)
        if match:
            body=[line]
            while body[-1].endswith('\\'): body.append(next(lines))
            definitions[match.group(1)]='\n'.join(body)
needed=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',helpers+'\n'+'\n'.join(profiles))) & definitions.keys()
rust=(Path(__file__).parents[1]/'pcie.rs').read_text()
symbols=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',rust)) & definitions.keys()
needed |= symbols
while True:
    more=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b','\n'.join(definitions[n] for n in needed))) & definitions.keys()
    if more <= needed: break
    needed |= more
defs='\n'.join(definitions[n] for n in sorted(needed))
pre=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define u16_encode_bits(v,m) FIELD_PREP(m,v)
#define u32_replace_bits(o,v,m) (((o)&~(m))|FIELD_PREP(m,v))
#define PCIE_PHY_GEN1 0
#define PCIE_PHY_GEN2 1
#define PCIE_CLKDLY_HW_0 0
#define CHIP_CAV 0
#define CHIP_CBV 1
#define RTW89_QUIRK_PCI_BER 0
#define EOPNOTSUPP 95
#define EINVAL 22
#define INTF_INTGRA_HOSTREF_V1 100
#define INTF_INTGRA_MINREF_V1 90
#define rtw89_err(...) ((void)0)
#define rtw89_debug(...) ((void)0)
#define RTW89_DBG_HCI 0
#define fsleep(us) ((void)0)
enum rtw89_core_chip_id {RTL8852A,RTL8852B,RTL8852C,RTL8851B};
enum rtw89_pcie_phy {unused_phy};
struct chip {enum rtw89_core_chip_id chip_id;};
struct rtw89_pci_info {
 u32 txbd_trunc_mode,rxbd_trunc_mode,rxbd_mode,tag_mode,wd_dma_idle_intvl,wd_dma_act_intvl;
 u32 tx_burst,rx_burst,multi_tag_num,lbc_en,lbc_tmr,io_rcy_en,io_rcy_tmr;
 u32 init_cfg_reg,rxbd_mode_bit,exp_ctrl_reg,max_tag_num_mask;
};
struct rtw89_dev {struct chip *chip; const struct rtw89_pci_info *pci_info;struct {u8 cv;} hal;unsigned long quirks[1];};
static bool test_bit(int n,unsigned long*v){return (*v>>n)&1;}
static bool rtw89_is_rtl885xb(struct rtw89_dev*d){return d->chip->chip_id==RTL8852B||d->chip->chip_id==RTL8851B;}
static u8 mem[0x210000];
static u32 raw(u32 a,unsigned width){u32 v=0;memcpy(&v,mem+a,width/8);return v;}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){return raw(a,32);}
static u16 rtw89_read16(struct rtw89_dev*d,u32 a){return raw(a,16);}
static void wr(u32 a,u32 v,unsigned width){printf("(%u,0x%x,0x%x),",width,a,v);memcpy(mem+a,&v,width/8);}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){wr(a,v,32);}
static void rtw89_write16(struct rtw89_dev*d,u32 a,u16 v){wr(a,v,16);}
static void rtw89_write32_set(struct rtw89_dev*d,u32 a,u32 m){rtw89_write32(d,a,raw(a,32)|m);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 m){rtw89_write32(d,a,raw(a,32)&~m);}
static void rtw89_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_write32(d,a,u32_replace_bits(raw(a,32),v,m));}
static void rtw89_write16_set(struct rtw89_dev*d,u32 a,u16 m){rtw89_write16(d,a,raw(a,16)|m);}
static void rtw89_write16_clr(struct rtw89_dev*d,u32 a,u16 m){rtw89_write16(d,a,raw(a,16)&~m);}
static int rtw89_read16_mdio(struct rtw89_dev*d,u8 a,int gen,u16*out){*out=raw(0x100000+gen*0x10000+a*2,16);return 0;}
static int rtw89_write16_mdio(struct rtw89_dev*d,u8 a,u16 v,int gen){wr(0x100000+gen*0x10000+a*2,v,16);return 0;}
static int rtw89_write16_mdio_mask(struct rtw89_dev*d,u8 a,u16 mask,u16 v,int gen){u16 old;rtw89_read16_mdio(d,a,gen,&old);return rtw89_write16_mdio(d,a,(old&~mask)|FIELD_PREP(mask,v),gen);}
static int rtw89_write16_mdio_clr(struct rtw89_dev*d,u8 a,u16 mask,int gen){return rtw89_write16_mdio_mask(d,a,mask,0,gen);}
static int rtw89_write16_mdio_set(struct rtw89_dev*d,u8 a,u16 mask,int gen){return rtw89_write16_mdio_mask(d,a,mask,mask>>__builtin_ctz(mask),gen);}
static int rtw89_pci_read_config_byte(struct rtw89_dev*d,u16 a,u8*out){*out=mem[0x200000+a];return 0;}
static int rtw89_pci_write_config_byte(struct rtw89_dev*d,u16 a,u8 v){wr(0x200000+a,v,8);return 0;}
static int __get_target(struct rtw89_dev*d,u16*t,int gen){return -22;}
'''
main=r'''
int main(int argc,char**argv) {
 if(argc>1){CONSTANTS;return 0;}
 const struct rtw89_pci_info *profiles[]={&p8852a,&p8852b,&p8852c,&p8851b};
 for(int ch=0;ch<4;ch++)for(int cut=0;cut<2;cut++)for(int seed=0;seed<2;seed++)for(int gen=1;gen<=2;gen++)for(int ber=0;ber<=(ch==2);ber++) {
  struct chip c={ch};struct rtw89_dev d={.chip=&c,.pci_info=profiles[ch],.hal={cut},.quirks={ber}};
  memset(mem,seed?0xa5:0,sizeof(mem));mem[0x200082]=gen;if(seed)mem[0x200719]|=8;
  printf("Case{chip:ChipId::%s,cut:%d,seed:%d,generation:%d,ber:%s,trace:&[",(const char*[]){"Rtl8852A","Rtl8852B","Rtl8852C","Rtl8851B"}[ch],cut,seed?0xa5:0,gen,ber?"true":"false");
  rtw89_pci_ber(&d);rtw89_pci_rxdma_prefth(&d);rtw89_pci_l1off_pwroff(&d);
  if(rtw89_pci_deglitch_setting(&d)||rtw89_pci_l2_rxen_lat(&d))return 2;
  rtw89_pci_aphy_pwrcut(&d);rtw89_pci_hci_ldo(&d);
  if(rtw89_pci_dphy_delay(&d)||rtw89_pci_autok_x(&d)||rtw89_pci_auto_refclk_cal(&d,false))return 3;
  rtw89_pci_power_wake_ax(&d,true);rtw89_pci_autoload_hang(&d);rtw89_pci_l12_vmain(&d);rtw89_pci_gen2_force_ib(&d);
  rtw89_pci_l1_ent_lat(&d);rtw89_pci_wd_exit_l1(&d);rtw89_pci_set_sic(&d);rtw89_pci_set_lbc(&d);
  rtw89_pci_set_io_rcy(&d);rtw89_pci_set_dbg(&d);rtw89_pci_set_keep_reg(&d);rtw89_pci_mode_op(&d);
  puts("]},");
 }
 return 0;
}
'''
main=main.replace('CONSTANTS',';'.join('printf("pub const '+n+': u32 = 0x%x;\\n",(unsigned)'+n+')' for n in sorted(symbols)))
with tempfile.TemporaryDirectory() as td:
    td=Path(td);(td/'oracle.c').write_text(pre+enums+'\n'+defs+'\n'+helpers+'\n'+'\n'.join(profiles)+main)
    subprocess.run(['cc','-O2','-o',str(td/'oracle'),str(td/'oracle.c')],check=True)
    traces=subprocess.check_output([str(td/'oracle')]).decode()
    constants=subprocess.check_output([str(td/'oracle'),'constants']).decode()
results={Path(__file__).with_name('golden.rs'):'// Extracted Linux pci.c helper SHA256 '+hashlib.sha256(helpers.encode()).hexdigest()+'\nconst CASES:&[Case]=&[\n'+traces+'];\n',
         Path(__file__).parents[1]/'pcie_regs.rs':'// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Linux pci.h/reg.h values, generated by pcie/make_linux_oracle.py.\n'+constants}
for path,value in results.items():
    if a.check:
        if path.read_text()!=value: raise SystemExit(str(path)+' differs')
    else: path.write_text(value)
