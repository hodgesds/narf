#!/usr/bin/env python3
"""Compile extracted Linux AX basic_cfg helpers against inert ECAM/RAC memory."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux'));p.add_argument('--check',action='store_true');a=p.parse_args()
root=a.linux/'drivers/net/wireless/realtek/rtw89';source=(root/'pci.c').read_text()
def block(text,marker,prefix=''):
    start=text.index(marker)
    if prefix:start=text.rfind(prefix,0,start)
    opening=text.index('{',start);cursor,depth=opening+1,1
    while depth:depth+=(text[cursor]=='{')-(text[cursor]=='}');cursor+=1
    return text[start:cursor]
names=['rtw89_pci_get_phy_offset_by_link_speed','rtw89_pci_disable_eq_ax','rtw89_pci_filter_out','rtw89_pci_clkreq_set_ax','rtw89_pci_aspm_set_ax','rtw89_pci_link_cfg','rtw89_pci_l1ss_set_ax','rtw89_pci_l1ss_cfg','rtw89_pci_cpl_timeout_cfg']
helpers='\n'.join(block(source,n+'(','\nstatic ') for n in names)
header=(root/'pci.h').read_text();enum_names=['rtw89_pcie_clkdly_hw','rtw89_pcie_l0sdly','rtw89_pcie_l1dly']
enums='\n'.join(block(header,'enum '+n)+';' for n in enum_names)
defs={}
for path in [root/'pci.h',root/'reg.h',a.linux/'include/uapi/linux/pci_regs.h']:
    lines=iter(path.read_text().splitlines())
    for line in lines:
        match=re.match(r'#define\s+(\w+)\s+',line)
        if match:
            body=[line]
            while body[-1].endswith('\\'):body.append(next(lines))
            defs[match.group(1)]='\n'.join(body)
rust=(Path(__file__).parents[1]/'pci_basic.rs').read_text()
symbols=(set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',rust))&defs.keys())|{'PCIE_CLKDLY_HW_30US','PCIE_L0SDLY_4US','PCIE_L1DLY_16US'}
needed=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',helpers))&defs.keys();needed|=symbols&defs.keys()
while True:
    more=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b','\n'.join(defs[n] for n in needed)))&defs.keys()
    if more<=needed:break
    needed|=more
definitions='\n'.join(defs[n] for n in sorted(needed))
pre=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define u32_get_bits(v,m) FIELD_GET(m,v)
#define u8p_replace_bits(p,v,m) (*(p)=(*(p)&~(m))|FIELD_PREP(m,v))
#define rtw89_err(...) ((void)0)
#define rtw89_warn(...) ((void)0)
#define EFAULT 14
#define EOPNOTSUPP 95
#define CHIP_CAV 0
#define RTL8922D_CID7090 0x7090
enum rtw89_core_chip_id{RTL8852A,RTL8852B,RTL8852C,RTL8851B,RTL8922D};
struct chip{enum rtw89_core_chip_id chip_id;};
struct pci_dev{int unused;};struct rtw89_pci{struct pci_dev *pdev;};
struct rtw89_hal{u8 cv;u16 cid;};
struct rtw89_dev{struct chip*chip;void*priv;struct rtw89_hal hal;};
static u8 mem[65536],config[4096];static bool ext_present,rtw89_pci_disable_l1ss;
static u32 raw(u32 a,unsigned width){u32 v=0;memcpy(&v,mem+a,width/8);return v;}
static u32 cfg(u32 a,unsigned width){u32 v=0;memcpy(&v,config+a,width/8);return v;}
static void wr(u32 a,u32 v,unsigned width){printf("(%u,0x%x,0x%x),",width,a,v);memcpy(mem+a,&v,width/8);}
static void wc(u32 a,u32 v,unsigned width){printf("(%u,0x%x,0x%x),",width,0x200000+a,v);memcpy(config+a,&v,width/8);}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){return raw(a,32);}
static u16 rtw89_read16(struct rtw89_dev*d,u32 a){return raw(a,16);}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){wr(a,v,32);}
static void rtw89_write16(struct rtw89_dev*d,u32 a,u16 v){wr(a,v,16);}
static u32 rtw89_read32_mask(struct rtw89_dev*d,u32 a,u32 m){return FIELD_GET(m,raw(a,32));}
static u16 rtw89_read16_mask(struct rtw89_dev*d,u32 a,u16 m){return FIELD_GET(m,raw(a,16));}
static void rtw89_write32_set(struct rtw89_dev*d,u32 a,u32 m){wr(a,raw(a,32)|m,32);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 m){wr(a,raw(a,32)&~m,32);}
static void rtw89_write16_set(struct rtw89_dev*d,u32 a,u16 m){wr(a,raw(a,16)|m,16);}
static void rtw89_write16_clr(struct rtw89_dev*d,u32 a,u16 m){wr(a,raw(a,16)&~m,16);}
static void rtw89_write16_mask(struct rtw89_dev*d,u32 a,u16 m,u16 v){wr(a,(raw(a,16)&~m)|FIELD_PREP(m,v),16);}
static bool rtw89_is_rtl885xb(struct rtw89_dev*d){return d->chip->chip_id==RTL8852B||d->chip->chip_id==RTL8851B;}
static int pci_read_config_dword(struct pci_dev*p,u16 a,u32*out){*out=cfg(a,32);return 0;}
static int pcie_capability_read_word(struct pci_dev*p,u16 a,u16*out){*out=cfg(0x40+a,16);return 0;}
static int pcie_capability_set_word(struct pci_dev*p,u16 a,u16 bits){wc(0x40+a,cfg(0x40+a,16)|bits,16);return 0;}
static int pcie_capability_clear_word(struct pci_dev*p,u16 a,u16 bits){wc(0x40+a,cfg(0x40+a,16)&~bits,16);return 0;}
static int pci_find_ext_capability(struct pci_dev*p,u16 id){return ext_present?0x160:0;}
static int rtw89_pci_read_config_byte(struct rtw89_dev*d,u16 a,u8*out){*out=config[a];return 0;}
static int rtw89_pci_write_config_byte(struct rtw89_dev*d,u16 a,u8 v){wc(a,v,8);return 0;}
static int rtw89_pci_config_byte_set(struct rtw89_dev*d,u16 a,u8 b){wc(a,config[a]|b,8);return 0;}
static int rtw89_pci_config_byte_clr(struct rtw89_dev*d,u16 a,u8 b){wc(a,config[a]&~b,8);return 0;}
static u16 gray_code_to_bin(u16 g){u16 b=g;while(g>>=1)b^=g;return b;}
static void rtw89_pci_clkreq_set(struct rtw89_dev*d,bool e);
static void rtw89_pci_aspm_set(struct rtw89_dev*d,bool e);
static void rtw89_pci_l1ss_set(struct rtw89_dev*d,bool e);
'''
post=r'''
static void rtw89_pci_clkreq_set(struct rtw89_dev*d,bool e){rtw89_pci_clkreq_set_ax(d,e);}
static void rtw89_pci_aspm_set(struct rtw89_dev*d,bool e){rtw89_pci_aspm_set_ax(d,e);}
static void rtw89_pci_l1ss_set(struct rtw89_dev*d,bool e){rtw89_pci_l1ss_set_ax(d,e);}
int main(int argc,char**argv){
 if(argc>1){CONSTANTS;return 0;}
 for(int ch=0;ch<4;ch++)for(int gen=1;gen<=2;gen++)for(int seed=0;seed<2;seed++)for(int host=0;host<2;host++)for(int done=0;done<=(ch==2);done++){
  memset(mem,seed?0xa5:0,sizeof(mem));memset(config,0,sizeof(config));
  config[0x34]=0x40;config[0x40]=0x10;config[0x42]=2;config[0x82]=gen;
  config[0x50]=host?2:0;config[0x51]=host?1:0;config[0x68]=seed?0xa5:0;
  config[0x70f]=seed?0xa5:0;config[0x719]=seed?0xa5:0;config[0x718]=seed?0xa5:0;
  ext_present=host;if(host){u32 h=0x16010001;memcpy(config+0x100,&h,4);h=0x1001e;memcpy(config+0x160,&h,4);config[0x168]=15;}
  if(done){u16 v=raw(0x3812,16)|16;memcpy(mem+0x3812,&v,2);v=raw(0x3892,16)|16;memcpy(mem+0x3892,&v,2);}
  struct chip chip={ch};struct pci_dev pdev={0};struct rtw89_pci pci={&pdev};struct rtw89_dev dev={.chip=&chip,.priv=&pci};
  printf("Case{chip:ChipId::%s,generation:%d,seed:%d,host:%s,calibrated:%s,trace:&[",(const char*[]){"Rtl8852A","Rtl8852B","Rtl8852C","Rtl8851B"}[ch],gen,seed?0xa5:0,host?"true":"false",done?"true":"false");
  rtw89_pci_disable_eq_ax(&dev);if(rtw89_pci_filter_out(&dev))return 2;rtw89_pci_cpl_timeout_cfg(&dev);rtw89_pci_link_cfg(&dev);rtw89_pci_l1ss_cfg(&dev);puts("]},");
 }
 return 0;
}
'''
post=post.replace('CONSTANTS',';'.join('printf("pub const '+n+': u32 = 0x%x;\\n",(unsigned)'+n+')' for n in sorted(symbols)))
with tempfile.TemporaryDirectory() as td:
    td=Path(td);(td/'oracle.c').write_text(pre+enums+'\n'+definitions+'\n'+helpers+post)
    subprocess.run(['cc','-O2','-o',str(td/'oracle'),str(td/'oracle.c')],check=True)
    trace=subprocess.check_output([str(td/'oracle')]).decode();constants=subprocess.check_output([str(td/'oracle'),'constants']).decode()
results={Path(__file__).with_name('golden.rs'):'// Linux basic_cfg helper SHA256 '+hashlib.sha256(helpers.encode()).hexdigest()+'\nconst CASES:&[Case]=&[\n'+trace+'];\n',Path(__file__).parents[1]/'pci_basic_regs.rs':'// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Generated Linux pci.h/reg.h constants; see pci_basic/make_linux_oracle.py.\n'+constants}
for path,value in results.items():
    if a.check:
        if path.read_text()!=value:raise SystemExit(str(path)+' differs')
    else:path.write_text(value)
