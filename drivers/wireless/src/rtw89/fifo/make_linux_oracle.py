# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
from pathlib import Path
import re, subprocess, sys, tempfile
directory=Path(__file__).parent
p=Path(tempfile.mkdtemp(prefix='rtw89-fifo-oracle-'))
linux=Path(sys.argv[1] if len(sys.argv)>1 else '/usr/src/linux/drivers/net/wireless/realtek/rtw89')
mac=(linux/'mac.c').read_text();core=(linux/'core.h').read_text()
def structure(name):
 a=core.index('struct '+name+' {');return core[a:core.index('\n};',a)+3]+'\n'
def function(name):
 m=re.search(r'^static (?:int|void) '+name+r'\(',mac,re.M);a=m.start();end=mac.index('{',a)+1;depth=1
 while depth:depth+=(mac[end]=='{')-(mac[end]=='}');end+=1
 return mac[a:end]+'\n'
s='/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */\n/* Copyright(c)2019-2022 Realtek Corporation. Functions/tables below extracted from Linux. */\n#include <stdio.h>\n#include <stdint.h>\n#include <stdbool.h>\ntypedef uint64_t u64;typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;\n#define RTW89_WDE_PG_64 64\n#define RTW89_WDE_PG_128 128\n#define RTW89_WDE_PG_256 256\n#define RTW89_PLE_PG_64 64\n#define RTW89_PLE_PG_128 128\n#define RTW89_PLE_PG_256 256\n#define DLE_BOUND_UNIT 8192\n#define RTW89_QTA_SCC 0\n#define RTW89_QTA_DLFW 1\nenum rtw89_qta_mode { ZERO };\n'
for name in ['rtw89_dle_size','rtw89_wde_quota','rtw89_ple_quota','rtw89_dle_mem','rtw89_hfc_prec_cfg']:s+=structure(name)
entries=[];refs=set()
for chip in ['rtw8852a','rtw8852b','rtw8852c','rtw8851b']:
 source=(linux/(chip+'.c')).read_text();a=source.index('static const struct rtw89_dle_mem '+chip+'_dle_mem_pcie[]');b=source.index('\n};',a);block=source[a:b]
 case=[]
 for mode in ['SCC','DLFW']:
  m=re.search(r'\[RTW89_QTA_'+mode+r'\]\s*=\s*\{.*?\}',block,re.S);case.append(m.group());refs.update(re.findall(r'rtw89_mac_size\.(\w+)',m.group()))
 entries.append((chip,case))
s+='struct selected_mac_size {\n'
for field in sorted(refs):
 typename='rtw89_dle_size' if '_size' in field else 'rtw89_wde_quota' if field.startswith('wde') else 'rtw89_ple_quota'
 s+=f'struct {typename} {field};\n'
s+='struct rtw89_hfc_prec_cfg hfc_preccfg_pcie;\n};\nstatic const struct selected_mac_size rtw89_mac_size={\n'
for field in sorted(refs|{'hfc_preccfg_pcie'}):
 m=re.search(r'\.'+field+r'\s*=\s*\{.*?\}',mac,re.S);s+=m.group()+',\n'
s+='};\n'
for chip,case in entries:s+=f'static const struct rtw89_dle_mem {chip}[]={{'+','.join(case)+'};\n'
s+='''
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#define BIT(x) (1ULL<<(x))
#define GENMASK(h,l) ((~0ULL<<(l))&(~0ULL>>(63-(h))))
#define FIELD_PREP(m,v) (((u64)(v)<<__builtin_ctzll(m))&(m))
#define u32_encode_bits(v,m) FIELD_PREP(m,v)
#define u32_replace_bits(o,v,m) (((o)&~(m))|FIELD_PREP(m,v))
#define RTW89_HCI_TYPE_PCIE 1
#define RTW89_HCI_TYPE_USB 2
#define RTW89_DMA_H2C 12
#define U16_MAX UINT16_MAX
enum rtw89_core_chip_id { CHIP_UNUSED };
#define RTL8852A 0
#define RTL8852B 1
#define RTL8852C 2
#define RTL8851B 3
#define RTL8852BT 4
#define rtw89_err(...) ((void)0)
'''
s+='#include "'+str(linux/'reg.h')+'"\n'
mh=(linux/'mac.h').read_text()
s+='\n'.join(line for line in mh.splitlines() if line.startswith('#define S_AX_WDE_PAGE_SEL_') or line.startswith('#define S_AX_PLE_PAGE_SEL_'))+'\n'
s+=structure('rtw89_page_regs')
for chip in ['rtw8852a','rtw8852b','rtw8852c','rtw8851b']:
 text=(linux/(chip+'.c')).read_text();a=text.index('static const struct rtw89_page_regs '+chip+'_page_regs');s+=text[a:text.index('\n};',a)+3]+'\n'
s+='''struct rtw89_chip_info {int chip_id;const struct rtw89_page_regs *page_regs;};
struct rtw89_hfc_param {bool en,h2c_en;struct rtw89_hfc_prec_cfg prec_cfg;};
struct rtw89_dev {struct rtw89_chip_info *chip;struct{int type;}hci;struct{struct rtw89_hfc_param hfc_param;}mac;};
static u8 registers[65536];
static u32 rtw89_read32(struct rtw89_dev*d,u32 address){(void)d;u32 value;memcpy(&value,registers+address,4);return value;}
static void rtw89_write32(struct rtw89_dev*d,u32 address,u32 value){(void)d;printf("%x %x\\n",address,value);memcpy(registers+address,&value,4);}
static void rtw89_write32_set(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32(d,a,rtw89_read32(d,a)|v);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32(d,a,rtw89_read32(d,a)&~v);}
static void rtw89_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_write32(d,a,u32_replace_bits(rtw89_read32(d,a),v,m));}
'''
for n in ['rtw89_mac_hci_func_en_ax','rtw89_mac_dmac_func_pre_en_ax','dle_func_en_ax','dle_clk_en_ax','dle_mix_cfg_ax']:s+=function(n)
a=mac.index('#define INVALID_QT_WCPU');b=mac.index('int rtw89_mac_resize_ple_rx_quota',a);s+=mac[a:b]
for n in ['hfc_h2c_cfg_ax','hfc_func_en_ax']:s+=function(n)
s+='''int main(int argc,char**argv){if(argc!=3)return 2;unsigned chip_id=atoi(argv[1]);unsigned seed=atoi(argv[2]);
const struct rtw89_dle_mem*profiles[]={rtw8852a,rtw8852b,rtw8852c,rtw8851b};
const struct rtw89_page_regs*pages[]={&rtw8852a_page_regs,&rtw8852b_page_regs,&rtw8852c_page_regs,&rtw8851b_page_regs};
struct rtw89_chip_info chip={chip_id,pages[chip_id]};struct rtw89_dev d={0};d.chip=&chip;d.hci.type=1;d.mac.hfc_param.prec_cfg=rtw89_mac_size.hfc_preccfg_pcie;
memset(registers,seed,sizeof(registers));
rtw89_mac_hci_func_en_ax(&d);rtw89_mac_dmac_func_pre_en_ax(&d);
const struct rtw89_dle_mem*cfg=&profiles[chip_id][1];
dle_func_en_ax(&d,false);dle_clk_en_ax(&d,true);int result=dle_mix_cfg_ax(&d,cfg);if(result)return 3;
wde_quota_cfg_ax(&d,cfg->wde_min_qt,cfg->wde_max_qt,profiles[chip_id][0].wde_min_qt->wcpu);
ple_quota_cfg_ax(&d,cfg->ple_min_qt,cfg->ple_max_qt);dle_func_en_ax(&d,true);
hfc_func_en_ax(&d,false,false);hfc_h2c_cfg_ax(&d);hfc_func_en_ax(&d,false,true);
return 0;}\n'''
(p/'oracle.c').write_text(s)
subprocess.run(['cc','-std=gnu11',str(p/'oracle.c'),'-o',str(p/'oracle')],check=True)
golden='// Generated by make_linux_oracle.py from extracted Linux C callbacks.\nconst CASES:&[Case]=&[\n'
chips=['Rtl8852A','Rtl8852B','Rtl8852C','Rtl8851B']
for chip in range(4):
 for seed in [0,165]:
  data=subprocess.check_output([str(p/'oracle'),str(chip),str(seed)]).decode()
  golden+=f'Case{{chip:ChipId::{chips[chip]},seed:{seed},trace:&[\n'
  for line in data.splitlines():
   a,v=line.split();golden+=f'(0x{a},0x{v}),\n'
  golden+=']},\n'
golden+='];\n';(directory/'golden.rs').write_text(golden)
print('eight Linux DLE/HFC callback traces generated',p/'oracle.c')
