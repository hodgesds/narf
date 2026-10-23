#!/usr/bin/env python3
"""Compile the actual AX WCPU helpers from local Linux into inert MMIO traces."""
from pathlib import Path
import subprocess, tempfile, sys
linux=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/usr/src/linux')
mac=(linux/'drivers/net/wireless/realtek/rtw89/mac.c').read_text()
reg=(linux/'drivers/net/wireless/realtek/rtw89/reg.h').read_text()
def function(name):
    at=mac.index(name+'('); start=mac.rfind('\nstatic',0,at)+1
    a=mac.index('{',at); depth=1; end=a+1
    while depth:
        depth+= (mac[end]=='{')-(mac[end]=='}');end+=1
    return mac[start:end]
names=['rtw89_mac_mem_write','rtw89_mac_mem_read','rtw89_disable_fw_watchdog','rtw89_mac_disable_cpu_ax','rtw89_mac_enable_cpu_ax','rtw89_fwdl_secure_idmem_share_mode_ax']
body='\n'.join(function(n) for n in names)
import re
symbols=set(re.findall(r'\b[RB]_AX_[A-Z0-9_]+\b',body))
defs=[]
for line in reg.splitlines():
    if line.startswith('#define ') and line.split()[1] in symbols:defs.append(line)
pre=r'''
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define RTW89_FLAG_FW_RDY 0
enum rtw89_mac_mem_sel { RTW89_MAC_MEM_CPU_LOCAL = 0 };
#define RTW89_FWDL_INITIAL_STATE 0
#define RTW89_FWDL_CHECK_FREERTOS_DONE 0
#define WDT_CTRL_ALL_DIS 0
#define EFAULT 14
#define clear_bit(...) ((void)0)
#define mdelay(...) ((void)0)
static unsigned char memory[0x40004];
static u32 cpu_ctrl,cpu_status;
struct rtw89_mac_gen_def {u32 filter_model_addr,indir_access_addr;};
struct chip {const struct rtw89_mac_gen_def *mac_def;};
struct rtw89_fw_secure {bool secure_boot;};
struct rtw89_dev {int chip_id;struct chip *chip;struct {struct rtw89_fw_secure sec;} fw;unsigned long flags;};
static bool rtw89_is_rtl885xb(struct rtw89_dev*d){return d->chip_id==1||d->chip_id==3;}
static u32 rtw89_mac_mem_base_addrs(struct rtw89_dev*d,int space){return 0x18003000;}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){u32 v;if(a==0x40000){u32 sel;memcpy(&sel,memory+0xc04,4);if(sel==0x18003040)return cpu_ctrl;if(sel==0x18003044)return cpu_status;}memcpy(&v,memory+a,4);return v;}
static u16 rtw89_read16(struct rtw89_dev*d,u32 a){u16 v;memcpy(&v,memory+a,2);return v;}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){printf("(%u,0x%x,0x%x),",32,a,v);memcpy(memory+a,&v,4);if(a==0x40000){u32 sel;memcpy(&sel,memory+0xc04,4);if(sel==0x18003040)cpu_ctrl=v;if(sel==0x18003044)cpu_status=v;}}
static void rtw89_write16(struct rtw89_dev*d,u32 a,u16 v){printf("(%u,0x%x,0x%x),",16,a,v);memcpy(memory+a,&v,2);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 m){rtw89_write32(d,a,rtw89_read32(d,a)&~m);}
static void rtw89_write32_set(struct rtw89_dev*d,u32 a,u32 m){rtw89_write32(d,a,rtw89_read32(d,a)|m);}
static u32 u32_replace_bits(u32 old,u32 v,u32 m){return (old&~m)|((v<<__builtin_ctz(m))&m);}
static void rtw89_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_write32(d,a,u32_replace_bits(rtw89_read32(d,a),v,m));}
static void rtw89_write16_mask(struct rtw89_dev*d,u32 a,u16 m,u16 v){rtw89_write16(d,a,u32_replace_bits(rtw89_read16(d,a),v,m));}
static int rtw89_fw_check_rdy(struct rtw89_dev*d,int type){return 0;}
'''
main=r'''
int main(void){struct rtw89_mac_gen_def mac={0xc04,0x40000};struct chip c={&mac};
 for(int chip=0;chip<4;chip++)for(int seed=0;seed<2;seed++)for(int secure=0;secure<2;secure++){
 memset(memory,seed?0xa5:0,sizeof(memory));cpu_ctrl=cpu_status=seed?0xa5a5a5a5:0;struct rtw89_dev d={.chip_id=chip,.chip=&c,.fw.sec.secure_boot=secure};
 printf("Case { chip: ChipId::%s, seed: %u, secure: %s, trace: &[",(const char*[]){"Rtl8852A","Rtl8852B","Rtl8852C","Rtl8851B"}[chip],seed?0xa5:0,secure?"true":"false");
 rtw89_mac_disable_cpu_ax(&d);if(rtw89_mac_enable_cpu_ax(&d,0,true,false))return 2;
 rtw89_fwdl_secure_idmem_share_mode_ax(&d,11);printf("] },\n");}return 0;}
'''
with tempfile.TemporaryDirectory() as temp:
    src=Path(temp)/'oracle.c'; exe=Path(temp)/'oracle';src.write_text(pre+'\n'+'\n'.join(defs)+'\n'+body+'\n'+main)
    subprocess.run(['cc','-O2','-Wno-incompatible-pointer-types','-o',str(exe),str(src)],check=True)
    output=subprocess.check_output([str(exe)]).decode()
Path(__file__).with_name('golden.rs').write_text('// Generated from actual Linux AX WCPU helpers by make_linux_oracle.py.\nconst CASES: &[Case] = &[\n'+output+'];\n')
