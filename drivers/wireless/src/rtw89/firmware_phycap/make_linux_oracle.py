#!/usr/bin/env python3
"""Compile original AX GET_FEATURE transport and B PHY capability decoding."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
fw=(a.linux/'fw.c').read_text();mac=(a.linux/'mac.c').read_text();h=(a.linux/'fw.h').read_text();reg=(a.linux/'reg.h').read_text()
def fun(n,s):
 m=re.search(r'^(?:static\s+)?int\s+'+n+r'\s*\(',s,re.M);e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]+'\n'
body=''.join(fun(n,fw) for n in ['rtw89_fw_write_h2c_reg','rtw89_fw_read_c2h_reg','rtw89_fw_msg_reg'])+fun('rtw89_mac_read_phycap',mac)+fun('rtw89_mac_setup_phycap_part0',mac)+fun('rtw89_hw_sch_tx_en_h2c',mac)
# Actual packed layouts and register masks define the C oracle independently.
structs=''.join(re.search(r'struct '+n+r' \{[^}]*\}(?: __packed)?;',h,re.M|re.S).group(0)+'\n' for n in ['rtw89_c2hreg_hdr','rtw89_c2hreg_phycap'])+re.search(r'struct rtw89_h2creg_hdr \{.*?enum rtw89_mac_h2c_type',h,re.S).group(0).split('enum rtw89_mac_h2c_type')[0]
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',h+'\n'+reg,re.M)}
selected=set(re.findall(r'\b(?:RTW89_[A-Z0-9_]+|B_AX_H2CREG_TRIGGER)\b',body+structs));todo=list(selected)
while todo:
 n=todo.pop()
 if n not in defs:continue
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in selected:selected.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(selected) if n in defs)
prefix=r'''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define u32_encode_bits(v,m) (((v)<<__builtin_ctz(m))&(m))
#define RTW89_CHIP_AX 0
#define RF_A 1
#define RF_B 2
#define rtw89_debug(...) ((void)0)
enum rtw89_mac_c2h_type {RTW89_FWCMD_C2HREG_FUNC_PHY_CAP=3,RTW89_FWCMD_C2HREG_FUNC_PHY_CAP_PART1=12};
struct rtw89_dev;struct rtw89_mac_gen_def {int(*cnv_efuse_state)(struct rtw89_dev*,bool);};
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define u32_get_bits(v,m) (((v)&(m))>>__builtin_ctz(m))
#define u32p_replace_bits(p,v,m) (*(p)=(*(p)&~(m))|(((v)<<__builtin_ctz(m))&(m)))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define RTW89_HCI_TYPE_USB 1
#define RTW89_FWCMD_C2HREG_FUNC_NULL 255
#define RTW89_FWCMD_C2HREG_FUNC_TX_PAUSE_RPT 4
#define RTW89_FWCMD_H2CREG_FUNC_GET_FEATURE 3
#define RTW89_FWCMD_H2CREG_FUNC_SCH_TX_EN 5
#define lockdep_assert_wiphy(...) ((void)0)
#define rtw89_warn(...) ((void)0)
#define read_poll_timeout(op,val,cond,step,budget,pre,...) ({val=op(__VA_ARGS__);assert(cond);0;})
#define read_poll_timeout_atomic read_poll_timeout
struct rtw89_chip_info{u8 chip_gen,tx_nss,rx_nss,rf_path_num;const struct rtw89_mac_gen_def*mac_def;u32 h2c_regs[4],c2h_regs[4],h2c_ctrl_reg,c2h_ctrl_reg;struct{u32 addr;u8 mask;}h2c_counter_reg,c2h_counter_reg;};
struct rtw89_fw_info{u8 h2c_counter,c2h_counter;};
struct rtw89_hal{u8 tx_nss,rx_nss,antenna_tx,antenna_rx;bool tx_path_diversity,ant_diversity,no_eht;};struct rtw89_efuse{u8 rfe_type;};
struct rtw89_dev{struct rtw89_hal hal;struct rtw89_efuse efuse;struct rtw89_chip_info*chip;struct rtw89_fw_info fw;struct{int type;}hci;u8 bytes[0x10000];};
static unsigned long long hash;static u32 count;static u32 reply[4];static int cnv(struct rtw89_dev*d,bool idle){return 0;}
static void byte(u8 v){hash^=v;hash*=1099511628211ULL;}
static void value(u32 v){for(int i=0;i<4;i++)byte(v>>(8*i));}
static void rec(u32 k,u32 a,u32 v){count++;value(k);value(a);value(v);}
static u8 rtw89_read8(struct rtw89_dev*d,u32 a){return d->bytes[a];}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){u32 v;memcpy(&v,d->bytes+a,4);return v;}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){memcpy(d->bytes+a,&v,4);rec(4,a,v);}
static void rtw89_write8(struct rtw89_dev*d,u32 a,u8 v){d->bytes[a]=v;rec(1,a,v);if(a==0x8160&&v==1){d->bytes[a]=0;d->bytes[0x8164]=1;if((rtw89_read32(d,0x8140)&127)==3){memcpy(d->bytes+0x8150,reply,16);}else{u32 response=0x204;memcpy(d->bytes+0x8150,&response,4);u16 enable=rtw89_read32(d,0x8140)>>16;memcpy(d->bytes+0xc348,&enable,2);}}}
static void rtw89_write8_mask(struct rtw89_dev*d,u32 a,u8 m,u8 v){rtw89_write8(d,a,(d->bytes[a]&~m)|((v<<__builtin_ctz(m))&m));}
'''
main=r'''int main(void){puts("type Golden=(u8,[u32;4],[u8;5],u32,u64);\npub(super) const CASES:&[Golden]=&[");
for(int seed=0;seed<2;seed++)for(int tx=0;tx<4;tx++)for(int rx=0;rx<4;rx++)for(int ta=0;ta<4;ta++)for(int ra=0;ra<4;ra++){
 struct rtw89_mac_gen_def md={.cnv_efuse_state=cnv};struct rtw89_chip_info c={.chip_gen=0,.tx_nss=2,.rx_nss=2,.rf_path_num=2,.mac_def=&md,.h2c_regs={0x8140,0x8144,0x8148,0x814c},.c2h_regs={0x8150,0x8154,0x8158,0x815c},.h2c_ctrl_reg=0x8160,.c2h_ctrl_reg=0x8164,.h2c_counter_reg={0x1f5,15},.c2h_counter_reg={0x1f5,0xf0}};
 static struct rtw89_dev d;memset(&d,0,sizeof(d));d.chip=&c;memset(d.bytes,seed?0xa5:0,sizeof(d.bytes));d.bytes[0x8160]=d.bytes[0x8164]=0;
 reply[0]=0x04000403|(rx<<16);reply[1]=0x5a030300|tx;reply[2]=seed?0xa5000001:1;reply[3]=0x03000000|(ta<<8)|(ra<<16);
 hash=14695981039346656037ULL;count=0;assert(!rtw89_mac_setup_phycap_part0(&d));assert(!rtw89_hw_sch_tx_en_h2c(&d,0,0,65535));
 printf("(%u,[%u,%u,%u,%u],[%u,%u,%u,%u,%u],%u,0x%llx),\n",seed?165:0,reply[0],reply[1],reply[2],reply[3],d.hal.tx_nss,d.hal.rx_nss,d.hal.antenna_tx?d.hal.antenna_tx:3,d.hal.antenna_rx?d.hal.antenna_rx:3,d.hal.tx_path_diversity,count,hash);
}puts("];");return 0;}'''
source=prefix+regs+'\n'+structs+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-mailbox-c-') as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B firmware PHY capability SHA256 '+hashlib.sha256((regs+structs+body).encode()).hexdigest()+'\n'+out
path=d/'golden.rs'
value=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=value.encode()).decode()
if a.check:
 if path.read_text()!=value:raise SystemExit('firmware PHY capability oracle differs')
else:path.write_text(value)
