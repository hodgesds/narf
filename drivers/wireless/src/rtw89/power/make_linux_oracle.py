from pathlib import Path
import subprocess
import re
import sys
import tempfile

directory = Path(__file__).resolve().parent
artifacts = Path(tempfile.mkdtemp(prefix='narf-rtw89-linux-oracle-'))
linux = Path(sys.argv[1] if len(sys.argv) > 1 else '/usr/src/linux/drivers/net/wireless/realtek/rtw89')
def function(file, name):
    text = (linux / file).read_text()
    match = re.search(r'^(?:static )?(?:int|void) '+name+r'\(', text, re.M)
    start = match.start()
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'
mac = (linux/'mac.h').read_text()
enum = mac[mac.index('enum rtw89_mac_xtal_si_offset'):]
enum = enum[:enum.index('\n};')+3]
pwrdefs = mac[mac.index('#define\tPWR_CMD_WRITE'):mac.index('/* STA scheduler */')]
a = (linux/'rtw8852a.c').read_text()
a = a[a.index('static const struct rtw89_pwr_cfg rtw8852a_pwron'):a.index('static const struct rtw89_pwr_cfg * const pwr_on_seq_8852a')]
c = r'''/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2019-2020 Realtek Corporation
 * Power functions below are extracted unchanged from the local Linux source.
 * The register model emits an independent golden trace for Rust's owner. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define BIT(x) (1ULL << (x))
#define GENMASK(h,l) ((~0ULL<<(l)) & (~0ULL>>(63-(h))))
#define FIELD_PREP(mask,val) (((uint64_t)(val) << __builtin_ctzll(mask)) & (mask))
#define u32_get_bits(val,mask) (((val)&(mask)) >> __builtin_ctzll(mask))
#define RTW89_HCI_TYPE_PCIE 1
#define RTW89_HCI_TYPE_USB 2
#define CHIP_CAV 0
#define CHIP_CBV 1
#define RTW89_FLAG_UNPLUGGED 0
#define test_bit(...) false
#define rtw89_warn(...) ((void)0)
#define read_poll_timeout(op,val,cond,interval,budget,delay,dev,address) ({ int result=-110; for(unsigned n=0;n<=((budget)/(interval));n++) { (val)=op(dev,address); if(cond) {result=0;break;} } result; })
struct rtw89_efuse {u8 rfe_type;bool valid,power_k_valid;};
struct rtw89_dev {struct rtw89_efuse efuse; struct {u8 type;} hci;struct {u8 cv;} hal;unsigned flags[1];};
static u8 regs[65536],ecv;
static u8 rtw89_read8(struct rtw89_dev *d,u32 addr) {(void)d;return regs[addr];}
static u16 rtw89_read16(struct rtw89_dev *d,u32 addr) {(void)d;u16 val;memcpy(&val,regs+addr,2);return val;}
static u32 rtw89_read32(struct rtw89_dev *d,u32 addr) {(void)d;u32 val;memcpy(&val,regs+addr,4);return val;}
static void rtw89_write8(struct rtw89_dev *d,u32 addr,u8 val) {(void)d;printf("8 %u %u\n",addr,val);regs[addr]=val;if(addr==5)regs[5]&=~1;}
static void rtw89_write16(struct rtw89_dev *d,u32 addr,u16 val) {(void)d;printf("16 %u %u\n",addr,val);memcpy(regs+addr,&val,2);}
static void rtw89_write32(struct rtw89_dev *d,u32 addr,u32 val) {(void)d;printf("32 %u %u\n",addr,val);if(addr==4)val&=~(1<<8);if(addr==0x270)val&=~(1U<<31);memcpy(regs+addr,&val,4);}
#define HELPERS(bits,type) \
static void rtw89_write##bits##_set(struct rtw89_dev*d,u32 addr,type mask){rtw89_write##bits(d,addr,rtw89_read##bits(d,addr)|mask);} \
static void rtw89_write##bits##_clr(struct rtw89_dev*d,u32 addr,type mask){rtw89_write##bits(d,addr,rtw89_read##bits(d,addr)&~mask);} \
static void rtw89_write##bits##_mask(struct rtw89_dev*d,u32 addr,type mask,type value){rtw89_write##bits(d,addr,(rtw89_read##bits(d,addr)&~mask)|FIELD_PREP(mask,value));}
HELPERS(8,u8) HELPERS(16,u16) HELPERS(32,u32)
static u32 rtw89_read32_mask(struct rtw89_dev*d,u32 addr,u32 mask){return u32_get_bits(rtw89_read32(d,addr),mask);}
static void fsleep(unsigned us){printf("0 0 %u\n",us);}
static int rtw89_read_efuse_ver(struct rtw89_dev*d,u8 *value){(void)d;*value=ecv;printf("255 0 %u\n",ecv);return 0;}
'''
c += '#include "'+str(linux/'reg.h')+'"\n'+enum+'\n'+pwrdefs
c += function('mac.c','rtw89_mac_write_xtal_si_ax')
c += '#define rtw89_mac_write_xtal_si rtw89_mac_write_xtal_si_ax\n'
c += function('rtw8852b.c','rtw8852b_pwr_sps_ana') + function('rtw8852b.c','rtw8852b_pwr_sps_dig_off')
for chip in ['rtw8852b','rtw8852c','rtw8851b']:
    c += function(chip+'.c',chip+'_pwr_on_func')
c += 'struct rtw89_pwr_cfg {unsigned addr,cv_msk,intf_msk,base,cmd,msk,val;};\n'+a
c += r'''
int main(int argc,char**argv){
 if(argc!=9)return 2;
 unsigned chip=atoi(argv[1]);struct rtw89_dev d={0};d.hal.cv=atoi(argv[2]);d.efuse.rfe_type=atoi(argv[3]);d.efuse.valid=atoi(argv[4]);d.efuse.power_k_valid=atoi(argv[5]);ecv=atoi(argv[6]);unsigned pad=atoi(argv[7]);unsigned seed=atoi(argv[8]);d.hci.type=RTW89_HCI_TYPE_PCIE;
 memset(regs,seed,sizeof(regs));u32 ready=1<<17;memcpy(regs+R_AX_SYS_PW_CTRL,&ready,4);u32 hci=pad<<3;memcpy(regs+R_AX_SYS_STATUS1,&hci,4);
 int ret=0;
 if(chip==0){for(const struct rtw89_pwr_cfg *p=rtw8852a_pwron;p->cmd!=PWR_CMD_END;p++){
  if(!(p->intf_msk&4)||!(p->cv_msk&BIT(d.hal.cv)))continue;
  if(p->cmd==PWR_CMD_WRITE)rtw89_write8(&d,p->addr,(rtw89_read8(&d,p->addr)&~p->msk)|(p->val&p->msk));
  else if(p->cmd==PWR_CMD_POLL){if((rtw89_read8(&d,p->addr)&p->msk)!=(p->val&p->msk))ret=-110;}
 }}else if(chip==1)ret=rtw8852b_pwr_on_func(&d);else if(chip==2)ret=rtw8852c_pwr_on_func(&d);else ret=rtw8851b_pwr_on_func(&d);
 if(!ret)rtw89_write8(&d,R_AX_SCOREBOARD+3,MAC_AX_NOTIFY_TP_MAJOR);
 printf("RESULT %d %u\n",ret,d.hal.cv);return ret?1:0;
}
'''
(artifacts/'power_oracle.c').write_text(c)
subprocess.run(['cc','-std=gnu11','-Wall','-Wextra',str(artifacts/'power_oracle.c'),'-o',str(artifacts/'power_oracle')],check=True)
cases=[(0,0,0,0,0,0,0,0),(0,1,0,0,0,0,0,0),(1,0,0,0,0,0,0,0),(1,1,5,1,0,0,0,0),(2,0,0,0,0,0,0,0),(2,1,0,0,0,0,3,0),(3,0,0,0,0,1,0,0),(3,0,0,0,0,0,0,0)]
golden='// Independent Linux C callback traces; regenerate with make_linux_oracle.py.\npub const CASES: &[Case] = &[\n'
for case in cases:
    lines=subprocess.check_output([str(artifacts/'power_oracle'),*map(str,case)]).decode().splitlines()
    trace=[]
    for line in lines:
        if line.startswith('RESULT'):result=list(map(int,line.split()[1:]));continue
        trace.append(tuple(map(int,line.split())))
    golden+=f'Case {{ chip:{case[0]}, cut:{case[1]}, rfe:{case[2]}, valid:{str(bool(case[3])).lower()}, power_k_valid:{str(bool(case[4])).lower()}, ecv:{case[5]}, pad:{case[6]}, result_cut:{result[1]}, trace:&[\n'
    for width,addr,val in trace:golden+=f'({width},0x{addr:x},0x{val:x}),\n'
    golden+='] },\n'
golden+='];\n';(directory/'golden.rs').write_text(golden)
print('Independent Linux power trace cases',len(cases))
print('Generated primary-source C oracle:', artifacts/'power_oracle.c')
