#!/usr/bin/env python3
"""Run original AX gain callbacks and packed argument layout, preserving s8."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
phy=(a.linux/'phy.c').read_text();core=(a.linux/'core.h').read_text();tables=(a.linux/'rtw8852b_table.c').read_text()
def block(source,pattern):
 m=re.search(pattern,source,re.M);end=source.index('{',m.end())+1;depth=1
 while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[m.start():end]
union=block(phy,r'^union rtw89_phy_bb_gain_arg\s*')+' __packed;\n'
gain=block(core,r'^struct rtw89_phy_bb_gain_info\s*')+';\n'
enum=block(phy,r'^enum rtw89_phy_bb_rxsc_start_idx\s*')+';\n'
names=['rtw89_phy_cfg_bb_gain_error','rtw89_phy_cfg_bb_rpl_ofst','rtw89_phy_cfg_bb_gain_bypass','rtw89_phy_cfg_bb_gain_op1db','rtw89_phy_config_bb_gain_ax']
functions='\n'.join(block(phy,r'^(?:static\s+)?void\s+'+name+r'\s*\(') for name in names)
table=re.search(r'^static const struct rtw89_reg2_def rtw89_8852b_phy_bb_reg_gain\[\] = \{.*?^\};',tables,re.M|re.S).group(0)
prefix='''#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint32_t u32;typedef uint64_t u64;
#define __packed __attribute__((packed))
#define RTW89_BB_GAIN_BAND_NR 8
#define RF_PATH_MAX 4
#define LNA_GAIN_NUM 7
#define TIA_GAIN_NUM 2
#define RTW89_BB_RXSC_NUM_40 9
#define RTW89_BB_RXSC_NUM_80 13
#define RTW89_BB_RXSC_NUM_160 15
#define rtw89_warn(...) ((void)0)
#define fallthrough __attribute__((fallthrough))
enum rtw89_rf_path {RF_PATH_A,RF_PATH_B};
enum {RTW89_CHANNEL_WIDTH_20,RTW89_CHANNEL_WIDTH_40,RTW89_CHANNEL_WIDTH_80,RTW89_CHANNEL_WIDTH_160};
struct rtw89_reg2_def {u32 addr,data;};
struct rtw89_chip_info {u8 rf_path_num;};struct rtw89_efuse {u8 rfe_type;};
'''
shim='struct rtw89_dev {const struct rtw89_chip_info *chip;struct rtw89_efuse efuse;struct {struct rtw89_phy_bb_gain_info ax;}bb_gain;};\n'
main=r'''static void emit(struct rtw89_dev *d,const char *name){
 printf("pub(super) const %s: &[i8] = &[",name);
 for(int b=0;b<8;b++)for(int p=0;p<2;p++) {
 #define OUT(field,n) for(int i=0;i<n;i++)printf("%d,",d->bb_gain.ax.field[b][p][i])
 OUT(lna_gain,7);OUT(tia_gain,2);OUT(lna_gain_bypass,7);OUT(lna_op1db,7);OUT(tia_lna_op1db,8);
 printf("%d,",d->bb_gain.ax.rpl_ofst_20[b][p]);OUT(rpl_ofst_40,9);OUT(rpl_ofst_80,13);OUT(rpl_ofst_160,15);
 }
 printf("];\n");
}
int main(void){
 struct rtw89_chip_info chip={2};struct rtw89_dev dev={.chip=&chip,.efuse.rfe_type=1};
 for(u32 i=0;i<sizeof(rtw89_8852b_phy_bb_reg_gain)/sizeof(rtw89_8852b_phy_bb_reg_gain[0]);i++)rtw89_phy_config_bb_gain_ax(&dev,&rtw89_8852b_phy_bb_reg_gain[i],0,0);
 emit(&dev,"DEFAULT");memset(&dev.bb_gain,0,sizeof(dev.bb_gain));
 printf("pub(super) const SYNTH: &[Pair] = &[");
 for(u32 kind=0;kind<4;kind++)for(u32 type=0;type<256;type++) {
  if(kind==0&&type>2)continue;if(kind==2&&type>1)continue;if(kind==3&&type>3)continue;
  if(kind==1&&!(type==0||type==16||type==17||type==32||type==33||type==41||type==48||type==49||type==53||type==57||type==61))continue;
  union rtw89_phy_bb_gain_arg arg={.cfg_type=kind,.gain_band=7,.path=1,.type=type};
  struct rtw89_reg2_def reg={arg.addr,0x80fe7f01};rtw89_phy_config_bb_gain_ax(&dev,&reg,0,0);
  printf("Pair(0x%x,0x%x),",reg.addr,reg.data);
 }
 printf("];\n");emit(&dev,"EXPECTED");return 0;
}'''
body=union+gain+enum+functions+table
with tempfile.TemporaryDirectory(prefix='rtw89-gain-oracle-') as td:
 td=Path(td);(td/'oracle.c').write_text(prefix+union+gain+enum+shim+functions+'\n'+table+'\n'+main)
 subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True)
 result=subprocess.check_output([str(td/'oracle')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux gain callbacks/types SHA256 '+hashlib.sha256(body.encode()).hexdigest()+'\n'+result
path=d/'golden.rs'
if a.check:
 if path.read_text()!=value:raise SystemExit('B gain oracle differs')
else:path.write_text(value)
