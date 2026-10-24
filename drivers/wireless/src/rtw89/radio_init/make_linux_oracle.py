#!/usr/bin/env python3
"""Execute original B BB/power/reset/RF upload and AX NCTL callbacks."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
phy=(a.linux/'phy.c').read_text();common=(a.linux/'rtw8852b_common.c').read_text();chip=(a.linux/'rtw8852b.c').read_text();tables=(a.linux/'rtw8852b_table.c').read_text()
def function(name,source):
 m=re.search(r'^(?:static\s+)?(?:int|u32|void)\s+'+name+r'\s*\(',source,re.M)
 if not m:raise RuntimeError(name)
 end=source.index('{',m.end())+1;depth=1
 while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[m.start():end]+'\n'
names=['rtw89_phy_sel_headline','rtw89_phy_init_reg','rtw89_phy_config_bb_reg','rtw89_phy_cofig_rf_reg_store','rtw89_phy_config_rf_reg_v1','rtw89_phy_config_rf_reg_fw','rtw89_phy_nctl_poll','rtw89_phy_preinit_rf_nctl_ax']
functions=[function(n,phy) for n in names]
functions += [function('__rtw8852bx_set_txpwr_ul_tb_offset',common),function('__rtw8852bx_init_txpwr_unit',common),function('__rtw8852bx_bb_reset_all',common),function('rtw8852b_bb_reset',chip)]
body='\n'.join(functions)
original=[]
for name in ['bb_regs','radioa_regs','radiob_regs','nctl_regs']:
 original.append(re.search(r'^static const struct rtw89_reg2_def rtw89_8852b_phy_'+name+r'\[\] = \{.*?^\};',tables,re.M|re.S).group(0))
header=(a.linux/'reg.h').read_text()+'\n'+(a.linux/'core.h').read_text()+'\n'+(a.linux/'fw.h').read_text()
definitions={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',header,re.M)}
selected=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+|RFREG_MASK|RTW89_H2C_RF_PAGE_\w+|BYPASS_CR_DATA)\b',body))
todo=list(selected)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',definitions[n]):
  if dep in definitions and dep not in selected:selected.add(dep);todo.append(dep)
defs='\n'.join(definitions[n] for n in sorted(selected))
ph=re.search(r'#define get_phy_headline.*?#define PHY_COND_DONT_CARE[^\n]+',(a.linux/'phy.h').read_text(),re.S).group(0)
prefix='''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint32_t __le32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define cpu_to_le32(v) (v)
static bool rejected;
#define rtw89_warn(...) ((void)(rejected=true))
#define rtw89_err(...) ((void)(rejected=true))
#define rtw89_debug(...) ((void)0)
#define RTW89_PHY_0 0
#define RTW89_PHY_1 1
#define RTW89_MAC_0 0
#define RTW89_MAC_1 1
#define RTL8852B 1
#define RTL8851B 2
#define RTL8852BT 3
enum rtw89_phy_idx {PHY0,PHY1};enum rtw89_mac_idx {MAC0,MAC1};enum rtw89_rf_path {RF_PATH_A,RF_PATH_B};
struct rtw89_reg2_def {u32 addr,data;};struct rtw89_phy_table {const struct rtw89_reg2_def *regs;u32 n_regs;enum rtw89_rf_path rf_path;};
struct rtw89_chip_info {int chip_id;};struct rtw89_dev {const struct rtw89_chip_info *chip;struct {u8 acv,cv;}hal;struct {u8 rfe_type;}efuse;u32 words[0x20000/4];};
static u64 hash;static u32 count;
static void octet(u8 v){hash^=v;hash*=1099511628211ULL;}
static void value(u32 v){for(int i=0;i<4;i++)octet(v>>(i*8));}
static void record(u32 kind,u32 address,u32 v){count++;value(kind);value(address);value(v);}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){return d->words[a/4];}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){d->words[a/4]=v;record(4,a,v);}
static void rtw89_write32_set(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32(d,a,rtw89_read32(d,a)|v);}
static void rtw89_write32_clr(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32(d,a,rtw89_read32(d,a)&~v);}
static void rtw89_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_write32(d,a,(rtw89_read32(d,a)&~m)|FIELD_PREP(m,v));}
static void rtw89_phy_write32(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32(d,a+0x10000,v);}
static void rtw89_phy_write32_set(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32_set(d,a+0x10000,v);}
static void rtw89_phy_write32_clr(struct rtw89_dev*d,u32 a,u32 v){rtw89_write32_clr(d,a+0x10000,v);}
static void rtw89_phy_write32_idx(struct rtw89_dev*d,u32 a,u32 m,u32 v,int idx){assert(idx==0);rtw89_write32_mask(d,a+0x10000,m,v);}
static u32 rtw89_phy_read32(struct rtw89_dev*d,u32 a){return rtw89_read32(d,a+0x10000);}
static int rtw89_phy0_phy1_offset(struct rtw89_dev*d,u32 a){return 0;}
static int rtw89_mac_txpwr_write32(struct rtw89_dev*d,int idx,u32 a,u32 v){assert(idx==0&&a>=0xd200&&a<0xe000);rtw89_write32(d,a,v);return 0;}
static u32 rtw89_mac_reg_by_idx(struct rtw89_dev*d,u32 a,int idx){assert(idx==0);return a;}
static void udelay(u32 us){record(8,us,0);}
static void fsleep(u32 us){udelay(us);}
static void rtw89_io_udelay(struct rtw89_dev*d,u32 us){udelay(us);}
static void rtw89_io_mdelay(struct rtw89_dev*d,u32 ms){udelay(ms*1000);}
static bool rtw89_write_rf(struct rtw89_dev*d,int path,u32 a,u32 m,u32 v){count++;value(16);value(path);value(a);value(m);value(v);return true;}
#define rtw8852bx_set_txpwr_ul_tb_offset __rtw8852bx_set_txpwr_ul_tb_offset
#define rtw8852bx_bb_reset_all __rtw8852bx_bb_reset_all
#define read_poll_timeout(op,val,condition,step,budget,pre,...) ({int err=-ETIMEDOUT;for(u32 t=0;t<=budget;t+=step){val=op(__VA_ARGS__);if(condition){err=0;break;}if(t<budget)udelay(step);}err;})
'''
shim='''struct rtw89_fw_h2c_rf_reg_info {u32 rtw89_phy_config_rf_h2c[3][500];u16 curr_idx;u8 rf_path;};
static int rtw89_fw_h2c_rf_reg(struct rtw89_dev*d,struct rtw89_fw_h2c_rf_reg_info *info,u16 len,u8 page){count++;value(32);value(info->rf_path);value(page);value(len);u8 *p=(u8*)info->rtw89_phy_config_rf_h2c[page];for(int i=0;i<len;i++)octet(p[i]);return 0;}
'''
main=r'''int main(void){
 puts("pub(super) const CASES: &[(u8,u8,u8,u32,u64,u32,u64,bool)] = &[");u8 rfes[]={1,5,16};struct rtw89_chip_info chip={RTL8852B};
 for(int s=0;s<2;s++)for(int r=0;r<3;r++)for(int c=0;c<2;c++) {
  struct rtw89_dev dev={.chip=&chip,.hal.cv=c,.efuse.rfe_type=rfes[r]};u32 seed=s?0xa5a5a5a5:0;
  for(u32 i=0;i<0x20000/4;i++)dev.words[i]=seed;hash=14695981039346656037ULL;count=0;rejected=false;
  struct rtw89_phy_table bb={rtw89_8852b_phy_bb_regs,sizeof(rtw89_8852b_phy_bb_regs)/8,0};
  rtw89_phy_init_reg(&dev,&bb,false,rtw89_phy_config_bb_reg,0);__rtw8852bx_init_txpwr_unit(&dev,0);rtw8852b_bb_reset(&dev,0);
  const struct rtw89_reg2_def *rf[]={rtw89_8852b_phy_radioa_regs,rtw89_8852b_phy_radiob_regs};u32 sizes[]={sizeof(rtw89_8852b_phy_radioa_regs)/8,sizeof(rtw89_8852b_phy_radiob_regs)/8};
  for(int p=0;p<2;p++){struct rtw89_phy_table t={rf[p],sizes[p],p};struct rtw89_fw_h2c_rf_reg_info info={.rf_path=p};rtw89_phy_init_reg(&dev,&t,false,rtw89_phy_config_rf_reg_v1,&info);if(rtw89_phy_config_rf_reg_fw(&dev,&info))return 1;}
  bool invalid=rejected;u32 n=count;u64 h=hash;hash=14695981039346656037ULL;count=0;
  rtw89_phy_preinit_rf_nctl_ax(&dev);struct rtw89_phy_table t={rtw89_8852b_phy_nctl_regs,sizeof(rtw89_8852b_phy_nctl_regs)/8,0};rtw89_phy_init_reg(&dev,&t,false,rtw89_phy_config_bb_reg,0);
  printf("(%u,%u,%u,%u,0x%llx,%u,0x%llx,%s),\n",s?165:0,rfes[r],c,n,(unsigned long long)h,count,(unsigned long long)hash,invalid?"true":"false");
 }puts("];");return 0;
}'''
source=prefix+defs+'\n'+ph+'\n'+shim+'\n'.join(original)+'\n'+body+'\n'+main
with tempfile.TemporaryDirectory(prefix='rtw89-radio-init-') as td:
 td=Path(td);(td/'oracle.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True);result=subprocess.check_output([str(td/'oracle')]).decode()
result=result.replace('pub(super) const CASES: &[(u8,u8,u8,u32,u64,u32,u64,bool)]','type InitGolden = (u8,u8,u8,u32,u64,u32,u64,bool);\npub(super) const CASES: &[InitGolden]')
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B radio init callbacks/tables SHA256 '+hashlib.sha256((body+'\n'.join(original)+defs+ph).encode()).hexdigest()+'\n'+result
path=d/'golden.rs'
if a.check:
 if path.read_text()!=value:raise SystemExit('B radio-init oracle differs')
else:path.write_text(value)
