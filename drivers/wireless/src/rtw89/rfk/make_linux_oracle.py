#!/usr/bin/env python3
"""Run original B RCK/DACK/RXDCK callbacks against explicit measurement inputs."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
source=(a.linux/'rtw8852b_rfk.c').read_text();phy=(a.linux/'phy.h').read_text();core=(a.linux/'core.h').read_text()
def function(name):
 m=re.search(r'^(?:static\s+)?(?:bool|u8|u32|void)\s+'+name+r'\s*\(',source,re.M)
 if not m:raise RuntimeError(name)
 end=source.index('{',m.end())+1;depth=1
 while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return m.start(),source[m.start():end]
names=['_kpath','_set_rx_dck','_rx_dck','_rck','_afe_init','_drck','_addck_backup','_addck_reload','_dack_backup_s0','_dack_backup_s1','_check_addc','_addck','_check_dadc','_dack_s0_check_done','_dack_s0','_dack_s1_check_done','_dack_s1','_dack','_dack_dump','_dac_cal','_wait_rx_mode','_set_dpd_backoff','rtw8852b_dpk_init','rtw8852b_rck','rtw8852b_dack','rtw8852b_rx_dck']
functions='\n'.join(v for _,v in sorted(function(n) for n in names))
table_source=(a.linux/'rtw8852b_rfk_table.c').read_text();tables=re.findall(r'^static const struct rtw89_reg5_def \w+\[\] = \{.*?^\};',table_source,re.M|re.S)
enum=re.search(r'enum rtw89_rfk_flag \{.*?\};',phy,re.S).group(0);macros=re.search(r'#define RTW89_DECL_RFK_WRF.*?\nvoid\nrtw89_rfk_parser',phy,re.S).group(0).split('\nvoid\n')[0]
header=(a.linux/'reg.h').read_text()+'\n'+core+'\n'+source;header=header.replace('\\\n','')
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',header,re.M)}
needed=set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+|RFREG_MASK|MASKDWORD|RTW89_DACK_\w+|RF_PATH_NUM_8852B|ADDC_T_AVG)\b',functions));needed.update(['RF_PATH_MAX','RTW89_DACK_PATH_NR','RTW89_DACK_IDX_NR'])
defs['RF_PATH_NUM_8852B']='#define RF_PATH_NUM_8852B 2'
todo=list(needed)
while todo:
 name=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[name]):
  if dep in defs and dep not in needed:needed.add(dep);todo.append(dep)
definitions='\n'.join(defs[n] for n in sorted(needed))
m=re.search(r'^struct rtw89_dack_info \{',core,re.M);end=core.index('};',m.end())+2;dack_type=core[m.start():end]
prefix='''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int32_t s32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define FIELD_GET_SIGNED(m,v) ((s32)((v)<<(31-(31-__builtin_clz(m))))>>(31-(31-__builtin_clz(m))+__builtin_ctz(m)))
#define rtw89_debug(...) ((void)0)
#define rtw89_err(...) ((void)0)
#define rtw89_warn(...) ((void)0)
#define RTW89_PHY_0 0
#define RTW89_PHY_1 1
#define RTW89_CHANCTX_0 0
#define RF_A 1
#define RF_B 2
#define RF_AB 3
#define BTC_WRFKT_DACK 0
#define BTC_WRFKT_RXDCK 1
#define BTC_WRFK_START 0
#define BTC_WRFK_STOP 1
#define RTW89_SCH_TX_SEL_ALL 0
enum rtw89_phy_idx {PHY0,PHY1};enum rtw89_chanctx_idx {CHAN0};enum rtw89_rf_path {RF_PATH_A,RF_PATH_B};
struct rtw89_reg5_def {u8 flag,path;u32 addr,mask,data;};struct rtw89_rfk_tbl {const struct rtw89_reg5_def *defs;u32 size;};
'''
shim=r'''
struct rtw89_dpk_info {u8 dpk_gs[2];};
struct rtw89_dev {bool dbcc_en,is_tssi_mode[4];struct rtw89_dack_info dack;struct {u8 cv;}hal;struct rtw89_dpk_info dpk;u32 words[0x20000/4];u32 rf[2][0x10100];};
static u64 hash;static u32 count;static bool second;
static void octet(u8 v){hash^=v;hash*=1099511628211ULL;}
static void value(u32 v){for(int i=0;i<4;i++)octet(v>>(i*8));}
static void three(u32 k,u32 a,u32 v){count++;value(k);value(a);value(v);}
static u32 read_word(struct rtw89_dev*d,u32 a){
 u32 v=d->words[a/4];u32 r=a-0x10000;
 if(r==R_DRCK_RS)v=0x98008;
 if(r==R_ADDCKR0)v=0xabcdf;
 if(r==R_ADDCKR1)v=0x54321;
 if(r==R_DACK_S0P0||r==R_DACK_S0P1)v|=0x80000000;
 if(r==R_DACK_S1P0)v=(v&~0x80000000)|(second?0:0x80000000);
 if(r==R_DACK_S1P1)v|=0x80000000;
 if(r==R_DACK_S0P2)v=((0x40+FIELD_GET(B_DCOF0_V,d->words[(0x10000+R_DCOF0)/4]))<<24)|0x123404;
 if(r==R_DACK_S0P3)v=((0x60+FIELD_GET(B_DCOF8_V,d->words[(0x10000+R_DCOF8)/4]))<<24)|0x123404;
 if(r==R_DACK10S)v=((0x80+FIELD_GET(B_DACK10,d->words[(0x10000+R_DACK10)/4]))<<24)|0x123404;
 if(r==R_DACK11S)v=((0xa0+FIELD_GET(B_DACK11,d->words[(0x10000+R_DACK11)/4]))<<24)|0x123404;
 three(0,a,v);return v;
}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){d->words[a/4]=v;three(4,a,v);}
static u32 rtw89_phy_read32_mask(struct rtw89_dev*d,u32 a,u32 m){return FIELD_GET(m,read_word(d,a+0x10000));}
static void rtw89_phy_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){u32 old=read_word(d,a+0x10000);rtw89_write32(d,a+0x10000,(old&~m)|FIELD_PREP(m,v));}
static void rtw89_phy_write32_set(struct rtw89_dev*d,u32 a,u32 m){u32 old=read_word(d,a+0x10000);rtw89_write32(d,a+0x10000,old|m);}
static void rtw89_phy_write32_clr(struct rtw89_dev*d,u32 a,u32 m){u32 old=read_word(d,a+0x10000);rtw89_write32(d,a+0x10000,old&~m);}
static u32 rtw89_read_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m){u32 v=d->rf[p][a];if(a==RR_RCKS)v|=8;if(a==RR_RCKC&&v==0x240)v|=0x4800;v=FIELD_GET(m,v);count++;value(32);value(p);value(a);value(m);value(v);return v;}
static bool rtw89_write_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m,u32 v){u32 old=d->rf[p][a];d->rf[p][a]=(old&~m)|FIELD_PREP(m,v);count++;value(36);value(p);value(a);value(m);value(v);return true;}
static void udelay(u32 us){three(8,us,0);}
static void mdelay(u32 ms){udelay(ms*1000);}
static u8 rtw89_btc_phymap(struct rtw89_dev*d,int p,int k,int c){return 0;}
static void rtw89_btc_ntfy_wl_rfk(struct rtw89_dev*d,int p,int kind,int event){three(48,kind,event);}
static void rtw89_chip_stop_sch_tx(struct rtw89_dev*d,int p,u32 *saved,int all){*saved=0x11223344;three(56,p,*saved);}
static void rtw89_chip_resume_sch_tx(struct rtw89_dev*d,int p,u32 saved){three(60,p,saved);}
static void rtw89_rfk_parser(struct rtw89_dev*d,const struct rtw89_rfk_tbl*t){for(u32 i=0;i<t->size;i++){const struct rtw89_reg5_def*p=t->defs+i;switch(p->flag){case 0:rtw89_write_rf(d,p->path,p->addr,p->mask,p->data);break;case 1:rtw89_phy_write32_mask(d,p->addr,p->mask,p->data);break;case 2:rtw89_phy_write32_set(d,p->addr,p->mask);break;case 3:rtw89_phy_write32_clr(d,p->addr,p->mask);break;case 4:udelay(p->data);break;}}}
#define RTW89_DECLARE_RFK_TBL(n) const struct rtw89_rfk_tbl n##_tbl={n,sizeof(n)/sizeof(n[0])}
#define rtw89_rfk_parser_by_cond(d,c,t,f) rtw89_rfk_parser(d,(c)?(t):(f))
#define read_poll_timeout_atomic(op,val,condition,step,budget,pre,...) ({int err=-ETIMEDOUT;for(u32 t=0;t<=budget;t+=step){val=op(__VA_ARGS__);if(condition){err=0;break;}if(t<budget)udelay(step);}err;})
'''
table_declarations='\n'.join(t+'\nRTW89_DECLARE_RFK_TBL('+re.search(r'rtw8852b_\w+',t).group(0)+');' for t in tables)
main=r'''int main(void){
 puts("type RfkGolden = (u8,bool,bool,u32,u64,&'static [u8]);\npub(super) const CASES: &[RfkGolden] = &[");
 for(int seed=0;seed<2;seed++)for(int high=0;high<2;high++)for(int alt=0;alt<2;alt++) {
  static struct rtw89_dev d;memset(&d,0,sizeof(d));second=alt;u32 s=seed?0xa5a5a5a5:0;
  for(u32 i=0;i<0x20000/4;i++)d.words[i]=s;for(int p=0;p<2;p++)for(u32 a=0;a<0x10100;a++)d.rf[p][a]=(s&0xfffff);
  d.words[(0x10000+R_DPD_BF)/4]=FIELD_PREP(B_DPD_BF_OFDM,high?31:0)|FIELD_PREP(B_DPD_BF_SCA,high?20:0);
  hash=14695981039346656037ULL;count=0;rtw8852b_dpk_init(&d);rtw8852b_rck(&d);rtw8852b_dack(&d,0);rtw8852b_rx_dck(&d,0,0);
  printf("(%u,%s,%s,%u,0x%llx,&[",seed?165:0,high?"true":"false",alt?"true":"false",count,(unsigned long long)hash);
  for(int p=0;p<2;p++)for(int k=0;k<2;k++)for(int i=0;i<16;i++)printf("%u,",d.dack.msbk_d[p][k][i]);
  for(int p=0;p<2;p++)for(int k=0;k<2;k++)printf("%u,",d.dack.dadck_d[p][k]);
  for(int p=0;p<2;p++)for(int k=0;k<2;k++){u16 v=d.dack.addck_d[p][k];printf("%u,%u,",v&255,v>>8);}
  for(int p=0;p<2;p++)for(int k=0;k<2;k++){u16 v=d.dack.biask_d[p][k];printf("%u,%u,",v&255,v>>8);}
  printf("%u]),\n",d.dpk.dpk_gs[0]);
 }puts("];");return 0;
}'''
code=prefix+enum+'\n'+definitions+'\n'+dack_type+'\n'+macros+'\n'+shim+'\n'+table_declarations+'\n'+functions+'\n'+main
with tempfile.TemporaryDirectory(prefix='rtw89-rfk-oracle-') as td:
 td=Path(td);(td/'oracle.c').write_text(code);subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True);result=subprocess.check_output([str(td/'oracle')]).decode()
body=functions+table_source+definitions+enum+macros+dack_type
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B basic RFK callbacks/types SHA256 '+hashlib.sha256(body.encode()).hexdigest()+'\n'+result
path=d/'golden.rs'
if a.check:
 if path.read_text()!=value:raise SystemExit('B RFK oracle differs')
else:path.write_text(value)
