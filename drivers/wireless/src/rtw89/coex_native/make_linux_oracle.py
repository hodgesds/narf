#!/usr/bin/env python3
"""Execute original B PTA and MAC grant callbacks and C firmware structures."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
src={n:(a.linux/n).read_text() for n in ['mac.c','mac.h','coex.c','coex.h','core.h','fw.h','rtw8852b.c','rtw8852b_common.c','reg.h']}
def function(name,s):
 m=re.search(r'^(?:static\s+)?(?:int|u32|void)\s+'+name+r'\s*\(',s,re.M)
 if not m:raise RuntimeError(name)
 e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]+'\n'
def block(pattern,s):return re.search(pattern,s,re.M|re.S).group(0)
body=''.join(function(n,src['mac.c']) for n in ['rtw89_mac_write_lte','rtw89_mac_read_lte','rtw89_mac_coex_init','rtw89_mac_cfg_gnt','rtw89_mac_cfg_ctrl_path','rtw89_mac_cfg_plt_ax','rtw89_mac_cfg_sb'])
body+=block(r'union rtw8852b_btc_wl_txpwr_ctrl \{.*?^\} __packed;',src['rtw8852b.c'])+'\n'+function('rtw8852b_btc_set_wl_txpwr_ctrl',src['rtw8852b.c'])+'\n'
body+=function('__rtw8852bx_btc_set_wl_pri',src['rtw8852b_common.c'])+function('rtw8852bx_set_trx_mask',src['rtw8852b_common.c'])+function('__rtw8852bx_btc_init_cfg',src['rtw8852b_common.c'])
# Packed C ABI is independent of the Rust encoder.
structs=''.join(block(r'struct '+n+r' \{.*?^\} __packed;',src['core.h'] if n.startswith('rtw89_btc_fbtc') else src['fw.h'])+'\n' for n in ['rtw89_btc_fbtc_tdma','rtw89_btc_fbtc_tdma_v3','rtw89_btc_fbtc_slot','rtw89_h2c_cxhdr','rtw89_h2c_cxinit'])
structs+=block(r'struct btc_fbtc_1slot \{.*?^\} __packed;',src['coex.c'])+'\n'
enums=''.join(block(r'enum '+n+r' \{.*?^\};',src['coex.c'])+'\n' for n in ['btc_fbtc_tdma_template','btc_fbtc_tdma_type','btc_fbtc_tdma_rx_flow_ctrl','btc_fbtc_tdma_wlan_tx_pause'])
# Slot enum and type are source-defined, not duplicated Rust constants.
for token in ['CXST_OFF','SLOT_MIX']:
 m=re.search(r'enum \w+ \{[^}]*\b'+token+r'\b[^}]*\};',src['core.h'],re.S);enums+=m.group(0)+'\n'
tables=block(r'static const struct rtw89_btc_fbtc_tdma t_def\[\] = \{.*?^\};',src['coex.c'])+'\n'
tables+=block(r'#define __DEF_FBTC_SLOT.*?static const struct rtw89_btc_fbtc_slot s_def\[\] = \{.*?^\};',src['coex.c'])+'\n'
tables+=block(r'static const u32 cxtbl\[\] = \{.*?^\};',src['coex.c'])+'\n'
headers='\n'.join(src[n] for n in ['reg.h','core.h','mac.h','fw.h','coex.h'])
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)}
selected=set(re.findall(r'\b(?:R_[A-Z0-9_]+|RR_[A-Z0-9_]+|B_[A-Z0-9_]+|MAC_AX_\w+|RFREG_MASK|BTC_BREAK_PARAM)\b',body));todo=list(selected)
while todo:
 n=todo.pop()
 if n not in defs:raise RuntimeError(n)
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in selected:selected.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(selected))
prefix=r'''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
typedef uint8_t u8;typedef int16_t s16;typedef int32_t s32;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BUILD_BUG_ON(v) _Static_assert(!(v),"mask")
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define RTW89_PHY_0 0
#define RTW89_MAC_0 0
#define RTW89_CMAC_SEL 0
enum rtw89_core_chip_id{RTL8852B=1,RTL8851B,RTL8852BT};
#define RTW89_MAC_AX_COEX_RTK_MODE 0
#define RTW89_MAC_AX_COEX_CSR_MODE 1
#define RTW89_MAC_AX_COEX_INNER 0
#define RTW89_MAC_AX_COEX_OUTPUT 1
#define RTW89_MAC_AX_COEX_INPUT 2
#define RF_PATH_A 0
#define RF_PATH_B 1
#define BTC_ANT_SHARED 0
#define BTC_PRI_MASK_TX_RESP 0
#define BTC_PRI_MASK_BEACON 1
#define BTC_PRI_MASK_RX_CCK 2
#define BTC_BT_SS_GROUP 0
#define BTC_BT_TX_GROUP 2
#define BTC_BT_RX_GROUP 3
#define RTW89_MAC_AX_PLT_LTE_RX 1
#define RTW89_MAC_AX_PLT_GNT_BT_TX 2
#define RTW89_MAC_AX_PLT_GNT_BT_RX 4
#define RTW89_MAC_AX_PLT_GNT_WL 8
#define RTW89_FLAG_UNPLUGGED 0
#define RTW89_FLAG_POWERON 1
#define test_bit(n,p) ((n)==1)
#define rtw89_err(...) ((void)0)
#define read_poll_timeout(op,val,cond,step,budget,pre,...) ({val=op(__VA_ARGS__);assert(cond);0;})
struct rtw89_dev;
struct ops{void(*btc_set_wl_pri)(struct rtw89_dev*,u8,bool);};
struct rtw89_chip_info{int chip_id;struct ops*ops;struct{struct{u32 cfg,get;}n[1];}btc_sb;};
struct rtw89_btc{u8 ant_type;};
struct rtw89_dev{struct rtw89_chip_info*chip;struct rtw89_btc btc;u8 bytes[0x20000];u32 lte[64];};
struct rtw89_mac_ax_coex{int pta_mode,direction;};
struct rtw89_mac_ax_coex_gnt{struct{bool gnt_bt,gnt_bt_sw_en,gnt_wl,gnt_wl_sw_en;}band[2];};
struct rtw89_mac_ax_plt{u8 band,tx,rx;};
static u64 hash;static u32 count;
static void octet(u8 v){hash^=v;hash*=1099511628211ULL;}
static void value(u32 v){for(int i=0;i<4;i++)octet(v>>(8*i));}
static void record(u32 k,u32 a,u32 v){count++;value(k);value(a);value(v);}
static u8 rtw89_read8(struct rtw89_dev*d,u32 a){return d->bytes[a]|(a==0xdaf3?32:0);}
static u16 rtw89_read16(struct rtw89_dev*d,u32 a){u16 v;memcpy(&v,d->bytes+a,2);return v;}
static u32 rtw89_read32(struct rtw89_dev*d,u32 a){u32 v;memcpy(&v,d->bytes+a,4);return v;}
static void rtw89_write8(struct rtw89_dev*d,u32 a,u8 v){d->bytes[a]=v;record(1,a,v);}
static void rtw89_write16(struct rtw89_dev*d,u32 a,u16 v){memcpy(d->bytes+a,&v,2);record(2,a,v);}
static void rtw89_write32(struct rtw89_dev*d,u32 a,u32 v){memcpy(d->bytes+a,&v,4);record(4,a,v);if(a==0xdaf0){if(v>>31){u32 idx=(v&0xff)/4;if(v>>30&1)d->lte[idx]=rtw89_read32(d,0xdaf4);else memcpy(d->bytes+0xdaf8,&d->lte[idx],4);}}}
#define helpers(bits) static void rtw89_write##bits##_set(struct rtw89_dev*d,u32 a,u##bits v){rtw89_write##bits(d,a,rtw89_read##bits(d,a)|v);}static void rtw89_write##bits##_clr(struct rtw89_dev*d,u32 a,u##bits v){rtw89_write##bits(d,a,rtw89_read##bits(d,a)&~v);}
helpers(8) helpers(16) helpers(32)
static bool rtw89_write_rf(struct rtw89_dev*d,u8 p,u32 a,u32 m,u32 v){count++;value(16);value(p);value(a);value(m);value(v);return true;}
static void rtw89_mac_txpwr_write32_mask(struct rtw89_dev*d,int i,u32 a,u32 m,u32 v){rtw89_write32(d,a,(rtw89_read32(d,a)&~m)|FIELD_PREP(m,v));}
static int rtw89_mac_check_mac_en(struct rtw89_dev*d,u8 i,int t){return 0;}
static u32 rtw89_mac_reg_by_idx(struct rtw89_dev*d,u32 a,u8 i){assert(i==0);return a;}
static void fsleep(u32 us){record(8,us,0);}
static void cmd(u8 f,const u8*b,u32 n,bool done){count++;value(32);value(f);value(done);value(n);for(int i=0;i<n;i++)octet(b[i]);}
'''
main=r'''int main(void){
 puts("pub(super) const CASES: &[(u8,u8,u32,u64)] = &[");
 for(int seed=0;seed<2;seed++)for(int dedicated=0;dedicated<2;dedicated++){
  struct ops ops={__rtw8852bx_btc_set_wl_pri};struct rtw89_chip_info chip={.chip_id=RTL8852B,.ops=&ops,.btc_sb.n[0].cfg=0xac};
  static struct rtw89_dev d;memset(&d,0,sizeof(d));d.chip=&chip;d.btc.ant_type=dedicated;
  memset(d.bytes,seed?0xa5:0,sizeof(d.bytes));for(int i=0;i<64;i++)d.lte[i]=seed?0xa5a5a5a5:0;
  count=0;hash=14695981039346656037ULL;__rtw8852bx_btc_init_cfg(&d);rtw89_mac_cfg_sb(&d,0x4003);
  u8 rfe=dedicated?2:1;struct rtw89_h2c_cxinit init={.hdr={0,12},.ant_type=dedicated,.ant_num=dedicated?3:2,.ant_iso=10,.mod_rfe=rfe,.mod_cv=1,.mod_info=dedicated?0:2,.wl_gch=6,.info=3};
  cmd(5,(u8*)&init,sizeof(init),false);u8 ctrl[]={6,4,0,0,0,0};cmd(5,ctrl,sizeof(ctrl),false);rtw8852b_btc_set_wl_txpwr_ctrl(&d,0xffffffff);
  struct rtw89_mac_ax_coex_gnt g={.band={{.gnt_bt_sw_en=1,.gnt_wl=1,.gnt_wl_sw_en=1},{.gnt_bt_sw_en=1,.gnt_wl=1,.gnt_wl_sw_en=1}}};
  rtw89_mac_cfg_gnt(&d,&g);u32 grant;assert(!rtw89_mac_read_lte(&d,0x38,&grant)&&grant==0x77007700);rtw89_mac_cfg_ctrl_path(&d,true);struct rtw89_mac_ax_plt plt={.band=0,.tx=8,.rx=8};rtw89_mac_cfg_plt_ax(&d,&plt);
  struct{u8 type,len;struct rtw89_btc_fbtc_tdma_v3 t;}__packed tdma={.type=0,.len=12,.t={.fver=3,.tdma=t_def[CXTD_OFF]}};
  struct{u8 type,len;struct btc_fbtc_1slot s;}__packed slot={.type=1,.len=10,.s={.fver=1,.sid=CXST_OFF,.slot=s_def[CXST_OFF]}};slot.s.slot.cxtbl=cpu_to_le32(cxtbl[2]);
  u8 policy[sizeof(tdma)+sizeof(slot)];memcpy(policy,&tdma,sizeof(tdma));memcpy(policy+sizeof(tdma),&slot,sizeof(slot));cmd(3,policy,sizeof(policy),true);
  printf("(%d,%d,%u,0x%llx),\n",seed?165:0,rfe,count,(unsigned long long)hash);
 }puts("];" );return 0;
}'''
source=prefix+regs+'\n'+structs+enums+tables+'\n'+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-coex-c-') as td:
 td=Path(td);(td/'oracle.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True);out=subprocess.check_output([str(td/'oracle')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux B WLAN-only SHA256 '+hashlib.sha256((body+structs+enums+tables+regs).encode()).hexdigest()+'\n'+out
recipe=hashlib.sha256(''.join(src[n] for n in sorted(src)).encode()).digest()
recipe_text='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Exact Linux B WLAN-only coexistence recipe.\n#[rustfmt::skip]\npub(super) const RECIPE: [u8;32] = ['+','.join(str(v) for v in recipe)+'];\n'
if a.check:
 if (d/'recipe.rs').read_text()!=recipe_text:raise SystemExit('B coex recipe differs')
else:(d/'recipe.rs').write_text(recipe_text)
path=d/'golden.rs'
if a.check:
 if path.read_text()!=value:raise SystemExit('B coex oracle differs')
else:path.write_text(value)
