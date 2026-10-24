#!/usr/bin/env python3
"""Original AX power packing/fixed20 limit helpers plus full B shape/reference."""
from pathlib import Path
import re,hashlib,argparse,tempfile,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'));p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent;phy=(a.linux/'phy.c').read_text();ph=(a.linux/'phy.h').read_text();common=(a.linux/'rtw8852b_common.c').read_text();core=(a.linux/'core.h').read_text()
def b(s,pattern):
 m=re.search(pattern,s,re.M);e=s.index('{',m.end())+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[m.start():e]
def f(n,s):return b(s,r'^(?:static\s+)?(?:void|u32)\s+'+n+r'\s*\(')+'\n'
body=''.join(f(n,phy) for n in ['rtw89_phy_set_txpwr_byrate_ax','rtw89_phy_set_txpwr_offset_ax','rtw89_phy_set_txpwr_limit_ax','rtw89_phy_set_txpwr_limit_ru_ax'])+''.join(f(n,common) for n in ['rtw8852bx_bb_cal_txpwr_ref','rtw8852bx_set_txpwr_ref','rtw8852bx_bb_set_tx_shape_dfir','rtw8852bx_set_tx_shape'])
helpers=f('rtw89_phy_fill_txpwr_limit_20m_ax',phy)+f('rtw89_phy_fill_txpwr_limit_ru_20m_ax',phy)
fillmacro=re.search(r'#define __fill_txpwr_limit_nonbf_bf.*?while \(0\)',phy,re.S).group(0)
structs=''.join(b(ph,r'^struct '+n+r'\s*')+';\n' for n in ['rtw89_txpwr_limit_ax','rtw89_txpwr_limit_ru_ax'])
enums=''.join(re.search(r'enum \w+ \{[^}]*\b'+n+r'\b[^}]*\};',core,re.S).group(0)+'\n' for n in ['RTW89_RS_CCK','RTW89_RATE_CCK_NUM','RTW89_NSS_1'])
arrays=''.join(re.search(r'^static const u8 '+n+r'\[\] = \{.*?^\};',phy,re.M|re.S).group(0)+'\n' for n in ['rtw89_rs_idx_num_ax','rtw89_rs_nss_num_ax'])
headers='\n'.join((a.linux/n).read_text() for n in ['reg.h','phy.h','core.h']);defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)};selected=set(re.findall(r'\b(?:R_[A-Z0-9_]+|B_[A-Z0-9_]+)\b',body));todo=list(selected)
while todo:
 n=todo.pop()
 for dep in re.findall(r'\b[A-Z][A-Z0-9_]+\b',defs[n]):
  if dep in defs and dep not in selected:selected.add(dep);todo.append(dep)
regs='\n'.join(defs[n] for n in sorted(selected))
pre=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef int16_t s16;typedef uint32_t u32;typedef int32_t s32;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_PREP(m,v) (((u32)(v)<<__builtin_ctz(m))&(m))
#define u16_get_bits(v,m) (((u16)(v)&(m))>>__builtin_ctz(m))
#define u32_encode_bits(v,m) FIELD_PREP(m,v)
#define clamp_t(t,v,l,h) ((t)(v)<(t)(l)?(t)(l):((t)(v)>(t)(h)?(t)(h):(t)(v)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))
#define BUILD_BUG_ON(v) assert(!(v))
#undef static_assert
#define static_assert(v) _Static_assert((v),"static")
#define rtw89_debug(...) ((void)0)
#define rtw89_warn(...) ((void)0)
#define RTW89_RATE_OFFSET_NUM_AX 5
#define RTW89_BF_NUM 2
#define RTW89_BW20_SEC_NUM_AX 8
#define RTW89_BW40_SEC_NUM_AX 4
#define RTW89_BW80_SEC_NUM_AX 2
#define RTW89_RU_SEC_NUM_AX 8
#define RTW89_TXPWR_LMT_PAGE_SIZE_AX 40
#define RTW89_TXPWR_LMT_RU_PAGE_SIZE_AX 24
#define RTW89_CHANNEL_WIDTH_20 0
#define RTW89_CHANNEL_WIDTH_40 1
#define RTW89_BAND_2G 0
#define RTW89_RU26 0
#define RTW89_RU52 1
#define RTW89_RU106 2
#define RF_PATH_NUM_8852BX 2
#define RF_PATH_A 0
#define RF_PATH_B 1
enum rtw89_phy_idx{PHY0};struct rtw89_rate_desc{u8 nss,rs,idx;};struct rtw89_chan{u8 band_type,channel,band_width;};
struct rtw89_chip_info{u8 rf_path_num;};struct rtw89_dev{struct rtw89_chip_info*chip;u32 words[0x20000/4];s8 byr[44],off[5],lmt[2][8],ru[2][3];u8 shape[2];};
static u64 hash;static u32 count;
static void record(u32 k,u32 a,u32 v){count++;u32 words[]={k,a,v};for(int i=0;i<3;i++)for(int j=0;j<4;j++){hash^=(u8)(words[i]>>(j*8));hash*=1099511628211ULL;}}
static int rtw89_mac_txpwr_write32(struct rtw89_dev*d,u8 i,u32 a,u32 v){assert(i==0);d->words[a/4]=v;record(4,a,v);return 0;}
static int rtw89_mac_txpwr_write32_mask(struct rtw89_dev*d,u8 i,u32 a,u32 m,u32 v){return rtw89_mac_txpwr_write32(d,i,a,(d->words[a/4]&~m)|FIELD_PREP(m,v));}
static void rtw89_phy_write32_idx(struct rtw89_dev*d,u32 a,u32 m,u32 v,u8 i){rtw89_mac_txpwr_write32_mask(d,i,a+0x10000,m,v);}
static void rtw89_phy_write32_mask(struct rtw89_dev*d,u32 a,u32 m,u32 v){rtw89_phy_write32_idx(d,a,m,v,0);}
static s8 rtw89_phy_read_txpwr_byrate(struct rtw89_dev*d,u8 b,u8 bw,const struct rtw89_rate_desc*r){assert(b==0&&bw==0);u8 base=r->rs==0?0:r->rs==1?4:r->rs==2?(r->nss?28:12):(r->nss?40:24);return (r->rs==4?d->off[r->idx]:d->byr[base+r->idx])>>1;}
static s8 rtw89_phy_read_txpwr_limit(struct rtw89_dev*d,u8 b,u8 bw,u8 n,u8 rs,u8 bf,u8 ch){assert(b==0&&ch==1);return d->lmt[n][(rs==0?(bw?2:0):rs==1?4:6)+bf]>>1;}
static s8 rtw89_phy_read_txpwr_limit_ru(struct rtw89_dev*d,u8 b,u8 ru,u8 n,u8 ch){assert(b==0&&ch==1&&ru<3);return d->ru[n][ru]>>1;}
static u8 rtw89_get_tx_shape_idx(struct rtw89_dev*d,u8 b,u8 rs){assert(b==0&&rs<2);return d->shape[rs];}
'''
shim='''static void rtw89_phy_fill_txpwr_limit_ax(struct rtw89_dev*d,const struct rtw89_chan*c,struct rtw89_txpwr_limit_ax*l,u8 n){assert(c->band_width==0);memset(l,0,sizeof(*l));rtw89_phy_fill_txpwr_limit_20m_ax(d,l,c->band_type,n,c->channel);}
static void rtw89_phy_fill_txpwr_limit_ru_ax(struct rtw89_dev*d,const struct rtw89_chan*c,struct rtw89_txpwr_limit_ru_ax*l,u8 n){assert(c->band_width==0);memset(l,0,sizeof(*l));rtw89_phy_fill_txpwr_limit_ru_20m_ax(d,l,c->band_type,n,c->channel);}
'''
main=r'''int main(void){puts("pub(super) const CASES:&[(u8,bool,u8,u32,u64)]=&[");for(int seed=0;seed<2;seed++)for(int neg=0;neg<2;neg++)for(int sharp=0;sharp<2;sharp++){struct rtw89_dev d={};struct rtw89_chip_info chip={2};d.chip=&chip;for(int i=0;i<0x20000/4;i++)d.words[i]=seed?0xa5a5a5a5:0;for(int i=0;i<44;i++)d.byr[i]=neg?-(i*3%120):80-i%20;for(int i=0;i<5;i++)d.off[i]=(s8[]){-16,-7,2,15,0}[i];for(int n=0;n<2;n++){for(int i=0;i<8;i++)d.lmt[n][i]=neg?-11-i*3-n:40+i*2+n;for(int i=0;i<3;i++)d.ru[n][i]=neg?-7-i*3-n:28+i*2+n;}d.shape[0]=sharp;d.shape[1]=sharp?3:0;hash=14695981039346656037ULL;count=0;struct rtw89_chan c={0,1,0};rtw89_phy_set_txpwr_byrate_ax(&d,&c,0);rtw89_phy_set_txpwr_offset_ax(&d,&c,0);rtw8852bx_set_tx_shape(&d,&c,0);rtw89_phy_set_txpwr_limit_ax(&d,&c,0);rtw89_phy_set_txpwr_limit_ru_ax(&d,&c,0);rtw8852bx_set_txpwr_ref(&d,0,0);printf("(%u,%s,%u,%u,0x%llx),\n",seed?165:0,neg?"true":"false",sharp,count,(unsigned long long)hash);}puts("];");}'''
source=pre+enums+structs+arrays+regs+'\n'+fillmacro+'\n'+helpers+shim+body+main
with tempfile.TemporaryDirectory(prefix='rtw89-power-c-')as td:
 td=Path(td);(td/'o.c').write_text(source);subprocess.run(['cc','-std=gnu11','-O2','-fwrapv',str(td/'o.c'),'-o',str(td/'o')],check=True);out=subprocess.check_output([str(td/'o')]).decode()
digest=hashlib.sha256((body+helpers+fillmacro+structs+arrays+regs+enums).encode()).digest();out='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original B source power SHA256 '+digest.hex()+'\n'+out;recipe='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\npub(super) const RECIPE:[u8;32]=['+','.join(map(str,digest))+'];\n'
for name,v in [('golden.rs',out),('recipe.rs',recipe)]:
 v=subprocess.check_output(['rustfmt','--edition','2021','--emit','stdout'],input=v.encode()).decode()
 if a.check:
  if(d/name).read_text()!=v:raise SystemExit(name+' differs')
 else:(d/name).write_text(v)
