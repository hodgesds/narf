"""Execute original RTL8188EE EFUSE/PG gain selection; no Rust arithmetic."""
from pathlib import Path
import re, subprocess, tempfile
base=Path('/usr/src/linux/drivers/net/wireless/realtek/rtlwifi/rtl8188ee')
def function(file,name):
 s=(base/file).read_text()
 for match in re.finditer(r'(?:static )?(?:bool|void|u8|u32)\s+'+name+r'\s*\(',s):
  start=s.index('{',match.end())
  if ';' in s[match.end():start]: continue
  end=start+1;depth=1
  while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
  return s[match.start():end]
 raise ValueError(name)
pre=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define MAX_RF_PATH 4
#define MAX_CHNL_GROUP_24G 6
#define MAX_CHNL_GROUP_5G 14
#define MAX_TX_COUNT 4
#define RF6052_MAX_TX_PWR 63
#define HT_CHANNEL_WIDTH_20 0
#define HT_CHANNEL_WIDTH_20_40 1
#define RF90_PATH_A 0
#define RF90_PATH_B 1
#define RF_1T1R 1
#define TXHIGHPWRLEVEL_BT1 1
#define TXHIGHPWRLEVEL_BT2 2
#define rtl_dbg(...) ((void)0)
#define RTPRINT(...) ((void)0)
struct txpower_info_2g {u8 index_cck_base[4][6],index_bw40_base[4][6],cck_diff[4][4],ofdm_diff[4][4],bw20_diff[4][4],bw40_diff[4][4];};
struct txpower_info_5g {u8 index_bw40_base[4][14],ofdm_diff[4][4],bw20_diff[4][4],bw40_diff[4][4];};
struct rtl_phy{u32 mcs_txpwrlevel_origoffset[16][16];int pwrgroup_cnt,current_chan_bw;};
struct rtl_efuse{u8 eeprom_regulatory,txpwrlevel_cck[2][14],txpwrlevel_ht40_1s[2][14],txpwr_ht20diff[2][14],txpwr_legacyhtdiff[2][14],pwrgroup_ht20[2][14],pwrgroup_ht40[2][14];};
struct rtl_mac{bool act_scanning;};struct dm{int dynamic_txhighpower_lvl;};
struct rtl_priv{struct rtl_phy phy;struct rtl_efuse efuse;struct rtl_mac mac;struct dm dm;};
struct ieee80211_hw{int unused;};static struct rtl_priv priv;static u32 regs[0x1000/4];
#define rtl_priv(h) (&priv)
#define rtl_efuse(p) (&priv.efuse)
#define rtl_mac(p) (&priv.mac)
#define get_rf_type(p) RF_1T1R
static void rtl_set_bbreg(struct ieee80211_hw*h,u32 a,u32 m,u32 v){unsigned s=__builtin_ctz(m);regs[a/4]=(regs[a/4]&~m)|(v<<s);}
static void rtl88e_dm_txpower_track_adjust(struct ieee80211_hw*h,int a,u8*d,u32*v){*d=0;*v=0;}
'''
names=[('hw.c','_rtl88e_get_chnl_group'),('hw.c','set_24g_base'),('hw.c','read_power_value_fromprom'),
 ('phy.c','store_pwrindex_rate_offset'),('phy.c','handle_path_a'),('rf.c','rtl88e_phy_rf6052_set_cck_txpower'),
 ('rf.c','rtl88e_phy_get_power_base'),('rf.c','_rtl88e_get_txpower_writeval_by_regulatory'),
 ('rf.c','_rtl88e_write_ofdm_power_reg'),('rf.c','rtl88e_phy_rf6052_set_ofdm_txpower')]
main=r'''
int main(){struct ieee80211_hw h;
for(unsigned channel=1;channel<=11;channel+=5)for(unsigned mode=0;mode<=3;++mode)for(unsigned nibble=0;nibble<16;++nibble){
 memset(&priv,0,sizeof(priv));memset(regs,0,sizeof(regs));u8 map[512]={0};memset(map+0x10,30,6);memset(map+0x16,20,5);map[0x1b]=0x20|nibble;
 struct txpower_info_2g p2={0};struct txpower_info_5g p5={0};read_power_value_fromprom(&h,&p2,&p5,false,map);
 for(unsigned ch=0;ch<14;++ch){unsigned g=_rtl88e_get_chnl_group(ch+1);priv.efuse.txpwrlevel_cck[0][ch]=p2.index_cck_base[0][g];priv.efuse.txpwrlevel_ht40_1s[0][ch]=p2.index_bw40_base[0][g];priv.efuse.txpwr_ht20diff[0][ch]=p2.bw20_diff[0][0];priv.efuse.txpwr_legacyhtdiff[0][ch]=p2.ofdm_diff[0][0];}
 for(unsigned i=0;i<sizeof(RTL8188EEPHY_REG_ARRAY_PG)/4;i+=3)store_pwrindex_rate_offset(&h,RTL8188EEPHY_REG_ARRAY_PG[i],RTL8188EEPHY_REG_ARRAY_PG[i+1],RTL8188EEPHY_REG_ARRAY_PG[i+2]);
 priv.efuse.eeprom_regulatory=mode;u8 cck[4]={0},ofdm[4]={0},bw20[4]={0},bw40[4]={0};handle_path_a(&priv.efuse,channel-1,cck,ofdm,bw20,bw40);
 rtl88e_phy_rf6052_set_cck_txpower(&h,cck);rtl88e_phy_rf6052_set_ofdm_txpower(&h,ofdm,bw20,bw40,channel);
 printf("(%u,%u,%u,[%u,%u,%u,%u],[",channel,mode,nibble,(regs[0xe08/4]>>8)&255,(regs[0x86c/4]>>8)&255,(regs[0x86c/4]>>16)&255,(regs[0x86c/4]>>24)&255);
 for(unsigned i=0;i<8;++i)printf("%s%u",i?",":"",(regs[(i<4?0xe00:0xe04)/4]>>((i%4)*8))&255);puts("]),");
}}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp);c=p/'oracle.c';exe=p/'oracle'
 c.write_text(pre+'\n#include "'+str(base/'reg.h')+'"\n#include "'+str(base/'table.c')+'"\n'+'\n'.join(function(*item) for item in names)+main)
 subprocess.run(['cc','-O2','-o',str(exe),str(c)],check=True)
 output=subprocess.check_output([str(exe)]).decode()
Path(__file__).with_name('power_golden.rs').write_text('// Executed original Linux hw.c/phy.c/rf.c EFUSE/PG gain arithmetic.\ntype LinuxPowerCase=(u8,u8,u8,[u8;4],[u8;8]);\nconst LINUX_POWER:&[LinuxPowerCase]=&[\n'+output+'];\n')
