"""Execute original Linux 8188EE table/calibration functions over a register model.

No Rust encoder or copied expected table generates these receipts. The small
main composes the same parked-radio boundary; hw_init's active DMA/MAC/ASPM,
CAM, board PA-bias and station operations remain outside this prerequisite.
"""
from pathlib import Path
import hashlib
import subprocess
import tempfile

base = Path('/usr/src/linux/drivers/net/wireless/realtek/rtlwifi/rtl8188ee')
source = (base / 'phy.c').read_text()
def function(name):
    import re
    matches = list(re.finditer(r'(?:static )?(?:bool|void|u8|u32)\s+' + name + r'\s*\(', source))
    for match in matches:
        start = source.index('{', match.end())
        if ';' in source[match.end():start]:
            continue
        end, depth = start + 1, 1
        while depth:
            depth += (source[end] == '{') - (source[end] == '}')
            end += 1
        return source[match.start():end]
    raise ValueError(name)

names = ['_rtl88e_phy_rf_serial_read','_rtl88e_phy_rf_serial_write',
    '_rtl8188e_config_rf_reg','_rtl8188e_config_rf_radio_a','_rtl8188e_config_bb_reg',
    '_rtl88e_phy_path_a_iqk','_rtl88e_phy_path_b_iqk','_rtl88e_phy_path_a_rx_iqk',
    '_rtl88e_phy_path_a_fill_iqk_matrix','_rtl88e_phy_save_adda_registers',
    '_rtl88e_phy_save_mac_registers','_rtl88e_phy_reload_adda_registers',
    '_rtl88e_phy_reload_mac_registers','_rtl88e_phy_path_adda_on',
    '_rtl88e_phy_mac_setting_calibration','_rtl88e_phy_path_a_standby',
    '_rtl88e_phy_pi_mode_switch','_rtl88e_phy_simularity_compare',
    '_rtl88e_phy_iq_calibrate','_rtl88e_phy_lc_calibrate','rtl88e_phy_iq_calibrate']
pre = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define MASKDWORD 0xffffffff
#define MASK12BITS 0xfff
#define RFREG_OFFSET_MASK 0xfffff
#define IQK_DELAY_TIME 10
#define IQK_ADDA_REG_NUM 16
#define IQK_MAC_REG_NUM 4
#define IQK_BB_REG_NUM 9
#define IQK_MATRIX_REG_NUM 8
#define MAX_TOLERANCE 5
#define RT_CANNOT_IO(hw) false
#define IS_92C_SERIAL(v) false
#define RF_2T2R 2
#define RF90_PATH_A 0
#define RF90_PATH_B 1
#define rtl_dbg(...) ((void)0)
#define pr_err(...) ((void)0)
enum radio_path { unused_path };
struct bb_reg_def { u32 rfhssi_para2,rf_rbpi,rf_rb,rf3wire_offset; };
struct rtl_phy { struct bb_reg_def phyreg_def[2]; u32 adda_backup[16],iqk_mac_backup[4],iqk_bb_backup[9];
  u8 rfpi_enable; long reg_eb4,reg_ebc,reg_e94,reg_e9c;
  struct { long value[1][8]; bool iqk_done; } iqk_matrix[1]; };
struct rtl_priv { struct rtl_phy phy; }; struct rtl_hal { int version; };
struct ieee80211_hw { int unused; }; static struct rtl_priv priv;
static struct rtl_hal hal;
#define rtl_priv(hw) (&priv)
#define rtl_hal(p) (&hal)
#define get_rf_type(p) 1
static u32 regs[0x1000/4], radio[256]; static unsigned shots;
static void emit(unsigned width,u32 a,u32 v){printf("(%u,0x%x,0x%x),\n",width,a,v);}
static u32 rtl_read_dword(struct rtl_priv*p,u32 a){return regs[a/4];}
static u8 rtl_read_byte(struct rtl_priv*p,u32 a){return (regs[a/4]>>((a%4)*8))&255;}
static void rtl_write_dword(struct rtl_priv*p,u32 a,u32 v){
 emit(32,a,v);regs[a/4]=v;
 if(a==0x840)radio[(v>>20)&255]=v&0xfffff;
 if(a==0x824&&(v&BIT(31))){regs[0x8a0/4]=regs[0x8b8/4]=radio[(v>>23)&255];}
 if(a==0xe48&&v==0xf8000000){++shots;regs[0xe94/4]=0x1050000;regs[0xe9c/4]=0x3fa0000;
    regs[0xea4/4]=shots%3==0?0x1010000:0;regs[0xeac/4]=shots%3==0?0x3f90000:0;}
}
static void rtl_write_byte(struct rtl_priv*p,u32 a,u8 v){emit(8,a,v);unsigned s=(a%4)*8;regs[a/4]=(regs[a/4]&~(255U<<s))|((u32)v<<s);}
static unsigned shift(u32 mask){return __builtin_ctz(mask);}
static u32 rtl_get_bbreg(struct ieee80211_hw*h,u32 a,u32 mask){return (rtl_read_dword(&priv,a)&mask)>>shift(mask);}
static void rtl_set_bbreg(struct ieee80211_hw*h,u32 a,u32 mask,u32 v){rtl_write_dword(&priv,a,mask==MASKDWORD?v:(regs[a/4]&~mask)|(v<<shift(mask)));}
static u32 _rtl88e_phy_rf_serial_read(struct ieee80211_hw*,enum radio_path,u32);
static void _rtl88e_phy_rf_serial_write(struct ieee80211_hw*,enum radio_path,u32,u32);
static u32 rtl_get_rfreg(struct ieee80211_hw*h,enum radio_path p,u32 a,u32 m){return (_rtl88e_phy_rf_serial_read(h,p,a)&m)>>shift(m);}
static void rtl_set_rfreg(struct ieee80211_hw*h,enum radio_path p,u32 a,u32 m,u32 v){
 if(m!=RFREG_OFFSET_MASK)v=(_rtl88e_phy_rf_serial_read(h,p,a)&~m)|(v<<shift(m));
 _rtl88e_phy_rf_serial_write(h,p,a,v);
}
static void udelay(u32 us){emit(0,0,us);if(us>=50000)radio[0x18]&=~BIT(15);}
static void mdelay(u32 ms){udelay(ms*1000);}
'''
main = r'''
int main(void){struct ieee80211_hw h;priv.phy.phyreg_def[0]=(struct bb_reg_def){0x824,0x8b8,0x8a0,0x840};
 regs[0x300/4]=0xff00;
 for(unsigned i=0;i<sizeof(RTL8188EEMAC_1T_ARRAY)/4;i+=2)rtl_write_byte(&priv,RTL8188EEMAC_1T_ARRAY[i],RTL8188EEMAC_1T_ARRAY[i+1]);
 rtl_write_byte(&priv,0x4ca,0xb);rtl_write_dword(&priv,0x608,regs[0x608/4]&~0x300);
 rtl_write_byte(&priv,2,3);rtl_write_byte(&priv,3,0x20);rtl_write_byte(&priv,0x1f,7);rtl_write_byte(&priv,2,0x27);
 rtl_write_dword(&priv,0x4c,regs[0x4c/4]|BIT(23));
 for(unsigned i=0;i<sizeof(RTL8188EEPHY_REG_1TARRAY)/4;i+=2)_rtl8188e_config_bb_reg(&h,RTL8188EEPHY_REG_1TARRAY[i],RTL8188EEPHY_REG_1TARRAY[i+1]);
 for(unsigned i=0;i<sizeof(RTL8188EEAGCTAB_1TARRAY)/4;i+=2){rtl_set_bbreg(&h,RTL8188EEAGCTAB_1TARRAY[i],MASKDWORD,RTL8188EEAGCTAB_1TARRAY[i+1]);udelay(1);}
 rtl_set_bbreg(&h,0x800,BIT(24),1);rtl_set_bbreg(&h,0x800,BIT(25),1);
 u32 env=rtl_get_bbreg(&h,0x870,BIT(4));
 rtl_set_bbreg(&h,0x860,BIT(20),1);udelay(1);rtl_set_bbreg(&h,0x860,BIT(4),1);udelay(1);
 rtl_set_bbreg(&h,0x824,0x400,0);udelay(1);rtl_set_bbreg(&h,0x824,0x800,0);udelay(1);
 for(unsigned i=0;i<sizeof(RTL8188EE_RADIOA_1TARRAY)/4;i+=2)_rtl8188e_config_rf_radio_a(&h,RTL8188EE_RADIOA_1TARRAY[i],RTL8188EE_RADIOA_1TARRAY[i+1]);
 rtl_set_bbreg(&h,0x870,BIT(4),env);
 (void)rtl_get_rfreg(&h,0,0x18,RFREG_OFFSET_MASK);
 rtl88e_phy_iq_calibrate(&h,false);_rtl88e_phy_lc_calibrate(&h,false);
 return 0;}
'''
with tempfile.TemporaryDirectory() as tmp:
    path=Path(tmp); c=path/'oracle.c';exe=path/'oracle'
    c.write_text(pre+'\n#include "'+str(base/'reg.h')+'"\n#include "'+str(base/'table.c')+'"\n'+'\n'.join(function(n) for n in names)+main)
    subprocess.run(['cc','-O2','-Wno-cpp','-o',str(exe),str(c)],check=True)
    trace=subprocess.check_output([str(exe)]).decode()
digest=hashlib.sha256(source.encode()).hexdigest()
Path(__file__).with_name('golden.rs').write_text('// Original Linux phy.c sha256: '+digest+'\nconst LINUX_RADIO: &[(u8,u16,u32)]=&[\n'+trace+'];\n')
