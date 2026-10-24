"""Execute original RTL8822C fresh DACK/TRX/channel/OTP and H2C functions.

The one-shot profile does not cache vectors for a later reset; the original
restore/backup-cache callbacks are inert. The DACK reference uses equal RF8f
seeds so Linux's path*i+i alias does not hide the separate Rust regression.
"""
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88')
HERE = Path(__file__).parent


def function(source, name):
    match = re.search(r'\b' + name + r'\s*\([^;{}]*\)\s*\{', source)
    start = source.rfind('\n', 0, match.start()) + 1
    if source[source.rfind('\n', 0, start-1)+1:start].strip() in ['void','static void']:
        start = source.rfind('\n', 0, start-1)+1
    brace = source.index('{', match.start())
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


chip = (BASE / 'rtw8822c.c').read_text()
mac = (BASE / 'mac.c').read_text()
fw = (BASE / 'fw.c').read_text()
names = ['rtw8822c_bb_reset', 'rtw8822c_dac_backup_reg', 'rtw8822c_dac_restore_reg',
         'rtw8822c_rf_minmax_cmp', '__rtw8822c_dac_iq_sort', 'rtw8822c_dac_iq_sort',
         'rtw8822c_dac_iq_offset', 'rtw8822c_get_path_write_addr', 'rtw8822c_get_path_read_addr',
         'rtw8822c_dac_iq_check', 'rtw8822c_dac_cal_iq_sample', 'rtw8822c_dac_cal_iq_search',
         'rtw8822c_dac_cal_rf_mode', 'rtw8822c_dac_bb_setting', 'rtw8822c_dac_cal_adc',
         'rtw8822c_dac_cal_step1', 'rtw8822c_dac_cal_step2', 'rtw8822c_dac_cal_step3',
         'rtw8822c_dac_cal_step4', 'rtw8822c_rf_dac_cal', 'rtw8822c_rstb_3wire',
         'rtw8822c_set_channel_rf', 'rtw8822c_toggle_igi', 'rtw8822c_set_channel_bb',
         'rtw8822c_set_channel', 'rtw8822c_config_cck_rx_path', 'rtw8822c_config_ofdm_rx_path',
         'rtw8822c_config_rx_path', 'rtw8822c_config_cck_tx_path', 'rtw8822c_config_ofdm_tx_path',
         'rtw8822c_config_tx_path', 'rtw8822c_config_trx_mode', 'rtw8822c_set_power_trim',
         'rtw8822c_power_trim', 'rtw8822c_thermal_trim', 'rtw8822c_pa_bias',
         'rtw8822c_set_write_tx_power_ref','rtw8822c_set_tx_power_diff']
body = function(mac, 'rtw_set_channel_mac') + '\n' + '\n'.join(function(chip, n) for n in names)
body += '\n'+function((BASE/'phy.c').read_text(),'rtw_phy_get_rrsr_mask')
body += '\n'+function((BASE/'phy.c').read_text(),'rtw_phy_dig_write')
body += '\n'+function((BASE/'phy.c').read_text(),'rtw_phy_set_edcca_th')
body += '\n'+function(chip,'rtw8822c_adaptivity_init')
body += '\n'+function(chip,'rtw8822c_adaptivity')
main=(BASE/'main.h').read_text();start=main.index('enum rtw_trx_desc_rate {');end=main.index('};',start)+2
body=main[start:end]+'\n'+body
fw_names = ['rtw_fw_send_general_info', 'rtw_fw_send_phydm_info', 'rtw_fw_do_iqk']
body += '\n' + '\n'.join(function(fw, n) for n in fw_names)
definitions = {}
for source in [(BASE / h).read_text() for h in ['reg.h', 'main.h', 'mac.h', 'phy.h', 'rtw8822c.h', 'efuse.h', 'fw.h']] + [chip]:
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if line.startswith('#define'):
            name = line.split()[1].split('(')[0]
            definition = line
            while definition.endswith('\\'):
                definition += '\n' + lines[index]
                index += 1
            definitions[name] = definition
needed = set(re.findall(r'\b[A-Z][A-Z0-9_]+\b', body))
# H2C's inline header builder is copied verbatim separately.
fw_header = (BASE / 'fw.h').read_text()
body = function(fw_header, 'rtw_h2c_pkt_set_header') + '\n' + body
needed |= set(re.findall(r'\b[A-Z][A-Z0-9_]+\b', body))
needed.add('RRSR_INIT_2G')
needed.add('REG_RRSR')
while True:
    more = set()
    for name in needed:
        more.update(re.findall(r'\b[A-Z][A-Z0-9_]+\b', definitions.get(name, '')))
    if more <= needed:
        break
    needed |= more
pre = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int8_t s8;
typedef uint32_t __le32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define WARN_ON(v) ((v)?(abort(),1):0)
#define WARN(...) abort()
#define rtw_dbg(...)
#define rtw_err(...) abort()
#define EXPORT_SYMBOL(...)
#define swap(a,b) do{u32 t=(a);(a)=(b);(b)=t;}while(0)
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define RTW_EDCCA_NORMAL 0
#define EDCCA_TH_L2H_IDX 0
#define EDCCA_TH_H2L_IDX 1
#define RF_PATH_A 0
#define RF_PATH_B 1
#define BB_PATH_A 1
#define BB_PATH_B 2
#define BB_PATH_AB 3
#define RTW_CHANNEL_WIDTH_20 0
#define RTW_CHANNEL_WIDTH_40 1
#define RTW_CHANNEL_WIDTH_80 2
#define RTW_CHANNEL_WIDTH_5 3
#define RTW_CHANNEL_WIDTH_10 4
#define RF_1T1R 0
#define RF_2T2R 1
#define FW_RF_1T1R 4
#define FW_RF_2T2R 2
#define RTW_SC_20_UPPER 1
#define RTW_SC_20_UPMOST 3
#define RTW_SC_40_UPPER 9
#define RTW_SC_40_LOWER 10
enum rtw_bb_path{unused_path};
struct rtw_dev;
struct rtw_backup_info{u32 reg,val;u8 len;};
struct rtw_dm_info{u32 dack_adck[2];u8 igi_history[4],edcca_mode;s8 l2h_th_ini;};
struct rtw_hw_reg{u32 addr,mask;};
struct rtw_hw_reg_offset{struct rtw_hw_reg hw_reg;s8 offset;};
struct rtw_chip_info{const struct rtw_hw_reg*dig,*dig_cck;const struct rtw_hw_reg_offset*edcca_th;};
struct rtw_fifo_conf{u16 rsvd_fw_txbuf_addr,rsvd_boundary;};
struct rtw_iqk_para{bool clear,segment_iqk;};
struct rtw_hal{u8 rf_path_num,rf_type,cut_version,antenna_tx,antenna_rx;};
struct rtw_efuse{u8 rfe_option;};
struct rtw_dev{struct rtw_dm_info dm_info;struct rtw_hal hal;struct rtw_efuse efuse;struct rtw_fifo_conf fifo;const struct rtw_chip_info*chip;};
static u8 regs[0x5000];static int recording=1;
static void trace(int op,int width,u32 reg,u32 value){if(recording)printf("(%d,%d,0x%x,0x%x),\n",op,width,reg,value);}
static u8 rtw_read8(struct rtw_dev*d,u32 r){return regs[r];}
static u16 rtw_read16(struct rtw_dev*d,u32 r){u16 v;memcpy(&v,regs+r,2);return v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){u32 v;memcpy(&v,regs+r,4);if(r==0x2dbc){u32 a,b;memcpy(&a,regs+0x1868,4);memcpy(&b,regs+0x4168,4);return a==0x4010||b==0x4010?0x10010:0;}if(r==0x2808||r==0x2834||r==0x4508||r==0x4534)return 0x7fff80;if(r==0x2824||r==0x2850||r==0x4524||r==0x4550)return 128U<<19;return v;}
static u32 rtw_read32_mask(struct rtw_dev*d,u32 r,u32 m){return FIELD_GET(m,rtw_read32(d,r));}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){trace(1,8,r,v);regs[r]=v;}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){trace(1,16,r,v);memcpy(regs+r,&v,2);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){trace(1,32,r,v);memcpy(regs+r,&v,4);}
static void rtw_write32_mask(struct rtw_dev*d,u32 r,u32 m,u32 v){rtw_write32(d,r,(rtw_read32(d,r)&~m)|FIELD_PREP(m,v));}
static void rtw_write32_set(struct rtw_dev*d,u32 r,u32 m){rtw_write32(d,r,rtw_read32(d,r)|m);}
static void rtw_write32_clr(struct rtw_dev*d,u32 r,u32 m){rtw_write32(d,r,rtw_read32(d,r)&~m);}
static void rtw_write16_set(struct rtw_dev*d,u32 r,u16 m){rtw_write16(d,r,rtw_read16(d,r)|m);}
static void rtw_write16_clr(struct rtw_dev*d,u32 r,u16 m){rtw_write16(d,r,rtw_read16(d,r)&~m);}
static void rtw_write8_clr(struct rtw_dev*d,u32 r,u8 m){rtw_write8(d,r,rtw_read8(d,r)&~m);}
static void mdelay(unsigned n){trace(8,0,0,n*1000);}
static void udelay(unsigned n){trace(8,0,0,n);}
static u32 rtw_read_rf(struct rtw_dev*d,u8 p,u32 r,u32 m){return FIELD_GET(m,rtw_read32(d,(p?0x4c00:0x3c00)+r*4));}
static void rtw_write_rf(struct rtw_dev*d,u8 p,u32 r,u32 m,u32 v){if(r){rtw_write32_mask(d,(p?0x4c00:0x3c00)+r*4,m,v);udelay(1);}else{u32 old=rtw_read_rf(d,p,r,0xfffff);v=(old&~m)|FIELD_PREP(m,v);rtw_write32(d,p?0x4108:0x1808,v);udelay(13);}}
static bool check_hw_ready(struct rtw_dev*d,u32 r,u32 m,u32 v){return rtw_read32_mask(d,r,m)==v;}
static bool rtw8822c_dac_cal_restore(struct rtw_dev*d){return false;}
static void rtw8822c_dac_cal_backup(struct rtw_dev*d){}
static void rtw_restore_reg(struct rtw_dev*d,struct rtw_backup_info*b,u32 n){for(int i=0;i<n;i++)rtw_write32(d,b[i].reg,b[i].val);}
static bool rtw_chip_wcpu_8051(struct rtw_dev*d){return false;}
static void le32p_replace_bits(__le32*p,u32 v,u32 m){*p=(*p&~m)|FIELD_PREP(m,v);}
static void rtw_fw_send_h2c_packet(struct rtw_dev*d,u8*p){static u16 sequence=0;p[6]=sequence;p[7]=sequence>>8;sequence++;for(int i=0;i<32;i++)printf("%02x",p[i]);puts("");}
static const u16 cells[19]={0x1ef,0x1b0,0x1d4,0x1ee,0x1d2,0x1ec,0x1e8,0x1e4,0x1e0,0x1dc,0x1eb,0x1e7,0x1e3,0x1df,0x1db,0x1d6,0x1d5,0x1d8,0x1d7};
static void rtw_read8_physical_efuse(struct rtw_dev*d,u16 r,u8*v){for(int i=0;i<19;i++)if(cells[i]==r){*v=(u8)(0x21+i*7);return;}abort();}
'''
post=r'''
int main(){struct rtw_dev d={.hal={.rf_path_num=2,.rf_type=RF_2T2R,.cut_version=3,.antenna_tx=1,.antenna_rx=3},.efuse={.rfe_option=5},.fifo={.rsvd_fw_txbuf_addr=1994,.rsvd_boundary=1938}};
for(int i=0;i<sizeof(regs);i++)regs[i]=(u8)(i*17+3);u32 v=0x15678;memcpy(regs+0x3e3c,&v,4);memcpy(regs+0x4e3c,&v,4);puts("DACK");rtw8822c_rf_dac_cal(&d);puts("END");
for(int i=0;i<sizeof(regs);i++)regs[i]=(u8)(i*17+3);puts("RADIO");rtw8822c_config_trx_mode(&d,1,3,false);rtw8822c_set_channel(&d,1,0,0);rtw8822c_thermal_trim(&d);rtw8822c_power_trim(&d);rtw8822c_pa_bias(&d);puts("END");
puts("H2C");rtw_fw_send_general_info(&d);rtw_fw_send_phydm_info(&d);struct rtw_iqk_para iqk={.clear=true};rtw_fw_do_iqk(&d,&iqk);puts("END");return 0;}
'''
post=post.replace('return 0;}','for(int i=0;i<sizeof(regs);i++)regs[i]=(u8)(i*17+3);puts("GAIN");u8 cck[]={36,32},ofdm[]={0,0};s8 diff[]={0,0,0,0};rtw8822c_set_write_tx_power_ref(&d,cck,ofdm);for(int rate=0;rate<12;rate+=4)rtw8822c_set_tx_power_diff(&d,rate,diff);rtw_write32(&d,REG_RRSR,RRSR_INIT_2G & rtw_phy_get_rrsr_mask(&d,DESC_RATE1M));puts("END");return 0;}')
post=post.replace('return 0;}','for(int i=0;i<sizeof(regs);i++)regs[i]=(u8)(i*17+3);puts("EDCCA");const struct rtw_hw_reg dig[]={{0x1d70,0x7f},{0x1d70,0x7f00}};const struct rtw_hw_reg_offset th[]={{{0x84c,0xff0000},0x80},{{0x84c,0xff000000},0x80}};const struct rtw_chip_info chip={.dig=dig,.edcca_th=th};d.chip=&chip;d.dm_info.igi_history[0]=0x1c;d.dm_info.edcca_mode=1;d.dm_info.l2h_th_ini=45;rtw_phy_dig_write(&d,0x1c);rtw8822c_adaptivity(&d);rtw_write32_clr(&d,REG_TX_PTCL_CTRL,BIT_DIS_EDCCA);rtw_write32_set(&d,REG_RD_CTRL,BIT_EDCCA_MSK_CNTDOWN_EN);rtw_write32_clr(&d,REG_EDCCA_DECISION,BIT_EDCCA_OPTION);puts("END");return 0;}')
with tempfile.TemporaryDirectory() as temp:
    source,exe=Path(temp)/'radio.c',Path(temp)/'radio'
    source.write_text(pre+'\n'+'\n'.join(definitions[n] for n in sorted(needed) if n in definitions)+'\n'+body+post)
    subprocess.run(['cc','-w','-O2','-o',str(exe),str(source)],check=True)
    output=subprocess.check_output([str(exe)]).decode()
golden='// Original Linux fresh DACK and TRX/channel/OTP callbacks; writes and delays.\n'
for name in ['DACK','RADIO','GAIN','EDCCA']:
    trace=re.search(name+r'\n(.*?)END\n',output,re.S)[1]
    golden+=f'const LINUX_{name}: &[(u8,u8,u16,u32)] = &[\n{trace}];\n'
packets=re.search(r'H2C\n(.*?)END\n',output,re.S)[1].splitlines()
golden+='const LINUX_H2C: [[u8;32];3] = [\n'
for packet in packets:
    golden+='['+','.join(str(v) for v in bytes.fromhex(packet))+'],\n'
golden+='];\n'
(HERE/'golden.rs').write_text(golden)
subprocess.run(['rustfmt','--edition','2021',str(HERE/'golden.rs')],check=True)
