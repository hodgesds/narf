"""Compile original RTL8822C station H2C functions, retaining first8 bytes.

No custom firmware is produced. These are fixed awake/CCK1, MACid0, port0
source function outputs for the independently modeled native mailbox owner.
"""
from pathlib import Path
import re
import subprocess
import tempfile

BASE=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88')
HERE=Path(__file__).parent

def function(source,name):
    match=re.search(r'\b'+name+r'\s*\([^;{}]*\)\s*\{',source)
    start=source.rfind('\n',0,match.start())+1
    previous=source[source.rfind('\n',0,start-1)+1:start].strip()
    if previous in ['void','static void']:
        start=source.rfind('\n',0,start-1)+1
    brace=source.index('{',match.start());end=brace+1;depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]

fw=(BASE/'fw.c').read_text()
body='\n'.join(function(fw,n) for n in ['rtw_fw_set_pwr_mode','rtw_fw_set_keep_alive_cmd','rtw_fw_set_disconnect_decision_cmd','rtw_fw_send_ra_info','rtw_fw_media_status_report','rtw_fw_default_port'])
body+='\n'+function((BASE/'mac80211.c').read_text(),'rtw_aifsn_to_aifs')
definitions={}
for name in ['fw.h','main.h']:
    lines=(BASE/name).read_text().splitlines();i=0
    while i<len(lines):
        line=lines[i];i+=1
        if not line.startswith('#define'):continue
        name=line.split()[1].split('(')[0]
        while line.endswith('\\'):line+='\n'+lines[i];i+=1
        definitions[name]=line
needed=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',body))
while True:
    more=set()
    for name in needed:more.update(re.findall(r'\b[A-Z][A-Z0-9_]+\b',definitions.get(name,'')))
    if more<=needed:break
    needed|=more
pre=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;typedef uint32_t __le32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define u32_encode_bits(v,m) (((v)<<__builtin_ctz(m))&(m))
#define RTW_CHIP_TYPE_8814A 1
#define RTW_NET_MGD_LINKED 2
#define KEEP_ALIVE_NULL_PKT 0
#define RTW_BAND_5G 1
#define test_bit(n,v) false
struct rtw_lps_conf{u8 mode,state,awake_interval,rlbm,smart_ps,port_id;};
struct rtw_sta_info{u8 mac_id,rate_id,init_ra_lv,bw_mode,ldpc_en,vht_enable;bool sgi_enable;u64 ra_mask;};
struct ieee80211_vif{struct{bool use_short_slot;}bss_conf;};
struct rtw_vif{u8 port,mac_id,net_type;struct ieee80211_vif vif;};
static struct ieee80211_vif*rtwvif_to_vif(struct rtw_vif*v){return &v->vif;}
struct rtw_wow_param{u32 flags[1];};
struct rtw_fw_wow_keep_alive_para{bool adopt;u8 pkt_type,period;};
struct rtw_fw_wow_disconnect_para{bool adopt;u8 period,retry_count;};
struct rtw_h2c_register{u32 w0,w1;};
struct rtw_dev{struct rtw_lps_conf lps_conf;struct rtw_wow_param wow;struct{u8 id;}*chip;struct{u8 current_band_type;}hal;};
static void le32p_replace_bits(__le32*p,u32 v,u32 m){*p=(*p&~m)|u32_encode_bits(v,m);}
static void rtw_fw_send_h2c_command(struct rtw_dev*d,u8*p){for(int i=0;i<8;i++)printf("%02x",p[i]);puts("");}
static void rtw_fw_send_h2c_command_register(struct rtw_dev*d,struct rtw_h2c_register*p){rtw_fw_send_h2c_command(d,(u8*)p);}
static void rtw_leave_lps(struct rtw_dev*d){}
'''
post=r'''
int main(){struct rtw_dev d={.lps_conf={.mode=0,.state=12,.awake_interval=1}};typeof(*d.chip) chip={0};d.chip=&chip;
rtw_fw_set_pwr_mode(&d);rtw_fw_set_keep_alive_cmd(&d,false);rtw_fw_set_disconnect_decision_cmd(&d,false);
struct rtw_sta_info si={.mac_id=0,.rate_id=8,.init_ra_lv=1,.ra_mask=1};rtw_fw_send_ra_info(&d,&si,true);
rtw_fw_media_status_report(&d,0,true);struct rtw_vif vif={.net_type=2};rtw_fw_default_port(&d,&vif);printf("SLOT %u\n",rtw_aifsn_to_aifs(&d,&vif,1)-rtw_aifsn_to_aifs(&d,&vif,0));return 0;}
'''
with tempfile.TemporaryDirectory() as temp:
    source,exe=Path(temp)/'control.c',Path(temp)/'control'
    source.write_text(pre+'\n'+'\n'.join(definitions[n] for n in sorted(needed) if n in definitions)+'\n'+body+post)
    subprocess.run(['cc','-O2','-o',str(exe),str(source)],check=True)
    output=subprocess.check_output([str(exe)]).decode().splitlines()
golden='// Original Linux awake/keepalive/RA/media/default-port H2C functions.\nconst LINUX_MAILBOX: [[u8;8];6] = [\n'
assert len(output)==7
for row in output[:6]:golden+='['+','.join(str(v) for v in bytes.fromhex(row))+'],\n'
golden+='];\n'
golden+='const LINUX_INITIAL_SLOT:u8='+output[6].split()[1]+';\n'
(HERE/'golden.rs').write_text(golden)
subprocess.run(['rustfmt','--edition','2021',str(HERE/'golden.rs')],check=True)
