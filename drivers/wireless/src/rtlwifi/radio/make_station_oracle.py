"""Execute original Linux EE mailbox, active-mode and reserved-page functions.

Only allocation/register primitives are inert. Expected byte lanes and page
patches come from the original C functions/macros, never Rust constructors.
"""
from pathlib import Path
import hashlib
import re
import subprocess
import tempfile

base = Path('/usr/src/linux/drivers/net/wireless/realtek/rtlwifi')
source = (base/'rtl8188ee/fw.c').read_text()
header = (base/'rtl8188ee/fw.h').read_text()
base_h = (base/'base.h').read_text()
def function(text, name):
    match = re.search(r'(?:static (?:inline )?)?(?:void|bool|u8)\s+'+name+r'\s*\(', text)
    start = text.index('{',match.end())
    end, depth = start+1, 1
    while depth:
        depth += (text[end]=='{')-(text[end]=='}')
        end += 1
    return text[match.start():end]
def define(text, name):
    lines=text.splitlines()
    for i,line in enumerate(lines):
        if re.match(r'#define\s+'+name+r'(?:\(|\s)',line):
            output=[line]
            while output[-1].endswith('\\'):
                i+=1;output.append(lines[i])
            return '\n'.join(output)
    raise ValueError(name)
pre=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define u8p_replace_bits(p,v,m) (*(p)=(*(p)&~(m))|(((v)<<__builtin_ctz(m))&(m)))
#define rtl_dbg(...) ((void)0)
#define pr_err(...) ((void)0)
#define WARN_ONCE(...) ((void)0)
#define RT_PRINT_DATA(...) ((void)0)
#define spin_lock_irqsave(l,f) ((f)=0)
#define spin_unlock_irqrestore(l,f) ((void)0)
#define CP_MACADDR(d,s) memcpy((d),(s),6)
#define ether_addr_copy(d,s) memcpy((d),(s),6)
#define FW_PS_ACTIVE_MODE 0
#define USE_OLD_WOWLAN_DEBUG_FW 0
struct ieee80211_hw {int unused;};
struct rtl_hal {bool fw_ready,h2c_setinprogress;u8 last_hmeboxnum;};
struct rtl_ps_ctl {u8 smart_ps,reg_max_lps_awakeintvl;};
struct rtl_mac {u8 mac_addr[6],bssid[6];u16 assoc_id;bool p2p;};
struct rtl_priv {struct rtl_hal hal;struct rtl_ps_ctl psc;struct rtl_mac mac80211;struct {int h2c_lock;} locks;};
static struct rtl_priv priv;
#define rtl_priv(hw) (&priv)
#define rtl_hal(p) (&(p)->hal)
#define rtl_psc(p) (&(p)->psc)
#define rtl_mac(p) (&(p)->mac80211)
static void udelay(u32 n){}
static void rtl_write_byte(struct rtl_priv *p,u16 a,u8 v){printf("(8,0x%x,0x%x),\n",a,v);}
static u8 rtl_read_byte(struct rtl_priv *p,u16 a){return 0;}
struct sk_buff {u8 *data;u32 len;};
static struct sk_buff *dev_alloc_skb(u32 n){struct sk_buff *s=malloc(sizeof(*s));s->data=malloc(n);s->len=0;return s;}
static void skb_put_data(struct sk_buff *s,const void *p,u32 n){memcpy(s->data,p,n);s->len=n;}
static u8 captured[768];
static bool rtl_cmd_send_packet(struct ieee80211_hw *h,struct sk_buff *s){if(s->len!=768)abort();memcpy(captured,s->data,768);return true;}
'''
enum=header[header.index('enum rtl8188e_h2c_cmd'):].split('};',1)[0]+'};\n'
defs='\n'.join(define(header,n) for n in ['H2C_88E_PWEMODE_LENGTH','FW_PS_RF_ON','FW_PS_REGISTER_ACTIVE','FW_PWR_STATE_ACTIVE','FW_PWR_STATE_RF_OFF',
 'SET_H2CCMD_JOINBSSRPT_PARM_OPMODE','SET_H2CCMD_RSVDPAGE_LOC_PROBE_RSP','SET_H2CCMD_RSVDPAGE_LOC_PSPOLL','SET_H2CCMD_RSVDPAGE_LOC_NULL_DATA'])
defs+='\n'+'\n'.join(define(base_h,n) for n in ['FRAME_OFFSET_ADDRESS1','FRAME_OFFSET_ADDRESS2','FRAME_OFFSET_ADDRESS3',
 'SET_80211_PS_POLL_AID','SET_80211_PS_POLL_BSSID','SET_80211_PS_POLL_TA','SET_80211_HDR_ADDRESS1','SET_80211_HDR_ADDRESS2','SET_80211_HDR_ADDRESS3'])
defs+='\n'+'\n'.join(define(source,n) for n in ['BEACON_PG','PSPOLL_PG','NULL_PG','PROBERSP_PG','TOTAL_RESERVED_PKT_LEN'])
inlines='\n'.join(function(header,n) for n in ['set_h2ccmd_pwrmode_parm_mode','set_h2ccmd_pwrmode_parm_rlbm','set_h2ccmd_pwrmode_parm_smart_ps',
 'set_h2ccmd_pwrmode_parm_awake_interval','set_h2ccmd_pwrmode_parm_all_queue_uapsd','set_h2ccmd_pwrmode_parm_pwr_state'])
template=source[source.index('static u8 reserved_page_packet'):].split('};',1)[0]+'};\n'
functions='\n'.join(function(source,n) for n in ['_rtl88e_check_fw_read_last_h2c','_rtl88e_fill_h2c_command','rtl88e_fill_h2c_cmd',
 'rtl88e_set_fw_pwrmode_cmd','rtl88e_set_fw_joinbss_report_cmd','rtl88e_set_fw_rsvdpagepkt'])
main=r'''
int main(void){struct ieee80211_hw h;
puts("pub(super) const TEMPLATE: [u8;768]=[");
for(unsigned i=0;i<768;i++)printf("0x%x,",reserved_page_packet[i]);puts("];\n/*GOLDEN*/");
priv.hal.fw_ready=true;priv.psc.reg_max_lps_awakeintvl=5;
memcpy(priv.mac80211.mac_addr,(u8[]){2,7,8,9,10,11},6);
memcpy(priv.mac80211.bssid,(u8[]){2,1,2,3,4,5},6);priv.mac80211.assoc_id=42;
puts("const LINUX_MAILBOX:&[(u8,u16,u32)]=&[");
rtl88e_set_fw_pwrmode_cmd(&h,FW_PS_ACTIVE_MODE);
rtl88e_fill_h2c_cmd(&h,H2C_88E_KEEP_ALIVE_CTRL,2,(u8[]){0xff,10});
rtl88e_set_fw_rsvdpagepkt(&h,false);rtl88e_set_fw_joinbss_report_cmd(&h,1);rtl88e_set_fw_joinbss_report_cmd(&h,0);
puts("];\nconst LINUX_RESERVED_BODY:[u8;768]=[");
for(unsigned i=0;i<768;i++)printf("0x%x,",captured[i]);puts("];");return 0;}
'''
with tempfile.TemporaryDirectory() as tmp:
    p=Path(tmp)
    (p/'oracle.c').write_text(pre+'\n#include "'+str(base/'rtl8188ee/reg.h')+'"\n'+enum+defs+'\n'+inlines+'\n'+template+functions+main)
    subprocess.run(['cc','-O2','-Wno-cpp','-o',str(p/'oracle'),str(p/'oracle.c')],check=True)
    result=subprocess.check_output([str(p/'oracle')]).decode()
production, golden = result.split('/*GOLDEN*/\n', 1)
Path(__file__).with_name('reserved_template.rs').write_text('// SPDX-License-Identifier: GPL-2.0\n// Original Linux rtl8188ee/fw.c sha256: '+hashlib.sha256(source.encode()).hexdigest()+'\n'+production)
Path(__file__).with_name('station_golden.rs').write_text('// Original Linux EE fw.c/fw.h/base.h sha256: '+hashlib.sha256((source+header+base_h).encode()).hexdigest()+'\n'+golden)
