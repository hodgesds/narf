"""Compile Linux AX-v0 station payload helpers and actual table-init writes.

Only inert skb/register/RCU adapters are substituted. This emits no firmware,
calibration or native readiness receipt. The fixed-rate additions use original
CCTL setters, not Rust-derived masks or generated Rust implementation code.
"""
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89')
HERE = Path(__file__).parent


def function(source, name):
    match = re.search(r'\b' + name + r'\s*\([^;{}]*\)\s*\{', source)
    start = source.rfind('\n', 0, match.start()) + 1
    previous = source[source.rfind('\n', 0, start - 1) + 1:start].strip()
    if previous in ['void', 'static void', 'static u8']:
        start = source.rfind('\n', 0, start - 1) + 1
    brace = source.index('{', match.start())
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


fw = (BASE / 'fw.c').read_text()
header = (BASE / 'fw.h').read_text()
cam = (BASE / 'cam.c').read_text()
cam_header = (BASE / 'cam.h').read_text()
mac = (BASE / 'mac.c').read_text()
mac80211 = (BASE / 'mac80211.c').read_text()
body = '\n'.join(function(cam, name) for name in [
    'rtw89_cam_addr_hash', 'rtw89_cam_fill_addr_cam_info',
    'rtw89_cam_fill_bssid_cam_info',
])
body += '\n' + '\n'.join(function(fw, name) for name in [
    '__rtw89_fw_h2c_set_tx_path', 'rtw89_fw_h2c_default_cmac_tbl',
    'rtw89_fw_h2c_assoc_cmac_tbl', 'rtw89_fw_h2c_set_edca',
])
body += '\n' + '\n'.join(function(mac80211, name) for name in [
    'rtw89_aifsn_to_aifs', '____rtw89_conf_tx_edca',
])
body += '\n' + '\n'.join(function(mac, name) for name in [
    'rtw89_mac_dmac_tbl_init', 'rtw89_mac_cmac_tbl_init',
])
setters = set(re.findall(r'\b(?:SET_CMC_TBL_|SET_CTRL_INFO_|RTW89_SET_EDCA_)[A-Z0-9_]+(?=\()', body))
setters.update(['SET_CMC_TBL_DATARATE', 'SET_CMC_TBL_DATA_BW',
                'SET_CMC_TBL_TRYRATE', 'SET_CMC_TBL_SECTYPE'])
body = '\n'.join(function(header, name) for name in sorted(setters)) + '\n' + body
role = re.search(r'h2c->w0 = .*?;', function(fw, 'rtw89_fw_h2c_role_maintain'), re.S).group()
join = re.search(r'h2c->w0 = .*?;', function(fw, 'rtw89_fw_h2c_join_info'), re.S).group()
body += '\nstatic void encode_role(struct rtw89_vif_link*rtwvif_link,u8 upd_mode){u8 mac_id=0,self_role=0;struct {u32 w0;}out={0},*h2c=&out;' + role + 'dump("role",&out,sizeof(out));}\n'
body += '\nstatic void encode_join(struct rtw89_vif_link*rtwvif_link,bool dis_conn){u8 mac_id=0,self_role=0,net_type=rtwvif_link->net_type;struct {u32 w0;}out={0},*h2c=&out;' + join + 'dump("join",&out,sizeof(out));}\n'

definitions = {}
for filename in ['fw.h', 'cam.h', 'core.h', 'mac.h', 'reg.h', 'fw.c']:
    lines = (BASE / filename).read_text().splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not re.match(r'^#define\s+', line):
            continue
        name = line.split()[1].split('(')[0]
        while line.endswith('\\'):
            line += '\n' + lines[index]
            index += 1
        definitions[name] = line
needed = set(re.findall(r'\b[A-Z][A-Z0-9_]+\b', body))
needed.add('R_AX_SS_MACID_PAUSE_0')
needed.update(['R_AX_LDM','B_AX_EN_32K','R_AX_PPWRBIT_SETTING'])
while True:
    more = set()
    for name in needed:
        more.update(re.findall(r'\b[A-Z][A-Z0-9_]+\b', definitions.get(name, '')))
    if more <= needed:
        break
    needed |= more
types = re.search(r'struct rtw89_h2c_addr_cam_v0 \{.*?\} __packed;', cam_header, re.S).group()
types += '\n' + re.search(r'struct rtw89_fw_macid_pause_grp \{.*?\} __packed;', header, re.S).group()
pre = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef u32 __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define le32_encode_bits(v,m) (((u32)(v)<<__builtin_ctz(m))&(m))
#define FIELD_PREP(m,v) le32_encode_bits(v,m)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define __ffs(x) __builtin_ctz(x)
#define ilog2(x) (31-__builtin_clz((unsigned)(x)))
#define RTW89_CHIP_AX 0
#define RTW89_NET_TYPE_AP_MODE 3
#define RTW89_NET_TYPE_INFRA 2
#define RTW89_BAND_2G 0
#define RTW89_CHANNEL_WIDTH_20 0
#define RTW89_CHANNEL_WIDTH_40 1
#define RTW89_CHANNEL_WIDTH_80 2
#define RTW89_CHANNEL_WIDTH_160 3
#define RTW89_CHANNEL_WIDTH_320 4
#define ETH_ALEN 6
#define RTW89_HW_RATE_CCK1 0
#define RTW89_HW_RATE_OFDM6 4
#define H2C_FUNC_USR_EDCA 15
#define NL80211_IFTYPE_STATION 0
#define RF_A 1
#define RF_AB 3
#define RTW89_SMA 1
#define RTW89_TMA 2
#define RTW89_DBG_FW 0
#define FWCMD_TYPE_H2C 0
#define ENOMEM 12
#define EXPORT_SYMBOL(x)
struct ieee80211_tx_queue_params{u16 cw_max,cw_min,txop;u8 aifs;};
struct ieee80211_bss_conf{bool use_short_slot,nontransmitted;struct{u8 color;}he_bss_color;};
struct ieee80211_vif{u8 type;bool p2p;struct{u16 aid;}cfg;};
struct ieee80211_sta{u16 aid;};
struct ieee80211_link_sta{u8 addr[6];struct{bool has_he;}he_cap;};
struct rtw89_addr_cam_entry{u8 addr_cam_idx,offset,len,bssid_cam_idx,addr_mask,mask_sel,sec_ent_mode;bool valid,wapi;u8 sec_ent_keyid[7],sec_ent[7];u32 sec_cam_map[1];};
struct rtw89_bssid_cam_entry{u8 bssid_cam_idx,offset,len,phy_idx,bssid[6];bool valid;};
struct rtw89_vif_link{u8 mac_id,self_role,wifi_role,mac_idx,port,net_type,wmm,trigger,phy_idx,bcn_hit_cond,hit_rule,lsig_txop,tgt_ind,frm_tgt_ind,chanctx_idx;bool wowlan_pattern,wowlan_uc,wowlan_magic;u8 mac_addr[6],bssid[6];struct ieee80211_vif vif;struct ieee80211_bss_conf conf;struct rtw89_addr_cam_entry addr_cam;struct rtw89_bssid_cam_entry bssid_cam;struct ieee80211_tx_queue_params tx_params[4];};
struct rtw89_sta_link{u8 mac_id;struct ieee80211_sta sta;struct ieee80211_link_sta link;};
struct rtw89_chip_info{u8 rf_path_num,h2c_cctl_func_id,chip_gen,addrcam_ver;};
struct rtw89_chan{u8 band_type;};
struct rtw89_hal{u8 antenna_tx;};struct rtw89_fw_secure{bool secure_boot;};
struct rtw89_dev{struct rtw89_chip_info*chip;struct rtw89_hal hal;struct{bool tx_rpt_enabled;}hci;struct{struct rtw89_fw_secure sec;}fw;};
struct sk_buff{u8*data;};
static bool fixed;
static void dump(const char*name,const void*bytes,size_t length){printf("%s ",name);for(size_t i=0;i<length;i++)printf("%02x",((const u8*)bytes)[i]);puts("");}
static void le32p_replace_bits(__le32*p,u32 v,u32 m){*p=(*p&~m)|le32_encode_bits(v,m);}
static struct sk_buff*rtw89_fw_h2c_alloc_skb_with_hdr(struct rtw89_dev*d,u32 n){struct sk_buff*s=calloc(1,sizeof(*s));s->data=calloc(1,n);return s;}
static void skb_put(struct sk_buff*s,u32 n){}
static void dev_kfree_skb_any(struct sk_buff*s){free(s->data);free(s);}
static void rtw89_err(struct rtw89_dev*d,const char*msg){}
static void rtw89_h2c_pkt_set_hdr(struct rtw89_dev*d,struct sk_buff*s,int delivery,int cat,int cls,int fn,int rec,int done,u32 len){}
static int rtw89_h2c_tx(struct rtw89_dev*d,struct sk_buff*s,bool keep);
static struct ieee80211_vif*rtwvif_link_to_vif(struct rtw89_vif_link*v){return &v->vif;}
static struct ieee80211_bss_conf*rtw89_vif_rcu_dereference_link(struct rtw89_vif_link*v,bool x){return &v->conf;}
static struct ieee80211_sta*rtwsta_link_to_sta_safe(struct rtw89_sta_link*s){return s?&s->sta:NULL;}
static struct ieee80211_link_sta*rtw89_sta_rcu_dereference_link(struct rtw89_sta_link*s,bool x){return &s->link;}
static struct rtw89_addr_cam_entry*rtw89_get_addr_cam_of(struct rtw89_vif_link*v,struct rtw89_sta_link*s){return &v->addr_cam;}
static struct rtw89_bssid_cam_entry*rtw89_get_bssid_cam_of(struct rtw89_vif_link*v,struct rtw89_sta_link*s){return &v->bssid_cam;}
static const struct rtw89_chan*rtw89_chan_get(struct rtw89_dev*d,u8 index){static const struct rtw89_chan chan={0};return &chan;}
static void __get_sta_he_pkt_padding(struct rtw89_dev*d,struct ieee80211_link_sta*s,u8*p){}
static const u8 ac_to_fw_idx[4]={3,2,0,1};
static void rtw89_write32(struct rtw89_dev*d,u32 address,u32 value){printf("W %08x %08x\n",address,value);}
'''
post = r'''
static int rtw89_h2c_tx(struct rtw89_dev*d,struct sk_buff*s,bool keep){
if(fixed){SET_CMC_TBL_DATARATE(s->data,0);SET_CMC_TBL_DATA_BW(s->data,0);SET_CMC_TBL_TRYRATE(s->data,0);SET_CMC_TBL_SECTYPE(s->data,0);}
dump(fixed?"fixed":"payload",s->data,68);dev_kfree_skb_any(s);return 0;}
int main(void){printf("P %08x\n",R_AX_SS_MACID_PAUSE_0);printf("A %08x %08x %08x %08x\n",R_AX_LDM,B_AX_EN_32K,R_AX_PPWRBIT_SETTING,0xE);struct rtw89_chip_info chip={.rf_path_num=2,.h2c_cctl_func_id=2,.addrcam_ver=0};struct rtw89_dev d={.chip=&chip,.hal.antenna_tx=1};
struct rtw89_vif_link v={.wifi_role=1,.mac_addr={2,4,6,8,10,12},.addr_cam={.len=64,.valid=true,.sec_ent_mode=2},.bssid_cam={.len=8,.valid=true}};
encode_role(&v,0);encode_role(&v,1);encode_join(&v,true);v.net_type=2;encode_join(&v,false);v.net_type=0;
for(int phase=0;phase<4;phase++){struct rtw89_h2c_addr_cam_v0 cmd={0};
if(phase){u8 peer[6]={2,3,5,7,11,13};memcpy(v.bssid,peer,6);memcpy(v.bssid_cam.bssid,peer,6);}
v.vif.cfg.aid=phase==2?42:0;v.net_type=phase==2?2:0;v.addr_cam.valid=phase!=3;v.bssid_cam.valid=phase!=3;
rtw89_cam_fill_addr_cam_info(&d,&v,NULL,NULL,&cmd);rtw89_cam_fill_bssid_cam_info(&d,&v,NULL,&cmd);dump("cam",&cmd,sizeof(cmd));}
for(int pause=0;pause<2;pause++){struct rtw89_fw_macid_pause_grp cmd={0};cmd.mask_grp[0]=1;if(pause)cmd.pause_grp[0]=1;dump("pause",&cmd,sizeof(cmd));}
v.net_type=0;rtw89_fw_h2c_default_cmac_tbl(&d,&v,NULL);fixed=true;rtw89_fw_h2c_assoc_cmac_tbl(&d,&v,NULL);fixed=false;
rtw89_mac_dmac_tbl_init(&d,0);rtw89_mac_cmac_tbl_init(&d,0);
return 0;}
'''
ps = (BASE / 'ps.c').read_text()
awake_mask = re.search(r'u32 pwr_en_bit = .*?;', function(ps, 'rtw89_fw_leave_lps_check')).group()
post = post.replace('int main(void){', 'int main(void){' + awake_mask, 1)
post = post.replace('R_AX_PPWRBIT_SETTING,0xE)', 'R_AX_PPWRBIT_SETTING,pwr_en_bit)')
# EDCA and pause use their original inline encoders, independently of skb size.
post = post.replace('rtw89_mac_dmac_tbl_init(&d,0);', r'''
for(int short_slot=0;short_slot<2;short_slot++){v.conf.use_short_slot=short_slot;
for(int ac=0;ac<4;ac++){u8 bytes[12]={0};u32 aifs=rtw89_aifsn_to_aifs(&d,&v,2);u32 value=FIELD_PREP(FW_EDCA_PARAM_CWMAX_MSK,10)|FIELD_PREP(FW_EDCA_PARAM_CWMIN_MSK,5)|FIELD_PREP(FW_EDCA_PARAM_AIFS_MSK,aifs);
RTW89_SET_EDCA_SEL(bytes,0);RTW89_SET_EDCA_BAND(bytes,0);RTW89_SET_EDCA_WMM(bytes,0);RTW89_SET_EDCA_AC(bytes,ac);RTW89_SET_EDCA_PARAM(bytes,value);dump("edca",bytes,12);}}
rtw89_mac_dmac_tbl_init(&d,0);''')
with tempfile.TemporaryDirectory() as directory:
    source, executable = Path(directory) / 'station.c', Path(directory) / 'station'
    source.write_text(pre + '\n'.join(definitions[n] for n in sorted(needed) if n in definitions) + '\n' + types + '\n' + body + post)
    subprocess.run(['cc', '-O2', '-Wno-address-of-packed-member', '-o', str(executable), str(source)], check=True)
    rows = subprocess.check_output([str(executable)]).decode().splitlines()
groups = {}
writes = []
pause_register = None
awake_registers = None
for row in rows:
    kind, *parts = row.split()
    if kind == 'P':
        pause_register = int(parts[0], 16)
    elif kind == 'A':
        awake_registers = tuple(int(value,16) for value in parts)
    elif kind == 'W':
        writes.append(tuple(int(value, 16) for value in parts))
    else:
        groups.setdefault(kind, []).append(bytes.fromhex(parts[0]))
golden = '// Compiled original Linux AX-v0 role/join/CAM/CCTL/EDCA and table writes.\n'
assert pause_register is not None
golden += f'const LINUX_PAUSE_REGISTER: u32 = 0x{pause_register:x};\n'
assert awake_registers is not None
golden += 'const LINUX_AWAKE_REGISTERS:[(u32,u32);2]=[' + ','.join(f'(0x{awake_registers[i]:x},0x{awake_registers[i+1]:x})' for i in [0,2]) + '];\n'
for name, group in groups.items():
    assert len({len(row) for row in group}) == 1
    golden += f'const LINUX_{name.upper()}: [[u8; {len(group[0])}]; {len(group)}] = [\n'
    for row in group:
        golden += '[' + ','.join(str(value) for value in row) + '],\n'
    golden += '];\n'
golden += f'const LINUX_TABLE_WRITES: [(u32,u32); {len(writes)}] = [\n'
for address, value in writes:
    golden += f'(0x{address:x},0x{value:x}),\n'
golden += '];\n'
(HERE / 'golden.rs').write_text(golden)
subprocess.run(['rustfmt', '--edition', '2021', str(HERE / 'golden.rs')], check=True)
