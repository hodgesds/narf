"""Run original mac80211 non-QoS defaults through rtw88 queue programming.

The explicit CCK1 profile keeps the conservative 11b contention window for
both negotiated slot times. These inert register words grant no radio power.
"""
from pathlib import Path
import re
import subprocess
import tempfile

LINUX = Path('/usr/src/linux')
HERE = Path(__file__).parent


def function(source, name):
    match = re.search(r'\b' + name + r'\s*\([^;{}]*\)\s*\{', source)
    start = source.rfind('\n', 0, match.start()) + 1
    brace = source.index('{', match.start())
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


rtw = (LINUX / 'drivers/net/wireless/realtek/rtw88/mac80211.c').read_text()
util = (LINUX / 'net/mac80211/util.c').read_text()
table = re.search(r'static const u32 ac_to_edca_param\[.*?\};', rtw, re.S).group()
functions = '\n'.join(function(rtw, name) for name in [
    'rtw_aifsn_to_aifs', '__rtw_conf_tx',
])
defaults = function(util, 'ieee80211_set_wmm_default')
pre = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define IEEE80211_NUM_ACS 4
#define IEEE80211_AC_VO 0
#define IEEE80211_AC_VI 1
#define IEEE80211_AC_BE 2
#define IEEE80211_AC_BK 3
#define NL80211_BAND_2GHZ 0
#define RTW_BAND_5G 1
#define NL80211_IFTYPE_OCB 1
#define NL80211_IFTYPE_MONITOR 2
#define NL80211_IFTYPE_P2P_DEVICE 3
#define NL80211_IFTYPE_NAN 4
#define BSS_CHANGED_QOS 1
#define REG_EDCA_VO_PARAM 0x500
#define REG_EDCA_VI_PARAM 0x504
#define REG_EDCA_BE_PARAM 0x508
#define REG_EDCA_BK_PARAM 0x50c
#define BIT_MASK_TXOP_LMT 0x07ff0000U
#define BIT_MASK_CWMAX 0x0000f000U
#define BIT_MASK_CWMIN 0x00000f00U
#define BIT_MASK_AIFS 0x000000ffU
#define ilog2(x) (31-__builtin_clz((unsigned)(x)))
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)
struct ieee80211_tx_queue_params {u16 cw_max,cw_min,txop;u8 aifs;bool uapsd;};
struct channel {int band;};
struct ieee80211_chanctx_conf {struct {struct channel*chan;}def;};
struct ieee80211_bss_conf {bool use_short_slot,qos;struct ieee80211_chanctx_conf*chanctx_conf;};
struct ieee80211_vif {struct ieee80211_bss_conf bss_conf;int type;};
struct rtw_vif {struct ieee80211_vif vif;struct ieee80211_tx_queue_params tx_params[4];};
struct rtw_dev {struct {int current_band_type;}hal;u32 regs[4];};
static struct ieee80211_vif*rtwvif_to_vif(struct rtw_vif*v){return &v->vif;}
static void rtw_write32_mask(struct rtw_dev*d,u32 reg,u32 mask,u32 value){
u32*p=&d->regs[(reg-0x500)/4];*p=(*p&~mask)|((value<<__builtin_ctz(mask))&mask);}
struct ieee80211_local {struct {bool conf_tx;}*ops;struct {int queues;}hw;struct rtw_dev*rtw;struct rtw_vif*vif;};
struct ieee80211_sub_if_data {struct ieee80211_local*local;struct ieee80211_vif vif;};
struct ieee80211_link_data {struct ieee80211_sub_if_data*sdata;struct ieee80211_bss_conf*conf;bool operating_11g_mode;struct ieee80211_tx_queue_params tx_conf[4];};
static struct ieee80211_local*sdata_to_local(struct ieee80211_sub_if_data*s){return s->local;}
static void ieee80211_regulatory_limit_wmm_params(struct ieee80211_sub_if_data*s,struct ieee80211_tx_queue_params*p,int ac){}
static void ieee80211_link_info_change_notify(struct ieee80211_sub_if_data*s,struct ieee80211_link_data*l,int changed){}
'''
bridge = r'''
static void drv_conf_tx(struct ieee80211_local*l,struct ieee80211_link_data*link,int ac,struct ieee80211_tx_queue_params*p){
l->vif->tx_params[ac]=*p;__rtw_conf_tx(l->rtw,l->vif,ac);}
'''
post = r'''
int main(void){for(int short_slot=0;short_slot<2;short_slot++){
struct rtw_dev d={.regs={0xf8ffffff,0xf8ffffff,0xf8ffffff,0xf8ffffff}};
struct rtw_vif v={.vif.bss_conf.use_short_slot=short_slot};
struct channel channel={.band=NL80211_BAND_2GHZ};struct ieee80211_chanctx_conf channel_ctx={.def.chan=&channel};
v.vif.bss_conf.chanctx_conf=&channel_ctx;
struct ieee80211_local local={.hw.queues=4,.rtw=&d,.vif=&v};typeof(*local.ops)ops={.conf_tx=true};local.ops=&ops;
struct ieee80211_sub_if_data s={.local=&local};struct ieee80211_link_data link={.sdata=&s,.conf=&v.vif.bss_conf};
ieee80211_set_wmm_default(&link,false,false);
printf("%08x %08x %08x %08x\n",d.regs[0],d.regs[1],d.regs[2],d.regs[3]);
}return 0;}
'''
with tempfile.TemporaryDirectory() as directory:
    source, executable = Path(directory) / 'dcf.c', Path(directory) / 'dcf'
    source.write_text(pre + table + '\n' + functions + bridge + defaults + post)
    subprocess.run(['cc', '-O2', '-o', str(executable), str(source)], check=True)
    rows = subprocess.check_output([str(executable)]).decode().splitlines()
assert len(rows) == 2
golden = '// Original mac80211 non-QoS defaults and rtw88 __rtw_conf_tx; long/short slot.\n'
golden += 'const LINUX_DCF: [[u32; 4]; 2] = [\n'
for row in rows:
    golden += '[' + ','.join('0x' + word for word in row.split()) + '],\n'
golden += '];\n'
(HERE / 'dcf_golden.rs').write_text(golden)
subprocess.run(['rustfmt', '--edition', '2021', str(HERE / 'dcf_golden.rs')], check=True)
