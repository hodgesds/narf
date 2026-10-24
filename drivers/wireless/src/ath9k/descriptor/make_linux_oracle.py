#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build AR9285 descriptor expectations from complete original Linux C."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux', type=Path, default=Path('/usr/src/linux'))
p.add_argument('--out', type=Path)
args = p.parse_args()
scratch = tempfile.TemporaryDirectory(prefix='narf-ar9285-packets-') if args.out is None else None
out = args.out or Path(scratch.name)
out.mkdir(parents=True, exist_ok=True)
root = args.linux / 'drivers/net/wireless/ath/ath9k'
sources = {name: (root / name).read_text() for name in ['mac.h', 'mac.c', 'hw.h', 'ar9002_mac.c', 'hw.c', 'common-init.c', 'xmit.c']}

def clean(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)

def block(text, pattern, semicolon=False):
    match = re.search(pattern, text)
    assert match, pattern
    end = match.end()
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if semicolon:
        end = text.index(';', end) + 1
    return text[match.start():end]

header = clean(sources['mac.h']).replace('\\\n', ' ')
defines = '\n'.join(m.group(0) for m in re.finditer(r'^#define\s+(?!MAC_H\b)[^\n]+', header, re.M))
structures = '\n'.join(block(header, r'struct ' + name + r'\s*\{', True)
    for name in ['ath_desc', 'ar5416_desc', 'ath9k_11n_rate_series', 'ath_tx_info', 'ath_rx_status'])
defines += '\n' + re.search(r'^#define AR_BufLen[^\n]+', sources['ar9002_mac.c'], re.M).group(0)
defines += '\n' + re.search(r'^#define ATH9K_RSSI_BAD[^\n]+', sources['hw.h'], re.M).group(0)
enums = '\n'.join(block(header, r'enum ' + name + r'\s*\{', True)
    for name in ['aggr_type', 'ath9k_key_type', 'ath9k_pkt_type'])
owners = [('ar9002_mac.c', 'ar9002_set_txdesc'),
          ('ar9002_mac.c', 'ath9k_hw_clear_rxdesc_status'),
          ('ar9002_mac.c', 'ath9k_hw_setuprxdesc'),
          ('hw.c', 'ath9k_hw_computetxtime'), ('mac.c','ath9k_hw_rxprocdesc')]
functions = [block(clean(sources[file]), r'(?:static\s+)?(?:void|u16|int)\s+' + name + r'\s*\([^)]*\)\s*\{') for file, name in owners]
rates_block = block(clean(sources['common-init.c']), r'static struct ieee80211_rate ath9k_legacy_rates\[\]\s*=\s*\{', True)
rates = [(int(kbps), int(hw, 16)) for kbps, hw in re.findall(r'RATE\((\d+),\s*(0x[0-9a-f]+)', rates_block)]
assert len(rates) == 12
prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t dma_addr_t;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define WRITE_ONCE(p,v) ((p)=(v))
#define fallthrough ((void)0)
#define SM(v,f) (((u32)(v)<<f##_S)&(f))
#define MS(v,f) (((v)&(f))>>f##_S)
#define AR_SREV_9285(a) 1
#define AR_SREV_9280_20_OR_LATER(a) 1
#define EINPROGRESS 115
#define RX_ENC_FLAG_SHORT_GI 1
#define RX_ENC_FLAG_STBC_SHIFT 1
enum rate_info_bw {RATE_INFO_BW_20,RATE_INFO_BW_40};
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define IS_CHAN_QUARTER_RATE(c) 0
#define IS_CHAN_HALF_RATE(c) 0
#define ath_err(...) ((void)0)
#define WLAN_RC_PHY_CCK 0
#define WLAN_RC_PHY_OFDM 1
struct ath_hw {void *curchan;};
'''
main = r'''
int main(void) {
 struct ath_hw hw={0};
 printf("pub const DESC_BYTES: usize = %zu;\n", sizeof(struct ar5416_desc));
 printf("pub const TX_STATUS_OFFSET: usize = %zu;\n", offsetof(struct ar5416_desc,u.tx.status0));
 printf("pub const RX_STATUS_OFFSET: usize = %zu;\n", offsetof(struct ar5416_desc,u.rx.status0));
 printf("pub const TX_CASES: &[(usize,usize,bool,[u32;24])] = &[\n");
 for (unsigned rate=0;rate<12;rate++) for (unsigned length=24;length<=2304;length+=(length==24?101:2179)) for (unsigned group=0;group<2;group++) {
  struct ar5416_desc desc;memset(&desc,0xa5,sizeof(desc));
  struct ath_tx_info info={0};info.is_first=info.is_last=true;
  info.pkt_len=length+4;info.buf_addr[0]=0x12345000;info.buf_len[0]=length;
  info.keyix=ATH9K_TXKEYIX_INVALID;info.flags=ATH9K_TXDESC_CLRDMASK|(group?ATH9K_TXDESC_NOACK:0);
  info.txpower[0]=63;info.rtscts_rate=rates[0][1];info.dur_update=true;
  info.rates[0].Rate=rates[rate][1];info.rates[0].Tries=group?1:4;info.rates[0].ChSel=1;
  info.rates[0].PktDuration=ath9k_hw_computetxtime(&hw,rate<4?WLAN_RC_PHY_CCK:WLAN_RC_PHY_OFDM,rates[rate][0]*100,length+4,rate,false);
  ar9002_set_txdesc(&hw,&desc,&info);
  printf("(%u,%u,%s,[",rate,length,group?"true":"false");
  for (unsigned i=0;i<24;i++){u32 v;memcpy(&v,(u8*)&desc+i*4,4);printf("0x%08x,",v);}
  printf("]),\n");
 }
 printf("];\n");
 printf("pub const RX_STATUS_CASES: &[(u32,u8,u8,u8)] = &[\n");
 const u32 cases[]={1,3,0x80000001,0x80000003,0x80000101,5,9,0x11,0x21,0x40000003};
 for(unsigned n=0;n<sizeof(cases)/sizeof(cases[0]);n++){
  struct ar5416_desc desc={0};struct ath_rx_status status={0};
  desc.ds_rxstatus0=0x1b000000;desc.ds_rxstatus1=100;desc.ds_rxstatus8=cases[n];
  if(ath9k_hw_rxprocdesc(&hw,(struct ath_desc*)&desc,&status))return 2;
  printf("(0x%08x,0x%02x,0x%02x,0x%02x),\n",cases[n],status.rs_status,status.rs_flags,status.rs_keyix);
 }printf("];\n");
 return 0;
}
'''
rate_array = 'static const unsigned rates[12][2]={' + ','.join('{%d,%d}' % x for x in rates) + '};\n'
unit = prefix + defines + '\n' + enums + '\n' + structures + '\n' + '\n'.join(functions) + '\n' + rate_array + main
(out/'original.c').write_text(unit)
subprocess.run(['cc','-std=gnu11','-Werror','-Wno-address-of-packed-member',str(out/'original.c'),'-o',str(out/'oracle')],check=True)
result = subprocess.run([str(out/'oracle')],check=True,capture_output=True,text=True)
(out/'golden.rs').write_text('// Extracted original Linux C. Regenerate with make_linux_oracle.py.\n' + result.stdout)
(out/'provenance.json').write_text(json.dumps({'sources':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in sources.items()}, 'functions':{name:hashlib.sha256(body.encode()).hexdigest() for (_,name),body in zip(owners, functions)}},indent=2)+'\n')
print(out/'golden.rs')
