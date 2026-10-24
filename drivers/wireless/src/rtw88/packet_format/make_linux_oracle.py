#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile original RTL8822CE PCI packet functions over an inert DMA backend."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88'))
p.add_argument('--check',action='store_true')
a=p.parse_args();here=Path(__file__).parent
sources={name:(a.linux/name).read_text() for name in ['pci.c','pci.h','tx.c','tx.h','rx.c','rx.h','fw.h','main.h','mac.h']}
def block(source,pattern,semicolon=False):
    match=re.search(pattern,source);assert match,pattern
    brace=source.index('{',match.start());end=brace+1;depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[match.start():source.index(';',end)+1 if semicolon else end]
def clean(source):return re.sub(r'/\*.*?\*/|//[^\n]*','',source,flags=re.S)
sources_clean={k:clean(v) for k,v in sources.items()}
types='\n'.join(block(sources_clean[file],r'(?:struct|enum) '+name+r'\s*\{',True) for file,name in [
    ('tx.h','rtw_tx_desc'),('tx.h','rtw_tx_desc_queue_select'),('pci.h','rtw_pci_tx_buffer_desc'),
    ('pci.h','rtw_pci_tx_data'),('pci.h','rtw_pci_ring'),('pci.h','rtw_pci_tx_ring'),('pci.h','rtw_pci_rx_buffer_desc'),
    ('rx.h','rtw_rx_desc'),('rx.h','rtw_rx_desc_enc'),('main.h','rtw_tx_queue_type'),
    ('main.h','rtw_tx_pkt_info'),('main.h','rtw_rx_pkt_stat'),('main.h','rtw_trx_desc_rate'),
    ('fw.h','rtw_c2h_cmd_id'),('fw.h','rtw_c2h_cmd_id_ext')])
defines='\n'.join(line for name in ['tx.h','rx.h','fw.h'] for line in sources_clean[name].splitlines()
    if line.startswith('#define RTW_TX_DESC_') or line.startswith('#define RTW_RX_DESC_') or line.startswith('#define GET_CCX_REPORT_'))
owners=[('tx.c',r'void rtw_tx_fill_tx_desc\s*\('),('pci.c',r'static u8 rtw_pci_get_tx_qsel\s*\('),
    ('pci.h',r'static inline int avail_desc\s*\('),('pci.h',r'static inline\s+struct rtw_pci_tx_buffer_desc \*get_tx_buffer_desc\s*\('),
    ('pci.c',r'static int rtw_pci_tx_write_data\s*\('),('rx.c',r'int rtw_rx_query_rx_desc\s*\(')]
functions=[block(sources_clean[file],pattern) for file,pattern in owners]
prefix=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t dma_addr_t;typedef int8_t s8;typedef int32_t s32;typedef u32 __le32;typedef u16 __le16;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((0xffffffffU>>(31-(h))) & (0xffffffffU<<(l)))
#define le32_encode_bits(v,m) (((u32)(v)<<__builtin_ctz(m))&(m))
#define le32_get_bits(v,m) (((v)&(m))>>__builtin_ctz(m))
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define RTW_RF_PATH_MAX 4
#define PHY_STATUS_SIZE 4
#define FCS_LEN 4
#define IEEE80211_MAX_MPDU_LEN_VHT_11454 11454
#define unlikely(x) (x)
#define WARN_ONCE(...) 0
#define ENOSPC 28
#define EBUSY 16
#define EINVAL 22
#define DMA_TO_DEVICE 0
#define RTK_PCI_TXBD_OWN_OFFSET 15
struct sk_buff_head {int dummy;};
'''
shim=r'''
struct sk_buff {u8 *data;u32 len;u8 priority;};
struct ieee80211_rx_status {int dummy;};
struct rtw_chip_ops {void (*query_phy_status)(void*,void*,void*);};
struct rtw_chip_info {u32 tx_pkt_desc_sz,tx_buf_desc_sz,rx_pkt_desc_sz;bool old_datarate_fb_limit;struct rtw_chip_ops *ops;};
struct rtw_dev {void *priv;const struct rtw_chip_info *chip;void *dev;};
struct pci_dev {int dev;};
struct rtw_pci {struct pci_dev *pdev;struct rtw_pci_tx_ring tx_rings[RTK_MAX_TX_QUEUE_NUM];int irq_lock;unsigned long tx_queued[1];};
static struct rtw_pci_tx_data native_tx_data;
static u8 *skb_push(struct sk_buff*s,u32 n){s->data-=n;s->len+=n;return s->data;}
static dma_addr_t dma_map_single(void*a,void*b,u32 c,int d){return 0x12345000;}
static bool dma_mapping_error(void*a,dma_addr_t b){return false;}
static struct rtw_pci_tx_data *rtw_pci_get_tx_data(struct sk_buff*s){return &native_tx_data;}
static void rtw_pci_release_rsvd_page(struct rtw_pci*p,struct rtw_pci_tx_ring*r){}
static void skb_queue_tail(struct sk_buff_head*q,struct sk_buff*s){}
static void spin_lock_bh(int*p){} static void spin_unlock_bh(int*p){}
static void set_bit(unsigned n,unsigned long*p){*p|=1UL<<n;}
static void query_phy(void*a,void*b,void*c){}
static void rtw_rx_fill_rx_status(struct rtw_dev*d,struct rtw_rx_pkt_stat*p,struct ieee80211_hdr*h,struct ieee80211_rx_status*s){}
'''
main=r'''
int main(void){
 struct rtw_chip_ops ops={.query_phy_status=query_phy};
 struct rtw_chip_info chip={.tx_pkt_desc_sz=48,.tx_buf_desc_sz=16,.rx_pkt_desc_sz=24,.ops=&ops};
 struct pci_dev pdev={0};struct rtw_pci pci={.pdev=&pdev};struct rtw_dev dev={.priv=&pci,.chip=&chip};
 printf("pub const LINUX_GEOMETRY: [usize;4]=[%zu,%zu,%zu,%zu];\n",sizeof(struct rtw_tx_desc),sizeof(struct rtw_pci_tx_buffer_desc)*2,sizeof(struct rtw_rx_desc),sizeof(struct rtw_pci_rx_buffer_desc));
 printf("pub type TxCase=(usize,bool,u8,Option<u8>,[u32;12],[u32;4]);\npub const TX_CASES: &[TxCase]=&[\n");
 const unsigned lengths[]={24,127,1500,2304};const unsigned ids[]={0,1,127};
 for(unsigned n=0;n<4;n++)for(unsigned mgmt=0;mgmt<2;mgmt++)for(unsigned m=0;m<3;m++)for(unsigned report=0;report<2;report++){
  u8 packet[48+2304]={0};u8 bd[16];memset(bd,0xa5,16);
  unsigned q=mgmt?RTW_TX_QUEUE_MGMT:RTW_TX_QUEUE_BE;
  struct rtw_pci_tx_ring *ring=&pci.tx_rings[q];memset(ring,0,sizeof(*ring));ring->r.head=bd;ring->r.len=128;
  struct sk_buff skb={.data=packet+48,.len=lengths[n],.priority=0};
  struct rtw_tx_pkt_info info={.tx_pkt_size=lengths[n],.offset=48,.mac_id=ids[m],.rate_id=8,.rate=0,.seq=0xabc,.use_rate=true,.ls=true,.dis_qselseq=true,.dis_rate_fallback=true,.report=report,.sn=report?0xfc:0};
  if(rtw_pci_tx_write_data(&dev,&info,&skb,q))return 1;
  printf("(%u,%s,%u,%s,[",lengths[n],mgmt?"true":"false",ids[m],report?"Some(252)":"None");
  for(unsigned i=0;i<12;i++){u32 v;memcpy(&v,packet+i*4,4);printf("0x%08x,",v);}printf("],[");
  for(unsigned i=0;i<4;i++){u32 v;memcpy(&v,bd+i*4,4);printf("0x%08x,",v);}printf("]),\n");
 }printf("];\n");
 printf("pub const RX_CASES: &[([u32;6],usize,usize,bool,bool)]=&[\n");
 for(unsigned info=0;info<2;info++)for(unsigned shift=0;shift<4;shift++)for(unsigned ctl=0;ctl<2;ctl++)for(unsigned crypt=0;crypt<3;crypt++){
  u8 buffer[11478]={0};struct rtw_rx_desc *d=(void*)buffer;struct rtw_rx_pkt_stat stat;struct ieee80211_rx_status status;
  d->w0=100|(info?4U<<16|1U<<26:0)|shift<<24|(crypt?4U<<20:0)|(crypt==2?1U<<27:0);
  d->w2=ctl?1U<<28:0;d->w3=0x0b;
  if(rtw_rx_query_rx_desc(&dev,buffer,&stat,&status))return 2;
  printf("([");for(unsigned i=0;i<6;i++){u32 v;memcpy(&v,buffer+i*4,4);printf("0x%08x,",v);}
  printf("],%u,%u,%s,%s),\n",24+stat.drv_info_sz+stat.shift,stat.pkt_len,stat.is_c2h?"true":"false",stat.decrypted?"true":"false");
 }printf("];\n");
 printf("pub const REPORT_CASES: &[(u8,u8,u8,u8,bool)]=&[\n");
 for(unsigned version=0;version<2;version++)for(unsigned sn=0;sn<256;sn+=4)for(unsigned status=0;status<256;status+=64){
  u8 payload[10]={0};payload[0]=version?C2H_CCX_RPT:status;payload[6]=sn;payload[8]=sn;payload[9]=status;
  u8 got_sn=version?GET_CCX_REPORT_SEQNUM_V1(payload):GET_CCX_REPORT_SEQNUM_V0(payload);
  u8 got_status=version?GET_CCX_REPORT_STATUS_V1(payload):GET_CCX_REPORT_STATUS_V0(payload);
  printf("(%u,%u,%u,%u,%s),\n",version?C2H_HALMAC:C2H_CCX_TX_RPT,sn,status,got_sn,got_status==0?"true":"false");
 }printf("];\n");return 0;
}
'''
unit=prefix+types+'\n'+defines+'\n'+shim+'\n'+'\n'.join(functions)+'\n'+main
with tempfile.TemporaryDirectory(prefix='narf-rtw88-packet-oracle-') as td:
    td=Path(td);(td/'oracle.c').write_text(unit)
    subprocess.run(['cc','-std=gnu11','-O2','-Werror','-Wno-address-of-packed-member',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True)
    output=subprocess.check_output([str(td/'oracle')]).decode()
    golden='// Original Linux C packet vectors; make_linux_oracle.py.\n'+output
    (td/'golden.rs').write_text(golden)
    subprocess.run(['rustfmt','--edition','2021',str(td/'golden.rs')],check=True)
    golden=(td/'golden.rs').read_text()
provenance=json.dumps({'sources':{name:hashlib.sha256(text.encode()).hexdigest() for name,text in sources.items()},'functions':{pattern:hashlib.sha256(body.encode()).hexdigest() for (_,pattern),body in zip(owners,functions)}},indent=2)+'\n'
for name,content in [('golden.rs',golden),('provenance.json',provenance)]:
    if a.check:
        assert (here/name).read_text()==content,name+' differs'
    else:(here/name).write_text(content)
