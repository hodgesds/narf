#!/usr/bin/env python3
"""Compile original AX RXD, RXBD and ring-index functions; no Rust encoder."""
from pathlib import Path
import argparse, hashlib, re, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
core=(a.linux/'core.h').read_text();pc=(a.linux/'pci.c').read_text();fw=(a.linux/'fw.c').read_text()
headers='\n'.join((a.linux/n).read_text() for n in ['txrx.h','pci.h','fw.h'])
def block(source,pattern):
    m=re.search(pattern,source,re.M)
    if not m:raise RuntimeError(pattern)
    end=source.index('{',m.end())+1;depth=1
    while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[m.start():end]
def structure(name,source=core):
    return block(source,r'^struct '+name+r'\s*')+';\n'
def function(name,source):
    return block(source,r'^(?:static )?(?:int|u8|u32|void) '+name+r'\s*\(')+'\n'
original=structure('rtw89_rx_desc_info')+structure('rtw89_rxdesc_short')+structure('rtw89_rxdesc_long')
original+=structure('rtw89_pci_rx_bd_32',headers)+structure('rtw89_fw_c2h_attr',headers)+structure('rtw89_c2h_hdr',headers)
original+=structure('rtw89_pci_rpp_fmt',headers)+structure('rtw89_pci_rpp_info',headers)
original+=block(headers,r'^enum rtw89_tx_channel\s*')+';\n'+block(headers,r'^enum rtw89_tx_qsel\s*')+';\n'
query=function('rtw89_core_query_rxdesc',(a.linux/'core.c').read_text())
recalc=function('rtw89_pci_dma_recalc',pc);init=function('rtw89_pci_init_rx_bd',pc)
c2h=function('rtw89_fw_c2h_parse_attr',fw)
mapping=function('rtw89_core_get_ch_dma',(a.linux/'core.c').read_text())
rpp=function('rtw89_pci_parse_rpp',pc)
defs={m.group(1):m.group(0) for m in re.finditer(r'^#define\s+(\w+)\s+[^\n]+',headers,re.M)}
names=set(re.findall(r'\b(?:AX_RXD_\w+|RTW89_C2H_HDR_\w+|RTW89_PCI_RPP_\w+|TXBD_HW_IDX_MASK)\b',query+recalc+c2h+rpp))
names.add('RTW89_PCI_RPP_MACID')
defines='\n'.join(defs[n] for n in sorted(names))
prefix='''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef uint16_t __le16;typedef uint32_t __le32;typedef uint64_t dma_addr_t;
#define __packed __attribute__((packed))
#define BIT(n) (1ULL<<(n))
#define GENMASK(h,l) ((~0ULL<<(l))&(~0ULL>>(63-(h))))
#define FIELD_GET(m,v) (((u64)(v)&(m))>>__builtin_ctzll(m))
#define le32_get_bits(v,m) FIELD_GET(m,v)
#define le16_encode_bits(v,m) (((u16)(v)<<__builtin_ctzll(m))&(m))
#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define RTL8852B 1
#define RTL8852C 2
#define DMA_FROM_DEVICE 0
#define rtw89_warn(...) ((void)0)
#define fallthrough __attribute__((fallthrough))
#define rtw89_chip_get_ch_dma rtw89_core_get_ch_dma
'''
shim='''struct rtw89_chip_info {int chip_id;};
struct rtw89_pci_info {bool rx_ring_eq_is_full;};
struct rtw89_dev {const struct rtw89_chip_info *chip;const struct rtw89_pci_info *pci_info;};
struct rtw89_pci_dma_ring {u32 rp,wp,len;};
struct rtw89_pci_rx_ring {struct rtw89_pci_rx_bd_32 bd[2];};
struct pci_dev {int dev;};
struct rtw89_pci_rx_info {dma_addr_t dma;};
struct sk_buff {u8 *data;struct rtw89_pci_rx_info rx;struct rtw89_fw_c2h_attr attr;};
#define RTW89_PCI_RX_SKB_CB(skb) (&(skb)->rx)
#define RTW89_SKB_C2H_CB(skb) (&(skb)->attr)
#define RTW89_PCI_RX_BD(ring,idx) (&(ring)->bd[idx])
#define dma_map_single(dev,data,size,dir) ((u64)(uintptr_t)(data))
#define dma_mapping_error(...) 0
#define upper_32_bits(a) ((u32)((a)>>32))
'''
main=r'''int main(void){
 struct rtw89_chip_info chip={RTL8852B};struct rtw89_pci_info pci={0};struct rtw89_dev dev={&chip,&pci};
 printf("type RxdGolden = ([u32;3],[u32;7]);\npub(super) const RXD: &[RxdGolden] = &[\n");
 for(u32 l=0;l<2;l++)for(u32 drv=0;drv<8;drv++)for(u32 k=0;k<3;k++) {
  u32 types[]={0,7,10};u8 data[128]={0};u32 *w=(u32*)(data+4);
  w[0]=64|(types[k]<<24)|(drv<<28)|(l<<31);w[1]=(11<<16);w[3]=(k==2?0x604:0);
  struct rtw89_rx_desc_info info={0};rtw89_core_query_rxdesc(&dev,&info,data,4);
  printf("([0x%x,0x%x,0x%x],[%u,%u,%u,%u,%u,%u,%u]),\n",w[0],w[1],w[3],info.pkt_size,info.offset+info.rxd_len,info.pkt_type,info.data_rate,info.bw,info.crc32_err,info.icv_err);
 }
 printf("];\npub(super) const BD: &[(u64,[u8;8])] = &[\n");
 u64 addresses[]={0,0x12345678,0xabcdef1234,0xffffffffff-11498+1};
 for(u32 i=0;i<4;i++) {
  struct rtw89_pci_rx_ring ring={0};struct pci_dev pdev={0};struct sk_buff skb={.data=(u8*)(uintptr_t)addresses[i]};
  rtw89_pci_init_rx_bd(&dev,&pdev,&ring,&skb,11498,0);u8 *b=(u8*)&ring.bd[0];
  printf("(0x%llx,[",(unsigned long long)addresses[i]);for(u32 n=0;n<8;n++)printf("%u,",b[n]);printf("]),\n");
 }
 printf("];\npub(super) const INDEX: &[(u16,u16,u32,u16)] = &[\n");
 for(u32 wp=0;wp<8;wp++)for(u32 rp=0;rp<8;rp++) {
  struct rtw89_pci_dma_ring ring={.wp=wp,.rp=0,.len=8};u32 idx=(rp<<16)|wp;
  u32 count=rtw89_pci_dma_recalc(&dev,&ring,idx,false);
  printf("(8,%u,0x%x,%u),\n",wp,idx,count);
 }
 printf("];\ntype C2hGolden = ([u32;2],[u16;4]);\npub(super) const C2H: &[C2hGolden] = &[\n");
 for(u32 cat=0;cat<3;cat++)for(u32 cl=0;cl<3;cl++) {
  u32 words[]={cat|(cl<<2)|(0x63<<8),12};struct sk_buff skb={.data=(u8*)words};rtw89_fw_c2h_parse_attr(&skb);
  printf("([0x%x,0x%x],[%u,%u,%u,%u]),\n",words[0],words[1],skb.attr.category,skb.attr.class,skb.attr.func,skb.attr.len);
 }
 printf("];\npub(super) const RPP: &[(u32,[u16;5])] = &[\n");
 u32 qs[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0x12,0x11,0x1a,0x19};
 for(u32 i=0;i<20;i++)for(u32 st=0;st<4;st++)for(u32 seq=0;seq<3;seq++) {
  u32 seqs[]={0,257,32767};struct rtw89_pci_rpp_fmt bytes={.dword=(seqs[seq]<<16)|(st<<13)|(qs[i]<<8)|0x79};
  struct rtw89_pci_rpp_info info={0};rtw89_pci_parse_rpp(&dev,&bytes,&info);
  printf("(0x%x,[%u,%u,%u,%u,%u]),\n",bytes.dword,info.seq,info.qsel,info.tx_status,info.txch,(u32)le32_get_bits(bytes.dword,RTW89_PCI_RPP_MACID));
 }
 printf("];\n");return 0;
}'''
body=original+query+recalc+init+c2h+mapping+rpp
code=prefix+defines+'\n'+original+shim+query+recalc+init+c2h+mapping+rpp+main
with tempfile.TemporaryDirectory(prefix='rtw89-rx-oracle-') as td:
    td=Path(td);(td/'oracle.c').write_text(code)
    subprocess.run(['cc','-std=gnu11','-O2',str(td/'oracle.c'),'-o',str(td/'oracle')],check=True)
    result=subprocess.check_output([str(td/'oracle')]).decode()
value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Original Linux RX functions/types SHA256 '+hashlib.sha256((body+defines).encode()).hexdigest()+'\n'+result
path=d/'golden.rs'
if a.check:
    if path.read_text()!=value:raise SystemExit('RX oracle differs')
else:path.write_text(value)
