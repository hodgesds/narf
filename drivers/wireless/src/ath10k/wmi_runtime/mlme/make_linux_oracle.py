#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile unmodified Linux WMI generators and compare complete MLME fixtures.
Usage: make_linux_oracle.py [LINUX_TREE] [--golden FILE] [--artifacts DIR]
Only host allocation/debug/endian/kernel glue is stubbed; native declarations,
command enums, packed-layout serializers and complete generators come from Linux.
"""
from pathlib import Path
import argparse, hashlib, json, re, subprocess, tempfile, sys
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("linux", nargs="?", type=Path, default=Path("/usr/src/linux"))
parser.add_argument("--golden", type=Path, default=Path(__file__).with_name("golden.rs"))
parser.add_argument("--artifacts", type=Path)
parser.add_argument("--write", action="store_true", help="replace the selected golden file with native C output")
args=parser.parse_args()
if sys.byteorder != "little": raise SystemExit("Linux little-endian host glue requires a little-endian host")
p=args.linux/"drivers/net/wireless/ath/ath10k"
scratch=tempfile.TemporaryDirectory(prefix="narf-ath10k-mlme-oracle-")
o=args.artifacts or Path(scratch.name)
o.mkdir(parents=True,exist_ok=True)
h=(p/'wmi.h').read_text();t=(p/'wmi-tlv.h').read_text();c=(p/'wmi.c').read_text();tc=(p/'wmi-tlv.c').read_text()
def decl(source,kind,name):
 m=re.search(r'\b'+kind+' '+re.escape(name)+r'\s*\{',source);assert m,name
 i=m.end();depth=1
 while depth:depth+=(source[i]=='{')-(source[i]=='}');i+=1
 return source[m.start():source.index(';',i)+1]
def func(source,name,ret):
 m=re.search(r'(?m)^'+name+r'\(',source);assert m,name
 i=source.index('{',m.end())+1;depth=1
 while depth:depth+=(source[i]=='{')-(source[i]=='}');i+=1
 return 'static '+ret+'\n'+source[m.start():i]
base='#include <stdio.h>\n#define BIT(n) (1u<<(n))\n#define WMI_CMD_GRP(n) (((n)<<12)|1)\n#define WMI_TLV_CMD(n) (((n)<<12)|1)\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdbool.h>\n#include <stddef.h>\n#define __packed __attribute__((packed))\n#define __le32 uint32_t\n#define __le16 uint16_t\n#define u32 uint32_t\n#define u16 uint16_t\n#define u8 uint8_t\n#define __cpu_to_le32(x) (x)\n#define __cpu_to_le16(x) (x)\n#define ETH_ALEN 6\n#define roundup(x,a) (((x)+(a)-1)&~((a)-1))\n#define struct_size(p,field,n) (sizeof(*(p))+sizeof((p)->field[0])*(n))\n#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))\n#define GFP_ATOMIC 0\n#define ENOMEM 12\n#define EINVAL 22\n#define ERR_PTR(x) NULL\n#define ath10k_dbg(...) ((void)0)\n#define ether_addr_copy(d,s) memcpy(d,s,6)\n#define WMI_HOST_SCAN_REQUESTOR_ID_PREFIX 0xa000\n#define WMI_HOST_SCAN_REQ_ID_PREFIX 0xa000\n#define WMI_CHAN_LIST_TAG 1\n#define WMI_SSID_LIST_TAG 2\n#define WMI_BSSID_LIST_TAG 3\n#define WMI_IE_TAG 4\n#define WLAN_SCAN_PARAMS_MAX_IE_LEN 256\n#define WLAN_SCAN_PARAMS_MAX_SSID 16\n#define WLAN_SCAN_PARAMS_MAX_BSSID 4\n#define WMI_TLV_MGMT_RX_NUM_RSSI 4\n#define WMI_SCAN_FILTER_PROBE_REQ 0x20\nstruct ath10k { int unused; };\nstruct sk_buff {u8 *data; size_t len;};\nstatic struct sk_buff *ath10k_wmi_alloc_skb(struct ath10k *ar, size_t len) {\n struct sk_buff *s=calloc(1,sizeof(*s));s->data=calloc(1,len);s->len=len;return s;\n}\n'
for name in ["wmi_cmd_group","wmi_cmd_id","wmi_10x_cmd_id","wmi_10_2_cmd_id","wmi_10_4_cmd_id","wmi_phy_mode"]: base+=decl(h,"enum",name)+"\n"
for name in ["wmi_tlv_grp_id","wmi_tlv_cmd_id","wmi_tlv_tag"]: base+=decl(t,"enum",name)+"\n"
base+=decl(h,"struct","wmi_mac_addr")+"\n"+decl(t,"struct","wmi_tlv")+"\n"
base+='\n#define __le64 uint64_t\n#define u64 uint64_t\n#define u16 uint16_t\n#define dma_addr_t uint64_t\n#define __cpu_to_le64(x) (x)\n#define le16_to_cpu(x) (x)\n#define WARN_ON_ONCE(x) (x)\n#define round_up(x,a) roundup(x,a)\n#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))\n#define WMI_TLV_MGMT_TX_FRAME_MAX_LEN 64\n#define IEEE80211_CCMP_MIC_LEN 8\n#define IEEE80211_GCMP_MIC_LEN 16\n#define WLAN_CIPHER_SUITE_GCMP 0x000fac08\n#define WLAN_CIPHER_SUITE_GCMP_256 0x000fac09\nstruct ieee80211_hdr { uint16_t frame_control,duration; uint8_t addr1[6],addr2[6],addr3[6];uint16_t seq; } __packed;\nstatic bool ieee80211_is_mgmt(uint16_t fc){return !(fc&0xc);}\nstatic bool ieee80211_is_action(uint16_t fc){return (fc&0xfc)==0xd0;}\nstatic bool ieee80211_is_deauth(uint16_t fc){return (fc&0xfc)==0xc0;}\nstatic bool ieee80211_is_disassoc(uint16_t fc){return (fc&0xfc)==0xa0;}\nstatic bool ieee80211_has_protected(uint16_t fc){return fc&0x4000;}\nstatic bool ieee80211_is_nullfunc(uint16_t fc){return (fc&0xfc)==0x48;}\nstatic bool ieee80211_is_qos_nullfunc(uint16_t fc){return (fc&0xfc)==0xc8;}\nstatic bool is_multicast_ether_addr(const u8 *a){return a[0]&1;}\nstatic const u8 *ieee80211_get_DA(const struct ieee80211_hdr *h){return h->addr1;}\nstruct ieee80211_mmie_16 { u8 bytes[26]; };\nstruct ath10k_vif { uint32_t vdev_id; };\nstatic struct ath10k_vif vif={.vdev_id=0};\nstruct ieee80211_vif {void *drv_priv;};\nstatic struct ieee80211_vif iface={.drv_priv=&vif};\nstruct ath10k_skb_cb {struct ieee80211_vif *vif;uint32_t ucast_cipher,msdu_id;};\nstatic struct ath10k_skb_cb oracle_cb={.vif=&iface};\n#define ATH10K_SKB_CB(skb) (&oracle_cb)\n#define trace_ath10k_tx_hdr(...) ((void)0)\n#define trace_ath10k_tx_payload(...) ((void)0)\nstatic void skb_put(struct sk_buff *s,unsigned n){s->len+=n;}\nstatic void dev_kfree_skb(struct sk_buff *s){free(s->data);free(s);}\nstatic int ath10k_wmi_mgmt_tx_alloc_msdu_id(struct ath10k *ar,struct sk_buff *s,dma_addr_t p){return 0;}\n'
for name in ["wmi_mgmt_tx_hdr","wmi_mgmt_tx_cmd"]: base+=decl(h,"struct",name)+"\n"
base+=decl(t,"struct","wmi_tlv_mgmt_tx_cmd")+"\n"
base+=func(c,"ath10k_wmi_op_gen_mgmt_tx","struct sk_buff *")+"\n"+func(tc,"ath10k_wmi_tlv_op_gen_mgmt_tx_send","struct sk_buff *")+"\n"
base+='static void dump(const char *name,u32 id,struct sk_buff *s){printf("%s",name);for(int i=0;i<4;i++)printf(" %02x",(id>>(8*i))&255);for(size_t i=0;i<s->len;i++)printf(" %02x",s->data[i]);puts("");free(s->data);free(s);}\n'
base=base.replace('static int ath10k_wmi_mgmt_tx_alloc_msdu_id', 'static unsigned oracle_id;\nstatic int ath10k_wmi_mgmt_tx_alloc_msdu_id').replace('struct sk_buff *s,dma_addr_t p){return 0;}', 'struct sk_buff *s,dma_addr_t p){return oracle_id;}')
base+='\n#define MAX_SUPPORTED_RATES 128\n#define SM(v,f) (((v)<<f##_LSB)&f##_MASK)\n'
for name in ['WMI_PEER_ASSOC_INFO0_MAX_MCS_IDX_LSB','WMI_PEER_ASSOC_INFO0_MAX_MCS_IDX_MASK','WMI_PEER_ASSOC_INFO0_MAX_NSS_LSB','WMI_PEER_ASSOC_INFO0_MAX_NSS_MASK']:
 base+=re.search(r'(?m)^#define '+name+r'[^\n]*',h).group(0)+'\n'
for name in ['wmi_rate_set','wmi_rate_set_arg','wmi_vht_rate_set','wmi_vht_rate_set_arg','wmi_common_peer_assoc_complete_cmd','wmi_main_peer_assoc_complete_cmd','wmi_10_1_peer_assoc_complete_cmd','wmi_10_2_peer_assoc_complete_cmd','wmi_10_4_peer_assoc_complete_cmd','wmi_peer_assoc_complete_arg','wmi_vdev_up_cmd']:
 base+=decl(h,'struct',name)+'\n'
base+=decl(t,'struct','wmi_tlv_peer_assoc_cmd')+'\n'
for name in ['wmi_peer_flags','wmi_10x_peer_flags','wmi_10_2_peer_flags']:
 base+=decl(h,'enum',name)+'\n'
base+=decl(t,'enum','wmi_tlv_peer_flags')+'\n'
for name in ['ath10k_wmi_peer_assoc_fill','ath10k_wmi_peer_assoc_fill_main','ath10k_wmi_peer_assoc_fill_10_1','ath10k_wmi_peer_assoc_fill_10_2','ath10k_wmi_peer_assoc_fill_10_4']:
 base+=func(c,name,'void')+'\n'
base+=func(c,'ath10k_wmi_peer_assoc_check_arg','int')+'\n'
for name in ['ath10k_wmi_op_gen_peer_assoc','ath10k_wmi_10_1_op_gen_peer_assoc','ath10k_wmi_10_2_op_gen_peer_assoc','ath10k_wmi_10_4_op_gen_peer_assoc','ath10k_wmi_op_gen_vdev_up']:
 base+=func(c,name,'struct sk_buff *')+'\n'
for name in ['ath10k_wmi_tlv_op_gen_peer_assoc','ath10k_wmi_tlv_op_gen_vdev_up']:
 base+=func(tc,name,'struct sk_buff *')+'\n'
base+='''
int main(void){
 struct ath10k ar={0};
 for(unsigned secure=0;secure<2;secure++){
  struct sk_buff *f=ath10k_wmi_alloc_skb(&ar,128);f->len=30;
  memcpy(f->data,(u8[]){0xb0,0,0,0,2,8,9,10,11,12,2,3,4,5,6,7,2,8,9,10,11,12,0,0,0,0,1,0,0,0},30);
  if(!secure){
   oracle_id=0;
   dump("AUTH_MAIN",WMI_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
   dump("AUTH_10X",WMI_10X_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
   dump("AUTH_102",WMI_10_2_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
   dump("AUTH_104",WMI_10_4_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
   dump("AUTH_TLV",WMI_TLV_MGMT_TX_SEND_CMD,ath10k_wmi_tlv_op_gen_mgmt_tx_send(&ar,f,0x900000));
  }
  f->len=50;f->data[0]=0;f->data[24]=secure?0x31:0x21;f->data[25]=4;f->data[26]=5;f->data[27]=0;
  memcpy(f->data+28,(u8[]){0,4,'n','a','r','f',1,8,0x82,0x84,0x8b,0x96,12,18,24,36,50,4,48,72,96,108},22);
  if(secure){f->len=72;memcpy(f->data+50,(u8[]){48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0},22);}
  dump(secure?"AIR_SEC_MAIN":"AIR_OPEN_MAIN",WMI_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
  dump(secure?"AIR_SEC_10X":"AIR_OPEN_10X",WMI_10X_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
  dump(secure?"AIR_SEC_102":"AIR_OPEN_102",WMI_10_2_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
  dump(secure?"AIR_SEC_104":"AIR_OPEN_104",WMI_10_4_MGMT_TX_CMDID,ath10k_wmi_op_gen_mgmt_tx(&ar,f));
  oracle_id=1;
  dump(secure?"AIR_SEC_TLV":"AIR_OPEN_TLV",WMI_TLV_MGMT_TX_SEND_CMD,ath10k_wmi_tlv_op_gen_mgmt_tx_send(&ar,f,0x901000));
  struct wmi_peer_assoc_complete_arg arg={.addr={2,8,9,10,11,12},.peer_aid=7,.peer_caps=secure?0x431:0x421,.peer_listen_intval=1,.peer_num_spatial_streams=1,.peer_phymode=MODE_11G};
  arg.peer_legacy_rates.num_rates=12;memcpy(arg.peer_legacy_rates.rates,(u8[]){2,4,11,22,12,18,24,36,48,72,96,108},12);
  arg.peer_flags=WMI_PEER_AUTH|(secure?WMI_PEER_NEED_PTK_4_WAY:0);
  dump(secure?"SEC_MAIN":"OPEN_MAIN",WMI_PEER_ASSOC_CMDID,ath10k_wmi_op_gen_peer_assoc(&ar,&arg));
  arg.peer_flags=WMI_10X_PEER_AUTH|(secure?WMI_10X_PEER_NEED_PTK_4_WAY:0);
  dump(secure?"SEC_10X":"OPEN_10X",WMI_10X_PEER_ASSOC_CMDID,ath10k_wmi_10_1_op_gen_peer_assoc(&ar,&arg));
  arg.peer_flags=WMI_10_2_PEER_AUTH|(secure?WMI_10_2_PEER_NEED_PTK_4_WAY:0);
  dump(secure?"SEC_102":"OPEN_102",WMI_10_2_PEER_ASSOC_CMDID,ath10k_wmi_10_2_op_gen_peer_assoc(&ar,&arg));
  dump(secure?"SEC_104":"OPEN_104",WMI_10_4_PEER_ASSOC_CMDID,ath10k_wmi_10_4_op_gen_peer_assoc(&ar,&arg));
  arg.peer_flags=WMI_TLV_PEER_AUTH|(secure?WMI_TLV_PEER_NEED_PTK_4_WAY:0);
  dump(secure?"SEC_TLV":"OPEN_TLV",WMI_TLV_PEER_ASSOC_CMDID,ath10k_wmi_tlv_op_gen_peer_assoc(&ar,&arg));
 }
 dump("UP_MAIN",WMI_VDEV_UP_CMDID,ath10k_wmi_op_gen_vdev_up(&ar,0,7,(u8[]){2,8,9,10,11,12}));
 dump("UP_10X",WMI_10X_VDEV_UP_CMDID,ath10k_wmi_op_gen_vdev_up(&ar,0,7,(u8[]){2,8,9,10,11,12}));
 dump("UP_102",WMI_10_2_VDEV_UP_CMDID,ath10k_wmi_op_gen_vdev_up(&ar,0,7,(u8[]){2,8,9,10,11,12}));
 dump("UP_104",WMI_10_4_VDEV_UP_CMDID,ath10k_wmi_op_gen_vdev_up(&ar,0,7,(u8[]){2,8,9,10,11,12}));
 dump("UP_TLV",WMI_TLV_VDEV_UP_CMDID,ath10k_wmi_tlv_op_gen_vdev_up(&ar,0,7,(u8[]){2,8,9,10,11,12}));
 for(unsigned ofdm=0;ofdm<3;ofdm++){
  struct wmi_peer_assoc_complete_arg arg={.addr={2,8,9,10,11,12},.peer_aid=7,.peer_caps=0x421,.peer_listen_intval=1,.peer_num_spatial_streams=1,.peer_phymode=ofdm?MODE_11G:MODE_11B};
  arg.peer_legacy_rates.num_rates=1;arg.peer_legacy_rates.rates[0]=ofdm?12:2;
  if(ofdm==2){arg.peer_legacy_rates.num_rates=11;memcpy(arg.peer_legacy_rates.rates,(u8[]){2,4,11,22,12,18,24,36,48,72,96},11);}
  arg.peer_flags=WMI_PEER_AUTH;
  dump(ofdm==2?"DOWNGRADE_MAIN":ofdm?"OFDM_MAIN":"B_MAIN",WMI_PEER_ASSOC_CMDID,ath10k_wmi_op_gen_peer_assoc(&ar,&arg));
  arg.peer_flags=WMI_10X_PEER_AUTH;
  dump(ofdm==2?"DOWNGRADE_10X":ofdm?"OFDM_10X":"B_10X",WMI_10X_PEER_ASSOC_CMDID,ath10k_wmi_10_1_op_gen_peer_assoc(&ar,&arg));
  arg.peer_flags=WMI_10_2_PEER_AUTH;
  dump(ofdm==2?"DOWNGRADE_102":ofdm?"OFDM_102":"B_102",WMI_10_2_PEER_ASSOC_CMDID,ath10k_wmi_10_2_op_gen_peer_assoc(&ar,&arg));
  dump(ofdm==2?"DOWNGRADE_104":ofdm?"OFDM_104":"B_104",WMI_10_4_PEER_ASSOC_CMDID,ath10k_wmi_10_4_op_gen_peer_assoc(&ar,&arg));
  arg.peer_flags=WMI_TLV_PEER_AUTH;
  dump(ofdm==2?"DOWNGRADE_TLV":ofdm?"OFDM_TLV":"B_TLV",WMI_TLV_PEER_ASSOC_CMDID,ath10k_wmi_tlv_op_gen_peer_assoc(&ar,&arg));
 }
}
'''
(o/'oracle.c').write_text(base)
subprocess.run(['cc','-w',str(o/'oracle.c'),'-o',str(o/'oracle')],check=True)
out=subprocess.check_output([str(o/'oracle')],text=True)
(o/'oracle.txt').write_text(out)
actual={name:bytes.fromhex(raw) for name,raw in (line.split(maxsplit=1) for line in out.splitlines())}
if args.write:
    args.golden.write_text('// Complete native Linux C management/PEER_ASSOC/VDEV_UP generators.\n'+'\n'.join('const '+name+': &[u8] = &['+','.join(hex(b) for b in raw)+'];' for name,raw in actual.items())+'\n')
expected={name:bytes(int(x.strip(),0) for x in raw.split(',') if x.strip()) for name,raw in re.findall(r'const (\w+): &\[u8\] = &\[(.*?)\];',args.golden.read_text(),re.S)}
if actual != expected:
    for name in actual.keys() | expected.keys():
        if actual.get(name) != expected.get(name): print('MISMATCH',name)
    raise SystemExit(1)
provenance={"linux_tree":str(args.linux.resolve()),"linux_makefile":(args.linux/'Makefile').read_text().splitlines()[:6],"source_sha256":{name:hashlib.sha256((p/name).read_bytes()).hexdigest() for name in ['wmi.h','wmi-tlv.h','wmi.c','wmi-tlv.c']},"oracle_c_sha256":hashlib.sha256(base.encode()).hexdigest(),"fixtures":{name:{"length":len(value),"sha256":hashlib.sha256(value).hexdigest()} for name,value in actual.items()}}
(o/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
print(f'{len(actual)} complete Linux management/PEER_ASSOC/VDEV_UP fixtures match')
if args.artifacts: print('Artifacts:',o)
