"""Execute original Linux RTL8188EE descriptor setters and TX polling.

The host-selected profile is one legacy frame, host sequence, software crypto,
no early mode/aggregation. Expectations do not call a Rust packet encoder.
"""
from pathlib import Path
import hashlib
import re
import subprocess
import tempfile

base = Path('/usr/src/linux/drivers/net/wireless/realtek/rtlwifi')
header = (base / 'rtl8188ee/trx.h').read_text()
source = (base / 'rtl8188ee/trx.c').read_text()
names = ['pkt_size', 'offset', 'bmc', 'last_seg', 'first_seg', 'own', 'macid',
         'queue_sel', 'rate_id', 'sec_type', 'seq', 'hwseq_en', 'use_rate',
         'linip',
         'disable_fb', 'tx_rate', 'data_rate_fb_limit', 'rts_rate_fb_limit',
         'tx_buffer_size', 'tx_buffer_address', 'next_desc_address']
def function(text, name):
    match = re.search(r'(?:static inline )?void\s+' + name + r'\s*\(', text)
    start = text.index('{', match.end())
    end, depth = start + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]
pre = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8; typedef u32 __le32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define cpu_to_le32(v) (v)
#define le32p_replace_bits(p,v,m) (*(p)=(*(p)&~(m))|(((v)<<__builtin_ctz(m))&(m)))
struct ieee80211_hw {int unused;}; struct rtl_priv {int unused;};
typedef u16 __le16;typedef uint64_t dma_addr_t;
struct sk_buff{u8 *data;u32 len;};struct ieee80211_hdr{__le16 frame_control;};
struct rtl_pci{struct {int dev;} *pdev;};static struct rtl_pci pci;
#define rtl_pcipriv(hw) (&pci)
#define rtl_pcidev(p) (p)
#define rtl_get_hdr(s) ((struct ieee80211_hdr *)(s)->data)
#define DMA_TO_DEVICE 0
#define RT_PRINT_DATA(...) ((void)0)
#define rtl_dbg(...) ((void)0)
static dma_addr_t dma_map_single(void *d,void *p,u32 n,int dir){return 0x123400;}
static int dma_mapping_error(void *d,dma_addr_t a){return 0;}
static int ieee80211_is_data_qos(__le16 fc){return (fc&0x8c)==0x88;}
static struct rtl_priv priv;
#define rtl_priv(hw) (&priv)
static void rtl_write_word(struct rtl_priv *p,u16 reg,u16 value){printf("%u,",value);}
'''
defs = '\n'.join(function(header, 'set_tx_desc_' + n) for n in names)
defs += '\n'+function(header,'clear_pci_tx_desc_content')
poll = function(source, 'rtl88ee_tx_polling')
command=function(source,'rtl88ee_tx_fill_cmddesc')
main = r'''
static void descriptor(int data){u32 desc[16]={0};
set_tx_desc_pkt_size(desc,32);set_tx_desc_offset(desc,USB_HWDESC_HEADER_LEN);
set_tx_desc_first_seg(desc,1);set_tx_desc_last_seg(desc,1);set_tx_desc_own(desc,1);
set_tx_desc_queue_sel(desc,data?0:QSLT_MGNT);set_tx_desc_macid(desc,0);set_tx_desc_rate_id(desc,0);
set_tx_desc_sec_type(desc,0);set_tx_desc_seq(desc,0x123);set_tx_desc_hwseq_en(desc,0);
set_tx_desc_use_rate(desc,1);set_tx_desc_disable_fb(desc,1);set_tx_desc_tx_rate(desc,0);
set_tx_desc_data_rate_fb_limit(desc,31);set_tx_desc_rts_rate_fb_limit(desc,15);
set_tx_desc_tx_buffer_size(desc,32);set_tx_desc_tx_buffer_address(desc,0x123400);
set_tx_desc_next_desc_address(desc,0x223400);
printf("const LINUX_%s:[u32;12]=[",data?"DATA":"MANAGEMENT");
for(unsigned i=0;i<12;i++)printf("0x%x,",desc[i]);puts("];");}
int main(void){struct ieee80211_hw hw;descriptor(0);descriptor(1);
u32 desc[16]={0};u8 body[768]={0x80};struct sk_buff skb={body,768};desc[10]=0x223400;
rtl88ee_tx_fill_cmddesc(&hw,(u8 *)desc,&skb);
printf("const LINUX_RESERVED_DESCRIPTOR:[u32;12]=[");for(unsigned i=0;i<12;i++)printf("0x%x,",desc[i]);puts("];");
printf("const LINUX_TX_BASES:[u16;7]=[0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x];\n",
 REG_BCNQ_DESA,REG_MGQ_DESA,REG_VOQ_DESA,REG_VIQ_DESA,REG_BEQ_DESA,REG_BKQ_DESA,REG_HQ_DESA);
printf("const LINUX_RX_BASE:u16=0x%x;\n",REG_RX_DESA);
printf("const LINUX_POLLS:[u16;10]=[");
for(int i=0;i<5;i++){rtl88ee_tx_polling(&hw,MGNT_QUEUE);rtl88ee_tx_polling(&hw,BE_QUEUE);}puts("];");}
'''
# Use the actual constant definitions, including the queue enumeration that
# differs from the driver's allocation-vector order.
constants = '\n'.join(line for text in [(base/'pci.h').read_text(), (base/'wifi.h').read_text(),
    (base/'rtl8188ee/reg.h').read_text(), header]
    for line in text.splitlines() if re.match(r'#define\s+(?:TX_DESC_SIZE|TX_DESC_NEXT_DESC_OFFSET|BE_QUEUE|MGNT_QUEUE|BEACON_QUEUE|REG_PCIE_CTRL_REG|REG_[A-Z0-9_]+_DESA|QSLT_MGNT|USB_HWDESC_HEADER_LEN)\s', line))
constants += '\nenum { ' + re.search(r'QSLT_MGNT\s*=\s*[^,]+', (base/'rtl8188ee/def.h').read_text()).group() + ' };\n'
constants += '\nenum { '+','.join(re.search(name+r'\s*=\s*[^,]+',(base/'rtl8188ee/def.h').read_text()).group() for name in ['QSLT_BEACON','DESC92C_RATE1M'])+' };\n'
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp)
    (path/'oracle.c').write_text(pre + constants + '\n' + defs + poll + command + main)
    subprocess.run(['cc', '-O2', '-o', str(path/'oracle'), str(path/'oracle.c')], check=True)
    result = subprocess.check_output([str(path/'oracle')]).decode()
Path(__file__).with_name('packet_golden.rs').write_text(
    '// Original Linux trx.h/trx.c sha256: ' + hashlib.sha256((header+source).encode()).hexdigest() + '\n' + result)
