#!/usr/bin/env python3
"""Derive independent CH12/global DMA geometry from original Linux profiles.

The NARF initial download intentionally keeps both RX HCI layers disabled.
This emits profile constants, not a claim that Linux's RX-enabling runtime
sequence itself was executed. No Rust constants are read.
"""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--linux',type=Path,default=Path('/usr/src/linux'));p.add_argument('--check',action='store_true');a=p.parse_args();root=a.linux/'drivers/net/wireless/realtek/rtw89'
fields=['init_cfg_reg','txhci_en_bit','rxhci_en_bit','dma_io_stop','dma_stop1'];profiles=[];original=[]
for model in ['8852a','8852b','8852c','8851b']:
    text=(root/('rtw'+model+'e.c')).read_text();entries=[]
    for field in fields:
        value=re.search(r'\.'+field+r'\s*=\s*(.*?),\n',text,re.S).group(1);entries.append('.'+field+'='+value);original.append(value)
    chip=(root/('rtw'+model+'.c')).read_text();hci=re.search(r'\.hci_func_en_addr\s*=\s*(.*?),\n',chip).group(1);original.append(hci)
    profiles.append('static const struct profile p'+model+'={'+','.join(entries)+',.hci='+hci+'};')
defs={}
for name in ['pci.h','reg.h']:
    lines=iter((root/name).read_text().splitlines())
    for line in lines:
        m=re.match(r'#define\s+(\w+)\s+',line)
        if m:
            body=[line]
            while body[-1].endswith('\\'):body.append(next(lines))
            defs[m.group(1)]='\n'.join(body)
needed=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b','\n'.join(profiles)))&defs.keys();needed|={'B_AX_STOP_WPDMA','B_AX_STOP_CH12','B_AX_HCI_TXDMA_EN','B_AX_HCI_RXDMA_EN'}
while True:
    more=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b','\n'.join(defs[n] for n in needed)))&defs.keys()
    if more<=needed:break
    needed|=more
code='#include <stdint.h>\n#include <stdio.h>\ntypedef uint32_t u32;\n#define BIT(n) (1U<<(n))\n#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))\n'+ '\n'.join(defs[n] for n in sorted(needed))+r'''
struct reg{u32 addr,mask;};struct profile{u32 init_cfg_reg,txhci_en_bit,rxhci_en_bit,hci;struct reg dma_io_stop,dma_stop1;};
'''+ '\n'.join(profiles)+r'''
int main(void){const struct profile*p[]={&p8852a,&p8852b,&p8852c,&p8851b};
 puts("const CASES:&[Case]=&[");for(int i=0;i<4;i++)printf("Case{chip:ChipId::%s,init:0x%x,tx:0x%x,rx:0x%x,hci:0x%x,tx_internal:0x%x,rx_internal:0x%x,io_address:0x%x,io_stop:0x%x,stop_address:0x%x,channels:0x%x,wpdma:0x%x,fw:0x%x},\n",(const char*[]){"Rtl8852A","Rtl8852B","Rtl8852C","Rtl8851B"}[i],p[i]->init_cfg_reg,p[i]->txhci_en_bit,p[i]->rxhci_en_bit,p[i]->hci,B_AX_HCI_TXDMA_EN,B_AX_HCI_RXDMA_EN,p[i]->dma_io_stop.addr,p[i]->dma_io_stop.mask,p[i]->dma_stop1.addr,p[i]->dma_stop1.mask,B_AX_STOP_WPDMA,B_AX_STOP_CH12);puts("];");}
'''
with tempfile.TemporaryDirectory() as td:
    td=Path(td);(td/'oracle.c').write_text(code);subprocess.run(['cc','-O2','-o',str(td/'oracle'),str(td/'oracle.c')],check=True);result=subprocess.check_output([str(td/'oracle')]).decode()
value='// Original Linux AX DMA/profile expression SHA256 '+hashlib.sha256('\n'.join(original).encode()).hexdigest()+'\n'+result;path=Path(__file__).with_name('golden.rs')
if a.check:
    if path.read_text()!=value:raise SystemExit('DMA profile geometry differs')
else:path.write_text(value)
