# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
from pathlib import Path
import re, subprocess, tempfile
p=Path(__file__).parent
linux=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89')
source=(linux/'core.c').read_text();core=(linux/'core.h').read_text()
def structure(name):
 a=core.index('struct '+name+' {');b=core.index('\n}',a);end=core.index(';',b)+1
 return core[a:end]+'\n'
def function(name):
 m=re.search(r'^(?:static\s+)?(?:__le32|void)\s+'+name+r'\(',source,re.M);a=m.start();end=source.index('{',a)+1;depth=1
 while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[a:end]+'\n'
c='''/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c)2019-2022 Realtek Corporation. Extracted Linux command descriptor builders. */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(x) (1ULL<<(x))
#define GENMASK(h,l) ((~0ULL<<(l))&(~0ULL>>(63-(h))))
#define FIELD_PREP(m,v) (((uint64_t)(v)<<__builtin_ctzll(m))&(m))
#define cpu_to_le32(x) (x)
#define RTW89_DMA_H2C 12
#define RTW89_CORE_RX_TYPE_FWDL 14
#define RTW89_CORE_RX_TYPE_H2C 13
'''
header=(linux/'txrx.h').read_text()
c+='\n'.join(line for line in header.splitlines() if line.startswith('#define RTW89_TXWD_BODY') or line.startswith('#define AX_RXD_RPKT_'))+'\n'
for n in ['rtw89_tx_desc_info','rtw89_txwd_body','rtw89_txwd_info','rtw89_rxdesc_short']:c+=structure(n)
c+='struct rtw89_dev{int unused;};struct rtw89_core_tx_request{struct rtw89_tx_desc_info desc_info;};\n'
# Runtime WD-info is absent in FWCMD. These unreachable functions are stubbed;
# the unmodified core_fill function must return before calling any of them.
for n in range(5):c+=f'#define rtw89_build_txwd_info{n}(x) (abort(),0)\n'
for n in ['rtw89_core_tx_update_h2c_info','rtw89_build_txwd_body0','rtw89_build_txwd_body2','rtw89_build_txwd_body3','rtw89_core_fill_txdesc','rtw89_build_txwd_fwcmd0_v1','rtw89_core_fill_txdesc_fwcmd_v1']:c+=function(n)
c+='''int main(int argc,char**argv){if(argc!=4)return 2;unsigned chip=atoi(argv[1]);unsigned kind=atoi(argv[2]);unsigned size=atoi(argv[3]);
struct rtw89_core_tx_request request={0};request.desc_info.fw_dl=kind;request.desc_info.pkt_size=size;rtw89_core_tx_update_h2c_info(NULL,&request);
u8 bytes[24]={0};unsigned desc_size=chip==2?sizeof(struct rtw89_rxdesc_short):sizeof(struct rtw89_txwd_body);
if(chip==2)rtw89_core_fill_txdesc_fwcmd_v1(NULL,&request.desc_info,bytes);else rtw89_core_fill_txdesc(NULL,&request.desc_info,bytes);
for(unsigned i=0;i<desc_size;i++)printf("%u ",bytes[i]);puts("");return 0;}\n'''
artifacts=Path(tempfile.mkdtemp(prefix='rtw89-ch12-oracle-'));(artifacts/'oracle.c').write_text(c)
subprocess.run(['cc','-std=gnu11',str(artifacts/'oracle.c'),'-o',str(artifacts/'oracle')],check=True)
golden='// Extracted Linux C command descriptor outputs.\nconst GOLDEN:&[Case]=&[\n'
chips=['Rtl8852A','Rtl8852B','Rtl8852C','Rtl8851B']
for chip in range(4):
 for kind in range(2):
  for length in [1,72,2020]:
   output=subprocess.check_output([str(artifacts/'oracle'),str(chip),str(kind),str(length)]).decode().split()
   golden+=f'Case{{chip:ChipId::{chips[chip]},kind:Kind::{"Section" if kind else "Header"},length:{length},descriptor:&['+','.join(output)+']},\n'
golden+='];\n';(p/'golden.rs').write_text(golden)
print('24 extracted Linux descriptor cases',artifacts/'oracle.c')
