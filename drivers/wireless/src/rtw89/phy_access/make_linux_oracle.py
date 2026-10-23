#!/usr/bin/env python3
"""Build Linux MDIO and DBI helpers against inert completion/register models."""
from pathlib import Path
import subprocess,sys,tempfile,re,hashlib
linux=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/usr/src/linux')
pci=linux/'drivers/net/wireless/realtek/rtw89/pci.c';code=pci.read_text()
header=(pci.with_suffix('.h')).read_text()
def function(name):
    at=code.index(name+'(');start=code.rfind('\nstatic',0,at)+1;a=code.index('{',at);end=a+1;depth=1
    while depth:
        depth+=(code[end]=='{')-(code[end]=='}');end+=1
    return code[start:end]
body='\n'.join(function(n) for n in ['rtw89_pci_check_mdio','rtw89_read16_mdio','rtw89_write16_mdio','rtw89_write16_mdio_mask','rtw89_dbi_write8','rtw89_dbi_read8'])
symbols=set(re.findall(r'\b(?:[RB]_AX_|MDIO_PG|RTW89_PCI_)[A-Z0-9_]*\b',body))
defs='\n'.join(s for s in header.splitlines() if s.startswith('#define ') and s.split()[1] in symbols)
pre=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define PCIE_PHY_GEN1 0
#define PCIE_PHY_GEN2 1
#define EINVAL 22
#define __ffs(v) __builtin_ctz(v)
#define rtw89_err(...) ((void)0)
#define read_poll_timeout(op,v,cond,interval,budget,delay,...) ({v=op(__VA_ARGS__);(cond)?0:-110;})
#define read_poll_timeout_atomic read_poll_timeout
struct rtw89_dev {int unused;};
static u8 mem[65536], config[4096];static u16 rac[4][32];
static u16 raw16(u32 a){u16 v;memcpy(&v,mem+a,2);return v;}
static u8 rtw89_read8(struct rtw89_dev*d,u32 a){if(a==0x1092&&mem[a]){u16 f=raw16(0x1090);if(mem[a]&1){unsigned byte=__builtin_ctz(f>>12);config[(f&0xffc)+byte]=mem[0x1094+byte];}if(mem[a]&2)memcpy(mem+0x1098,config+(f&0xffc),4);mem[a]=0;}return mem[a];}
static u16 rtw89_read16(struct rtw89_dev*d,u32 a){u16 v=raw16(a);if(a==0x10a0&&(v&0x300)){unsigned page=(v>>12)&3,reg=v&31;if(v&0x100)rac[page][reg]=raw16(0x10a4);if(v&0x200){u16 data=rac[page][reg];memcpy(mem+0x10a6,&data,2);}v&=~0x300;memcpy(mem+a,&v,2);}return v;}
static void rtw89_write8(struct rtw89_dev*d,u32 a,u8 v){printf("(%u,0x%x,0x%x),",8,a,v);mem[a]=v;}
static void rtw89_write16(struct rtw89_dev*d,u32 a,u16 v){printf("(%u,0x%x,0x%x),",16,a,v);memcpy(mem+a,&v,2);}
static void rtw89_write16_set(struct rtw89_dev*d,u32 a,u16 m){rtw89_write16(d,a,rtw89_read16(d,a)|m);}
static u16 u16_replace_bits(u16 old,u16 v,u16 mask){return (old&~mask)|((v<<__builtin_ctz(mask))&mask);}
static u16 u16_encode_bits(u16 v,u16 mask){return (v<<__builtin_ctz(mask))&mask;}
'''
main=r'''
static void init(u8 seed){memset(mem,seed,sizeof(mem));memset(config,seed,sizeof(config));for(int a=0;a<4;a++)for(int b=0;b<32;b++)rac[a][b]=seed*257;mem[0x1092]=0;u16 cfg=raw16(0x10a0)&~0x300;memcpy(mem+0x10a0,&cfg,2);}
int main(void){struct rtw89_dev dev={0};
 for(int seed=0;seed<2;seed++)for(int op=0;op<3;op++)for(int speed=0;speed<2;speed++)for(int p=0;p<4;p++){
  u8 addr=(u8[]){0,31,32,63}[p];init(seed?0xa5:0);u16 out=0;int ret;
  printf("Case{operation:%d,address:0x%x,speed:%d,seed:%d,result:",op,addr,speed,seed?0xa5:0);
  /* Compute expected result independently; printf keeps trace immediately in the case. */
  printf("0x%x,trace:&[",op==0?(seed?0xa5a5:0):0);
  if(op==0)ret=rtw89_read16_mdio(&dev,addr,speed,&out);
  else if(op==1)ret=rtw89_write16_mdio(&dev,addr,0x5ac3,speed);
  else ret=rtw89_write16_mdio_mask(&dev,addr,0xf0,0xb,speed);
  if(ret)return 2;printf("]},\n");
 }
 for(int seed=0;seed<2;seed++)for(int op=3;op<5;op++)for(int p=0;p<5;p++){
  u16 addr=(u16[]){0x70c,0x70d,0x70e,0x70f,0xfff}[p];u8 out=0;init(seed?0xa5:0);
  printf("Case{operation:%d,address:0x%x,speed:0,seed:%d,result:0x%x,trace:&[",op,addr,seed?0xa5:0,op==3?(seed?0xa5:0):0);
  int ret=op==3?rtw89_dbi_read8(&dev,addr,&out):rtw89_dbi_write8(&dev,addr,0x5a);
  if(ret)return 2;printf("]},\n");
 }return 0;}
'''
with tempfile.TemporaryDirectory() as td:
 p=Path(td);(p/'oracle.c').write_text(pre+'\n'+defs+'\n'+body+'\n'+main)
 subprocess.run(['cc','-O2','-o',str(p/'oracle'),str(p/'oracle.c')],check=True)
 result=subprocess.check_output([str(p/'oracle')]).decode()
out='// Linux pci.c extracted helper SHA256 '+hashlib.sha256(body.encode()).hexdigest()+'\nconst CASES:&[Case]=&[\n'+result+'];\n'
Path(__file__).with_name('golden.rs').write_text(out)
