from pathlib import Path
import re, subprocess, tempfile
base=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw88')
s=(base/'mac.c').read_text()
functions=['check_firmware_size','wlan_cpu_enable','download_firmware_reg_backup','download_firmware_reset_platform','download_firmware_reg_restore','send_firmware_pkt_rsvd_page','send_firmware_pkt','iddma_enable','iddma_download_firmware','check_fw_checksum','download_firmware_to_mem','start_download_firmware','download_firmware_validate','download_firmware_end_flow','__rtw_download_firmware']
def function(name):
 m=re.search(r'\b'+name+r'\s*\(',s);a=s.rfind('\nstatic ',0,m.start())+1;b=s.index('{',m.end());end=b+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[a:end]
body='\n'.join(function(name) for name in functions)
needed=set(re.findall(r'\b(?:REG_|BIT_|BTI_|FW_|OCPBASE_|ILLEGAL_|SDIO_)[A-Z0-9_]+\b',body))
definitions={}
for header in ['reg.h','mac.h','fw.h','sdio.h']:
 lines=(base/header).read_text().splitlines();index=0
 while index<len(lines):
  line=lines[index];index+=1
  if line.startswith('#define '):
   name=line.split()[1].split('(')[0];definition=line
   while definition.endswith('\\'):
    definition+='\n'+lines[index];index+=1
   definitions[name]=definition
while True:
 more=set()
 for name in needed:
  more.update(re.findall(r'\b(?:REG_|BIT_|BTI_|FW_|OCPBASE_|ILLEGAL_|SDIO_)[A-Z0-9_]+\b',definitions.get(name,'')))
 if more<=needed:break
 needed|=more
pre=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define le32_to_cpu(v) (v)
#define GFP_KERNEL 0
#define EINVAL 22
#define EBUSY 16
#define ENOMEM 12
#define DLFW_RESTORE_REG_NUM 6
#define TX_DESC_SIZE 48
#define RTW_HCI_TYPE_PCIE 1
#define RTW_HCI_TYPE_SDIO 2
#define RTW_HCI_TYPE_USB 3
#define RTW_DMA_MAPPING_HIGH 3
#define RTW_FLAG_FW_RUNNING 0
#define WARN(...) ((void)0)
#define rtw_err(...) ((void)0)
#define set_bit(...) ((void)0)
struct rtw_fw_hdr {u16 signature;u8 category,function;u16 version;u8 subversion,subindex;u32 rsvd,feature;u8 month,day,hour,min;u16 year,rsvd3;u8 mem_usage,rsvd4[3];u16 h2c_fmt_ver,rsvd5;u32 dmem_addr,dmem_size,rsvd6,rsvd7,imem_size,emem_size,emem_addr,imem_addr;} __attribute__((packed));
struct rtw_chip_info{u32 tx_pkt_desc_sz;void*ltecoex_addr;};
struct rtw_dev{const struct rtw_chip_info*chip;struct{u8 last_box_num,seq;}h2c;int flags;};
struct firmware{const u8*data;u32 size;};struct rtw_fw_state{const struct firmware*firmware;};
struct rtw_backup_info{u8 len;u32 reg,val;};
static u8 regs[0x1400];
static void trace(int op,int width,u32 reg,u32 value){printf("(%d,%d,0x%x,0x%x),\n",op,width,reg,value);}
static u8 rtw_read8(struct rtw_dev*d,u32 r){trace(0,8,r,0);return regs[r];}
static u16 rtw_read16(struct rtw_dev*d,u32 r){u16 v;memcpy(&v,regs+r,2);trace(0,16,r,0);return v;}
static u32 rtw_read32(struct rtw_dev*d,u32 r){u32 v;memcpy(&v,regs+r,4);trace(0,32,r,0);if(r==0x1208)v&=~BIT(31);if(r==0x80&&(v&BIT(14)))v|=BIT(15);return v;}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){trace(1,8,r,v);regs[r]=v;}
static void rtw_write16(struct rtw_dev*d,u32 r,u16 v){trace(1,16,r,v);memcpy(regs+r,&v,2);}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){trace(1,32,r,v);memcpy(regs+r,&v,4);}
static void rtw_write8_clr(struct rtw_dev*d,u32 r,u8 mask){u8 v=rtw_read8(d,r);rtw_write8(d,r,v&~mask);}
static void rtw_write8_set(struct rtw_dev*d,u32 r,u8 mask){u8 v=rtw_read8(d,r);rtw_write8(d,r,v|mask);}
static int rtw_hci_type(struct rtw_dev*d){return RTW_HCI_TYPE_PCIE;}
static bool check_hw_ready(struct rtw_dev*d,u32 r,u32 mask,u32 target){return (rtw_read32(d,r)&mask)==target;}
static void*kmemdup(const void*p,u32 n,int flag){void*q=malloc(n);memcpy(q,p,n);return q;}
static void kfree(void*p){free(p);}
static int rtw_fw_write_data_rsvd_page(struct rtw_dev*d,u16 page,u8*p,u32 n){trace(2,0,0,n);return 0;}
static bool ltecoex_read_reg(struct rtw_dev*d,u32 r,u32*out){trace(3,0,0,0);*out=0x12345678;return true;}
static bool ltecoex_reg_write(struct rtw_dev*d,u32 r,u32 v){trace(4,0,0,v);return true;}
static void rtw_hci_setup(struct rtw_dev*d){trace(5,0,0,0);}
static void rtw_restore_reg(struct rtw_dev*d,struct rtw_backup_info*b,u8 n){for(int i=0;i<n;i++){if(b[i].len==1)rtw_write8(d,b[i].reg,b[i].val);else if(b[i].len==2)rtw_write16(d,b[i].reg,b[i].val);else rtw_write32(d,b[i].reg,b[i].val);}}
'''
image=bytearray(64+4093+8+9+8+5+8);image[:2]=b'\x22\x88';image[4:7]=b'\x09\x00\x09';image[0x18]=0x10
for offset,value in [(0x20,0x80200000),(0x24,4093),(0x30,9),(0x34,5),(0x38,0x80100000),(0x3c,0x80030000)]:image[offset:offset+4]=value.to_bytes(4,'little')
post='\nstatic const u8 bytes[]={'+','.join(map(str,image))+'};\n'+r'''
int main(){regs[3]=255;regs[0x1d]=0xa5;regs[0x10d]=0x36;regs[0x100]=0x30;regs[0x550]=0x19;struct rtw_chip_info c={48,(void*)1};struct rtw_dev d={.chip=&c};struct firmware f={bytes,sizeof(bytes)};struct rtw_fw_state state={&f};return __rtw_download_firmware(&d,&state);}
'''
with tempfile.TemporaryDirectory() as temp:
 source=Path(temp)/'oracle.c';exe=Path(temp)/'oracle';source.write_text(pre+'\n'+'\n'.join(definitions[name] for name in sorted(needed) if name in definitions)+'\n'+body+post)
 subprocess.run(['cc','-O2','-o',str(exe),str(source)],check=True)
 output=subprocess.check_output([str(exe)]).decode()
Path(__file__).with_name('golden.rs').write_text('// Actual Linux mac.c firmware callbacks; reserved-page PCI DMA is a separate backend.\nconst LINUX_FW:&[(u8,u8,u16,u32)]=&[\n'+output+'];\n')
