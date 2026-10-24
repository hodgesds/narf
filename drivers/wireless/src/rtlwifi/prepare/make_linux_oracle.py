from pathlib import Path
import re,subprocess,tempfile
base=Path('/usr/src/linux/drivers/net/wireless/realtek/rtlwifi/rtl8188ee')
s=(base/'hw.c').read_text();reg=(base/'reg.h').read_text()
def function(name):
 a=s.index('static bool '+name+'(');b=s.index('{',a);end=b+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[a:end]
body='\n'.join(function(n) for n in ['_rtl88ee_llt_write','_rtl88ee_llt_table_init'])
names=set(re.findall(r'\b(?:REG_|_LLT_|POLLING_)[A-Z0-9_]+\b',body));defs=[]
# Discover the real init_mac publication order and compile those exact EE
# register definitions too. A different family's named constants are not an
# independent oracle, even if both sides of a Rust test import those names.
bases=re.findall(r'rtl_write_dword\(rtlpriv,\s*(REG_[A-Z0-9_]+_DESA),',function('_rtl88ee_init_mac'))
assert len(bases)==8 and bases[-1]=='REG_RX_DESA'
names.update(bases)
for line in reg.splitlines():
 if line.startswith('#define') and line.split()[1].split('(')[0] in names: defs.append(line)
pre=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint32_t u32;
struct ieee80211_hw{};struct rtl_priv{};
#define rtl_priv(hw) ((struct rtl_priv*)0)
#define pr_err(...) ((void)0)
static void rtl_write_byte(struct rtl_priv*p,u32 a,u8 v){printf("(8,0x%x,0x%x),\n",a,v);}
static void rtl_write_dword(struct rtl_priv*p,u32 a,u32 v){printf("(32,0x%x,0x%x),\n",a,v);}
static u32 rtl_read_dword(struct rtl_priv*p,u32 a){return 0;}
'''
with tempfile.TemporaryDirectory() as temp:
 tail='printf("BASES:");'+''.join('printf("0x%x,",'+name+');' for name in bases)
 c=Path(temp)/'oracle.c';exe=Path(temp)/'oracle';c.write_text(pre+'\n'+'\n'.join(defs)+'\n'+body+'\nint main(){struct ieee80211_hw h;_rtl88ee_llt_table_init(&h);'+tail+'return 0;}')
 subprocess.run(['cc','-O2','-o',str(exe),str(c)],check=True)
 output=subprocess.check_output([str(exe)]).decode()
trace,base_values=output.split('BASES:')
values=base_values.strip(',').split(',')
Path(__file__).with_name('golden.rs').write_text('// Extracted actual Linux EE hw.c LLT/init_mac and reg.h.\nconst LINUX_LLT:&[(u8,u16,u32)]=&[\n'+trace+'];\nconst LINUX_TX_BASES:[u16;7]=['+','.join(values[:-1])+'];\nconst LINUX_RX_BASE:u16='+values[-1]+';\n')
