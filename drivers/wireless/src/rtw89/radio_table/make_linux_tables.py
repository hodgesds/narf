#!/usr/bin/env python3
"""Compile actual RTL8852B PHY tables and original headline/branch selection."""
from pathlib import Path
import argparse,hashlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--linux',type=Path,default=Path('/usr/src/linux/drivers/net/wireless/realtek/rtw89'))
p.add_argument('--check',action='store_true');a=p.parse_args();d=Path(__file__).parent
tables=(a.linux/'rtw8852b_table.c').read_text();phy=(a.linux/'phy.c').read_text();header=(a.linux/'phy.h').read_text()
names=['bb_regs','bb_reg_gain','radioa_regs','radiob_regs','nctl_regs'];short=['BB','GAIN','RF_A','RF_B','NCTL']
original=[]
for name in names:
    m=re.search(r'^static const struct rtw89_reg2_def rtw89_8852b_phy_'+name+r'\[\] = \{.*?^\};',tables,re.M|re.S)
    if not m:raise RuntimeError(name)
    original.append(m.group(0))
functions=[]
for name in ['rtw89_phy_sel_headline','rtw89_phy_init_reg']:
    m=re.search(r'^static (?:int|void) '+name+r'\(',phy,re.M);end=phy.index('{',m.end())+1;depth=1
    while depth:depth+=(phy[end]=='{')-(phy[end]=='}');end+=1
    functions.append(phy[m.start():end])
definitions=re.search(r'#define get_phy_headline.*?#define PHY_COND_DONT_CARE[^\n]+',header,re.S).group(0)
prefix='''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
static bool rejected;
#define rtw89_err(...) ((void)(rejected=true))
#define rtw89_warn(...) ((void)(rejected=true))
enum rtw89_rf_path {RF_PATH_A,RF_PATH_B};
struct rtw89_reg2_def {u32 addr,data;};
struct rtw89_phy_table {const struct rtw89_reg2_def *regs;u32 n_regs;enum rtw89_rf_path rf_path;};
struct rtw89_dev {struct {u8 acv,cv;}hal;struct {u8 rfe_type;}efuse;};
static u64 digest;static u32 count;
static void record(struct rtw89_dev*d,const struct rtw89_reg2_def*r,enum rtw89_rf_path p,void*x){
 u32 v[]={r->addr,r->data};count++;for(u32 i=0;i<2;i++)for(u32 n=0;n<4;n++){digest^=(v[i]>>(8*n))&255;digest*=1099511628211ULL;}}
'''
main='int main(int argc,char**argv){if(argc==1){\n'
for name,label in zip(names,short):
    arr='rtw89_8852b_phy_'+name
    main+=f'printf("#[rustfmt::skip]\\npub(super) const {label}: &[Pair] = &[\\n");\n'
    main+=f'for(u32 i=0;i<sizeof({arr})/sizeof({arr}[0]);i++){{printf("Pair(0x%x,0x%x),",{arr}[i].addr,{arr}[i].data);if(i%4==3)puts("");}}puts("\\n];");\n'
main+='}else{puts("pub(super) const CASES: &[(usize,u8,u8,u32,u64,bool)] = &[");\n'
main+='u8 rfes[]={0,1,2,3,5,7,16,255};u8 cuts[]={0,1,2,15};\n'
for i,name in enumerate(names):
    arr='rtw89_8852b_phy_'+name
    main+=f'for(u32 r=0;r<8;r++)for(u32 c=0;c<4;c++){{struct rtw89_dev dev={{.hal.cv=cuts[c],.efuse.rfe_type=rfes[r]}};struct rtw89_phy_table t={{{arr},sizeof({arr})/sizeof({arr}[0]),0}};count=0;rejected=false;digest=14695981039346656037ULL;rtw89_phy_init_reg(&dev,&t,false,record,0);printf("({i},%u,%u,%u,0x%llx,%s),\\n",rfes[r],cuts[c],count,(unsigned long long)digest,rejected?"true":"false");}}\n'
main+='puts("];");}return 0;}\n'
body='\n'.join(original);callbacks='\n'.join(functions)
with tempfile.TemporaryDirectory(prefix='rtw89-b-phy-tables-') as td:
    td=Path(td);(td/'tables.c').write_text(prefix+definitions+'\n'+body+'\n'+callbacks+'\n'+main)
    subprocess.run(['cc','-std=gnu11','-O2',str(td/'tables.c'),'-o',str(td/'tables')],check=True)
    data=subprocess.check_output([str(td/'tables')]).decode()
    golden=subprocess.check_output([str(td/'tables'),'oracle']).decode()
sha=hashlib.sha256((body+callbacks+definitions).encode()).hexdigest()
for path,value in [(d.parent/'radio_tables_b.rs','use super::radio_table::Pair;\n'+data),(d/'golden.rs',golden)]:
    value='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Copyright(c) 2019-2020 Realtek Corporation\n// Original Linux table/selector SHA256 '+sha+'\n'+value
    if a.check:
        if path.read_text()!=value:raise SystemExit('B PHY table/selection differs: '+path.name)
    else:path.write_text(value)
