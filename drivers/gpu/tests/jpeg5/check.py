#!/usr/bin/env python3
"""Check JPEG5 register definitions and unchanged Linux packet constructors."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

linux=Path(sys.argv[1] if len(sys.argv)>1 else '/usr/src/linux')
gpu=Path(__file__).resolve().parents[2]
native=linux/'drivers/gpu/drm/amd'
offsets=(native/'include/asic_reg/vcn/vcn_5_0_0_offset.h').read_text()
rust=(gpu/'src/amdgpu_jpeg_navi48.rs').read_text()
registers={
    'DLDO_CONFIG':'UVD_IPX_DLDO_CONFIG','DLDO_STATUS':'UVD_IPX_DLDO_STATUS',
    'POWER':'UVD_JPEG_POWER_STATUS','DB':'VCN_JPEG_DB_CTRL','PITCH':'UVD_JPEG_PITCH',
    'ADDR_CONFIG':'JPEG_DEC_GFX10_ADDR_CONFIG','WPTR':'UVD_JRBC_RB_WPTR',
    'CNTL':'UVD_JRBC_RB_CNTL','STATUS':'UVD_JRBC_STATUS','RPTR':'UVD_JRBC_RB_RPTR',
    'SIZE':'UVD_JRBC_RB_SIZE','VMID':'UVD_LMI_JRBC_RB_VMID',
    'BASE_LO':'UVD_LMI_JRBC_RB_64BIT_BAR_LOW','BASE_HI':'UVD_LMI_JRBC_RB_64BIT_BAR_HIGH',
    'CLEAN':'UVD_JMI_CLEAN_STATUS','JMI':'UVD_JMI_CNTL','IRQ':'JPEG_SYS_INT_EN',
    'CG_GATE':'JPEG_CGC_GATE','CG_CTRL':'JPEG_CGC_CTRL',
}
for name,reg in registers.items():
    actual=int(re.search(r'const '+name+r':\s*u32\s*=\s*(\w+)',rust)[1],0)
    expected=int(re.search(r'#define reg'+reg+r'\s+(\w+)',offsets)[1],0)
    bank=int(re.search(r'#define reg'+reg+r'_BASE_IDX\s+(\w+)',offsets)[1],0)
    assert actual==expected and bank==1,(name,actual,expected,bank)
masks=(native/'include/asic_reg/vcn/vcn_5_0_0_sh_mask.h').read_text()
def mask(name):
    return int(re.search(r'#define '+name+r'\s+(0x[0-9a-fA-F]+)',masks)[1],0)
clean=sum(mask('UVD_JMI_CLEAN_STATUS__'+name+'_MASK') for name in [
    'LMI_READ_CLEAN','LMI_READ_CLEAN_RAW','LMI_WRITE_CLEAN','LMI_WRITE_CLEAN_RAW',
    'DJPEG_CORE0_READ_CLEAN','DJPEG_CORE0_WRITE_CLEAN'])
expected_masks={
    'CLEAN_VALUE':clean,'CLEAN_MASK':clean|mask('UVD_JMI_CLEAN_STATUS__MC_WRITE_PENDING_MASK'),
    'CG_MODES':mask('JPEG_CGC_CTRL__JPEG0_DEC_MODE_MASK')|mask('JPEG_CGC_CTRL__JPEG_ENC_MODE_MASK'),
    'CG_GATES':sum(mask('JPEG_CGC_GATE__'+n+'_MASK') for n in ['JPEG0_DEC','JPEG_ENC','JMCIF','JRBBM']),
}
for name,expected in expected_masks.items():
    actual=int(re.search(r'const '+name+r':\s*u32\s*=\s*(\w+)',rust)[1],0)
    assert actual==expected,(name,actual,expected)
messages=(native/'pm/swsmu/inc/pmfw_if/smu_v14_0_2_ppsmc.h').read_text()
for name,expected in [('PowerUpJpeg',0x2c),('PowerDownJpeg',0x2d)]:
    assert int(re.search(r'#define PPSMC_MSG_'+name+r'\s+(\w+)',messages)[1],0)==expected
pieces=[]
for file,names in [
    ('jpeg_v4_0_3.c',['jpeg_v4_0_3_dec_ring_insert_start','jpeg_v4_0_3_dec_ring_insert_end',
        'jpeg_v4_0_3_dec_ring_emit_fence','jpeg_v4_0_3_dec_ring_emit_ib','jpeg_v4_0_3_dec_ring_emit_wreg']),
    ('amdgpu_jpeg.c',['amdgpu_jpeg_dec_set_reg']),
]:
    source=(native/'amdgpu'/file).read_text()
    pieces.append(source[:source.index('#include')])
    for name in names:
        match=re.search(r'^(?:(?:static )?(?:void|int)\s+)?'+name+r'\s*\(',source,re.M)
        if not match:
            raise SystemExit('Missing Linux function '+name)
        start=match.start() if match[0].startswith(('void','static','int')) else source.rfind('void',0,match.start())
        opening=source.index('{',match.start())
        depth,end=1,opening+1
        while depth:
            depth+=(source[end]=='{')-(source[end]=='}');end+=1
        pieces.append(source[start:end])
header=(native/'amdgpu/jpeg_v4_0_3.h').read_text()
defs=re.findall(r'^#define\s+(?:regUVD_|JRBC_DEC_)[^\n]+',header,re.M)
pieces.insert(0,header[:header.index('#ifndef')]+'\n'+'\n'.join(defs))
soc=(native/'amdgpu/soc15d.h').read_text()
begin=soc.index('#define\tPACKETJ_CONDITION_CHECK0')
end=soc.index('#define CP_PACKETJ_NOP',begin)
pieces.insert(0,soc[:soc.index('#ifndef')]+'\n'+soc[begin:end])
with tempfile.TemporaryDirectory(prefix='narf-jpeg5-') as temp:
    out=Path(temp)
    (out/'native_jpeg.h').write_text('\n'.join(pieces)+'\n')
    harness=r'''
extern crate alloc;
#[path="WORDS"] mod w;
fn dump(n:&str,words:&[u32]) {print!("{n}");for v in words {print!(" {v:08x}");}println!();}
fn main() {
    dump("direct",&w::direct());dump("ib",&w::kernel_ib());
    dump("frame",&w::ib_frame(0x810001000,0x810003000,0x810002000,9,16));
}
'''.replace('WORDS',str(gpu/'src/amdgpu_jpeg_navi48_words.rs'))
    (out/'harness.rs').write_text(harness)
    subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
        '-Wno-sign-compare','-I'+str(out),str(Path(__file__).with_name('reference.c')),
        '-o',str(out/'native')],check=True)
    subprocess.run(['rustc','--edition=2021',str(out/'harness.rs'),'-o',str(out/'rust')],check=True)
    assert subprocess.check_output([str(out/'native')])==subprocess.check_output([str(out/'rust')])
print('JPEG5 registers and all transport words match unchanged Linux constructors.')
