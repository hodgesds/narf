#!/usr/bin/env python3
"""Check versioned AVC session headers against unchanged Mesa VCN5 code."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

p=argparse.ArgumentParser(description=__doc__);p.add_argument('mesa',type=Path);a=p.parse_args()
m=a.mesa;gpu=Path(__file__).resolve().parents[2];mm=m/'src/gallium/drivers/radeonsi/mm'
info=(m/'src/amd/common/ac_gpu_info.c').read_text();v5=(mm/'radeon_vcn_enc_5_0.c').read_text();v12=(mm/'radeon_vcn_enc_1_2.c').read_text();header=(mm/'radeon_vcn_enc.h').read_text()
start=v12.index('static void radeon_enc_session_info(');opening=v12.index('{',start);depth=1;end=opening+1
while depth:depth+=(v12[end]=='{')-(v12[end]=='}');end+=1
session=v12[start:end]
# Actual assignments consumed by the real initializer replay, then the exact
# VCN5 interface-selection block and session-info constructor. No changed
# firmware constants or hand-entered expected interface values in C.
fw=info[info.index('         info->vcn_dec_version ='):info.index('         info->vcn_fw_revision =')];fw+=info[info.index('         info->vcn_fw_revision ='):info.index(';',info.index('         info->vcn_fw_revision ='))+1]
start=v5.index('   minor_version =');end=v5.index(';',v5.index('enc->enc_pic.session_info.interface_version =',start))+1;selection=v5[start:end]
constants='\n'.join(re.findall(r'^#define RENCODE_FW_INTERFACE_(?:MAJOR|MINOR)_VERSION[^\n]*',v5,re.M))
macros=header[header.index('#define RADEON_ENC_CS'):header.index('#define RADEON_ENC_ADDR_SWAP')]
c=v12[:v12.index('#include')]+v5[:v5.index('#include')]+'''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "ac_vcn_enc.h"
#define MIN2(a,b) ((a)<(b)?(a):(b))
#define RADEON_USAGE_READ 1
#define RADEON_USAGE_WRITE 2
#define RADEON_USAGE_READWRITE 3
struct info {unsigned vcn_dec_version,vcn_enc_major_version,vcn_enc_minor_version,vcn_fw_revision;};
struct screen {struct info info;};
struct resource {uint64_t buf;unsigned domains;};
struct radeon_encoder {struct {struct {uint32_t *buf;unsigned cdw;}current;}cs;unsigned total_task_size;struct {unsigned session_info;}cmd;struct {rvcn_enc_session_info_t session_info;}enc_pic;struct resource *si;};
static void radeon_enc_add_buffer(struct radeon_encoder*enc,uint64_t address,unsigned usage,unsigned domain,unsigned offset){assert(usage==3&&domain==1);address+=offset;enc->cs.current.buf[enc->cs.current.cdw++]=address>>32;enc->cs.current.buf[enc->cs.current.cdw++]=address;}
'''+constants+'\n'+macros+'\n'+session+'''
int main(int argc,char**argv){assert(argc==3);uint32_t vidip_fw_version=strtoul(argv[1],NULL,0);uint64_t address=strtoull(argv[2],NULL,0);struct screen screen={0},*sscreen=&screen;struct info*info=&screen.info;struct resource resource={address,1};uint32_t words[16]={0};struct radeon_encoder encoder={.cs.current={words,0},.cmd.session_info=1,.si=&resource},*enc=&encoder;uint32_t minor_version;
'''+fw+'\n'+selection+'''
radeon_enc_session_info(enc);printf("%08x",enc->enc_pic.session_info.interface_version);for(unsigned i=0;i<enc->cs.current.cdw;i++)printf(" %08x",words[i]);puts("");}
'''
# The packet ID is the actual VCN command-table constant, not a replacement
# of a differing Rust field with our own expected word.
command=(m/'src/amd/common/ac_vcn_enc.c').read_text();param=re.search(r'^#define RENCODE_IB_PARAM_SESSION_INFO[^\n]*',command,re.M)[0]
c=c.replace(constants+'\n'+macros,constants+'\n'+param+'\n'+macros).replace('.cmd.session_info=1,','.cmd.session_info=RENCODE_IB_PARAM_SESSION_INFO,')
with tempfile.TemporaryDirectory(prefix='narf-avc-interface-')as temp:
    t=Path(temp);(t/'reference.c').write_text(c)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(m/'src/amd/common'),str(t/'reference.c'),'-o',str(t/'reference')],check=True)
    rust='''extern crate alloc;#[derive(Debug,PartialEq,Eq)]enum Error{Invalid,Unsupported}
#[allow(dead_code)]#[path="ENC"]mod e;
#[allow(dead_code)]#[path="POLICY"]mod policy;
fn main(){let base=0x810000000;for minor in[8,9,10,11]{let fw=1<<24|1<<20|minor<<12;let interface=policy::interface(fw).unwrap();for phase in[e::Phase::Create,e::Phase::Encode,e::Phase::Destroy]{let ib=e::ib(base,phase,interface).unwrap();print!("{fw} {} {interface:08x}",base+e::SESSION);for w in &ib[8..14]{print!(" {w:08x}");}println!();}}
for i in[0,0x10007,0x1000b,0x2000a,u32::MAX]{assert_eq!(e::ib(base,e::Phase::Create,i),Err(Error::Unsupported));}
assert_eq!(policy::interface(0),None);assert_eq!(policy::interface(2<<20|10<<12),None);assert_eq!(policy::interface(1<<20|7<<12),None);}
'''.replace('ENC',str(gpu/'src/amdgpu_vcn_navi48_encode_words.rs')).replace('POLICY',str(gpu/'src/amdgpu_vcn_navi48_hevc_encode_words.rs'))
    (t/'words.rs').write_text(rust);subprocess.run(['rustc','--edition=2021','-Dwarnings',str(t/'words.rs'),'-o',str(t/'words')],check=True)
    rows=subprocess.check_output([str(t/'words')],text=True).splitlines();assert len(rows)==12
    for row in rows:
        raw,address,*words=row.split();native=subprocess.check_output([str(t/'reference'),raw,address],text=True).split();assert native==words,(raw,native,words)
print('AVC create/encode/destroy session headers match unchanged Mesa version decoding/selection/constructor for raw minors8/9/10/11; original IGT1.9 body is checked separately.')
