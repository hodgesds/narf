#!/usr/bin/env python3
"""Verify pinned JPEG fixture/provenance and unchanged IGT JPEG5 IB builders."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile

igt=Path(sys.argv[1])
gpu=Path(__file__).resolve().parents[2]
fixture=gpu/'fixtures/jpeg5'
manifest=json.loads((fixture/'manifest.json').read_text())
messages=(igt/manifest['source']['file']).read_text()
assert 'SPDX-License-Identifier: '+manifest['source']['license'] in messages
for notice in manifest['source']['copyright']:
    assert 'Copyright '+notice in messages
for name,expected in manifest['arrays'].items():
    body=re.search(r'static const uint8_t '+name+r'\[\]\s*=\s*\{(.*?)\};',messages,re.S)[1]
    native=bytes(int(v,16) for v in re.findall(r'0x[0-9a-fA-F]+',body))
    actual=(fixture/(name+'.bin')).read_bytes()
    assert actual==native and len(actual)==expected['bytes']
    assert hashlib.sha256(actual).hexdigest()==expected['sha256']
header=(igt/'lib/amdgpu/amd_jpeg_shared.h').read_text()
for name,expected in [('WIDTH',manifest['width']),('JPEG_DEC_DT_PITCH',manifest['pitch']),
    ('JPEG_DEC_CHROMA_OFFSET',manifest['chroma_offset']),('JPEG_DEC_SUM',manifest['target_sum'])]:
    assert int(re.search(r'#define '+name+r'\s+(\w+)',header)[1],0)==expected
source=(igt/'lib/amdgpu/amd_jpeg_shared.c').read_text()
pieces=[header.replace('#include "amd_mmd_shared.h"',''),source[:source.index('#include')]]
for name in ['is_jpeg_tests_enable','set_reg_jpeg','send_cmd_bitstream_direct','send_cmd_target_direct']:
    match=re.search(r'^'+name+r'\s*\(',source,re.M)
    start=source.rfind('bool' if name=='is_jpeg_tests_enable' else 'void',0,match.start())
    opening=source.index('{',match.start())
    depth,end=1,opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    pieces.append(source[start:end])
with tempfile.TemporaryDirectory(prefix='narf-jpeg-picture-') as temp:
    out=Path(temp)
    (out/'native_picture.h').write_text('\n'.join(pieces)+'\n')
    harness=r'''
extern crate alloc;
#[derive(Debug,PartialEq,Eq)] enum Error {Invalid}
#[allow(dead_code)] #[path="WORDS"] mod d;
fn main() {
    let base=0x810000000;
    println!("{} {}",base+d::INPUT,base+d::TARGET);
    for word in d::ib(base).unwrap() {println!("{word:08x}");}
    for at in [0,base+4,1<<48,(1<<48)-4096] {assert_eq!(d::ib(at),Err(Error::Invalid));}
    assert_eq!(d::CHROMA+d::PITCH*d::WIDTH/2,d::TARGET_BYTES);
    assert_eq!(d::STREAM.len(),406);
}
'''.replace('WORDS',str(gpu/'src/amdgpu_jpeg_navi48_decode_words.rs'))
    (out/'harness.rs').write_text(harness)
    subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
        '-Wno-sign-compare','-I'+str(out),str(Path(__file__).with_name('decode_reference.c')),
        '-o',str(out/'native')],check=True)
    subprocess.run(['rustc','--edition=2021',str(out/'harness.rs'),'-o',str(out/'rust')],check=True)
    rust=subprocess.check_output([str(out/'rust')],text=True).splitlines()
    native=subprocess.check_output([str(out/'native')]+rust[0].split(),text=True).splitlines()
    assert native==rust[1:],'JPEG5 picture IB differs from IGT'
print('JPEG fixture, attribution and picture IB match unchanged IGT JPEG5 builders.')
