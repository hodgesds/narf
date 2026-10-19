#!/usr/bin/env python3
"""Compare VCN5 encode words and input with unchanged, pinned IGT builders."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile

igt = Path(sys.argv[1])
gpu = Path(__file__).resolve().parents[2]
fixture = gpu / 'fixtures/vcn5/encode'
manifest = json.loads((fixture/'manifest.json').read_text())
frame_header = (igt/manifest['source']['file']).read_text()
assert 'SPDX-License-Identifier: '+manifest['source']['license'] in frame_header
for notice in manifest['source']['copyright']:
    assert 'Copyright '+notice in frame_header, 'Fixture copyright differs from source'
array = re.search(r'frame\[\]\s*=\s*\{(.*?)\};',frame_header,re.S)[1]
frame = bytes(int(v,16) for v in re.findall(r'0x[0-9a-fA-F]+',array))
assert frame == (fixture/'frame.bin').read_bytes()
assert len(frame) == manifest['arrays']['frame']['bytes']
assert hashlib.sha256(frame).hexdigest() == manifest['arrays']['frame']['sha256']
test = (igt/'tests/amdgpu/amd_vcn.c').read_text()
shared = (igt/'lib/amdgpu/amd_vcn_shared.c').read_text()
pieces = [test[:test.index('#include')], shared[:shared.index('#include')]]
for source, names in [
    (shared,['amdgpu_cs_sq_head','amdgpu_cs_sq_ib_tail']),
    (test,['amdgpu_cs_vcn_enc_create','amdgpu_cs_vcn_ib_zero_count',
           'amdgpu_cs_vcn_enc_encode_frame','amdgpu_cs_vcn_enc_destroy']),
]:
    for name in names:
        match = re.search(r'^'+name+r'\s*\(',source,re.M)
        start = source.rfind('void',0,match.start())
        if source[start-7:start] == 'static ':
            start -= 7
        opening = source.index('{',match.start())
        depth,end = 1,opening+1
        while depth:
            depth += (source[end]=='{') - (source[end]=='}')
            end += 1
        pieces.append(source[start:end])
with tempfile.TemporaryDirectory(prefix='narf-vcn-encode-') as temp:
    out = Path(temp)
    (out/'native_encode_funcs.h').write_text('\n'.join(pieces)+'\n')
    harness = r'''
extern crate alloc;
#[derive(Debug, PartialEq, Eq)] enum Error { Invalid }
#[allow(dead_code)] #[path="WORDS"] mod e;
fn main() {
    let base = 0x8_1000_0000;
    print!("layout");
    for at in [e::SESSION,e::CPB,e::OUTPUT,e::FEEDBACK,e::INPUT,e::METADATA] {
        print!(" {}",base+at);
    }
    println!();
    for (n,p) in [e::Phase::Create,e::Phase::Encode,e::Phase::Destroy].into_iter().enumerate() {
        print!("{n}"); for w in e::ib(base,p).unwrap() {print!(" {w:08x}");} println!();
    }
    for at in [0,base+4,1<<48,(1<<48)-4096] {
        assert_eq!(e::ib(at,e::Phase::Encode),Err(Error::Invalid));
    }
    assert!(e::OUTPUT+e::OUTPUT_BYTES <= e::OUTPUT_END_GUARD);
    assert_eq!(e::FRAME.len(),160*128*3/2);
}
'''.replace('WORDS',str(gpu/'src/amdgpu_vcn_navi48_encode_words.rs'))
    (out/'harness.rs').write_text(harness)
    subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
        '-Wno-sign-compare','-I'+str(out),'-I'+str(igt/'lib/amdgpu'),
        str(Path(__file__).with_name('encode_reference.c')),'-o',str(out/'native')],check=True)
    subprocess.run(['rustc','--edition=2021',str(out/'harness.rs'),'-o',str(out/'rust')],check=True)
    rust = subprocess.check_output([str(out/'rust')],text=True).splitlines()
    native = subprocess.check_output([str(out/'native')]+rust[0].split()[1:],text=True).splitlines()
    assert native == rust[1:], 'VCN5 encoder words differ from IGT'
print('VCN5 input frame and all encoder IBs match unchanged IGT constructors.')
