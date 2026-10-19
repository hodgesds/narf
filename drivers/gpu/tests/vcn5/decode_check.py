#!/usr/bin/env python3
"""Compare fixed fixtures and Rust descriptors with pinned IGT source."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile

igt = Path(sys.argv[1])
gpu = Path(__file__).resolve().parents[2]
fixtures = gpu / 'fixtures/vcn5'
manifest = json.loads((fixtures / 'manifest.json').read_text())
messages = (igt / manifest['source']['file']).read_text()
assert 'SPDX-License-Identifier: '+manifest['source']['license'] in messages
for notice in manifest['source']['copyright']:
    assert 'Copyright '+notice in messages, 'Fixture copyright differs from source'
for name, expected in manifest['arrays'].items():
    match = re.search(r'static\s+const\s+uint8_t\s+'+name+r'\s*\[\s*\]\s*=\s*\{(.*?)\};', messages, re.S)
    if not match:
        raise SystemExit(f'Missing IGT fixture {name}')
    body = re.sub(r'/\*.*?\*/|//[^\n]*', '', match[1], flags=re.S)
    native = bytes(int(v, 0) for v in re.findall(r'0x[0-9a-fA-F]+|\b[0-9]+\b', body))
    actual = (fixtures / (name+'.bin')).read_bytes()
    assert actual == native and len(actual) == expected['bytes'], name
    assert hashlib.sha256(actual).hexdigest() == expected['sha256'], name
assert int(re.search(r'#define\s+SUM_DECODE\s+(\w+)',messages)[1],0) == manifest['target_sum']
source = (igt/'lib/amdgpu/amd_vcn_shared.c').read_text()
header = (igt/'lib/amdgpu/amd_vcn_shared.h').read_text()
shared = (igt/'lib/amdgpu/amd_mmd_shared.h').read_text()
pieces = [
    source[:source.index('#include')],
    header[:header.index('#ifndef')],
    shared[:shared.index('#include')],
]
for name in ['rvcn_decode_buffer','rvcn_decode_ib_package']:
    pieces.append(re.search(r'struct '+name+r'\s*\{[^}]*\};',header)[0])
pieces.append(re.search(r'enum decoder_error_type\s*\{[^}]*\};',shared)[0])
pieces += re.findall(r'^#define\s+DECODE_\w+\s+[^\n]+',header,re.M)
for name in ['amdgpu_cs_sq_head','amdgpu_cs_sq_ib_tail','vcn_dec_cmd']:
    match = re.search(r'^'+name+r'\s*\(', source, re.M)
    start = source.rfind('void',0,match.start())
    opening = source.index('{', match.start())
    depth, end = 1, opening+1
    while depth:
        depth += (source[end]=='{') - (source[end]=='}')
        end += 1
    pieces.append(source[start:end])
with tempfile.TemporaryDirectory(prefix='narf-vcn-decode-') as temp:
    out = Path(temp)
    (out/'native_decode_funcs.h').write_text('\n'.join(pieces)+'\n')
    harness = r'''
#[derive(Debug, PartialEq, Eq)] enum Error { Invalid }
#[allow(dead_code)] #[path="WORDS"] mod d;
fn main() {
    let base = 0x8_1000_0000;
    print!("layout");
    for at in [d::SESSION,d::CREATE_MSG,d::DECODE_MSG,d::DESTROY_MSG,d::DPB,
        d::TARGET,d::FEEDBACK,d::BITSTREAM,d::SCALING,d::CONTEXT] { print!(" {}",base+at); }
    println!();
    for (n,p) in [d::Phase::Create,d::Phase::Decode,d::Phase::Destroy].into_iter().enumerate() {
        print!("{n}");
        for w in d::ib(base,p).unwrap() {print!(" {w:08x}");} println!();
    }
    for at in [0,base+4,1<<48,(1<<48)-4096] {
        assert_eq!(d::ib(at,d::Phase::Decode),Err(Error::Invalid));
    }
    assert!(d::CONTEXT >= d::DPB && d::CONTEXT < d::TARGET_GUARD);
    assert!(d::TARGET_END_GUARD+d::TARGET_BYTES > d::TARGET);
}
'''.replace('WORDS',str(gpu/'src/amdgpu_vcn_navi48_decode_words.rs'))
    (out/'harness.rs').write_text(harness)
    subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
        '-Wno-sign-compare','-I'+str(out),str(Path(__file__).with_name('decode_reference.c')),
        '-o',str(out/'native')],check=True)
    subprocess.run(['rustc','--edition=2021',str(out/'harness.rs'),'-o',str(out/'rust')],check=True)
    rust = subprocess.check_output([str(out/'rust')],text=True).splitlines()
    native = subprocess.check_output([str(out/'native')]+rust[0].split()[1:],text=True).splitlines()
    assert native == rust[1:], (native,rust[1:])
print('AVC fixtures and unified descriptors match unchanged IGT constructors.')
