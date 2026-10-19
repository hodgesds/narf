#!/usr/bin/env bash
set -euo pipefail
linux_tree="${1:-/usr/src/linux}"
test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
gpu_dir="$(cd -- "$test_dir/../.." >/dev/null && pwd)"
ref_dir="$(mktemp -d /tmp/narf-vcn5-ib.XXXXXX)"
python3 - "$linux_tree" "$ref_dir" "$gpu_dir" <<'PY'
from pathlib import Path
import re
import sys
linux, out, gpu = map(Path, sys.argv[1:])
source = (linux/'drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.c').read_text()
header = (linux/'drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.h').read_text()
names = [
    'amdgpu_vcn_unified_ring_ib_header', 'amdgpu_vcn_unified_ring_ib_checksum',
    'amdgpu_vcn_enc_get_create_msg', 'amdgpu_vcn_enc_get_destroy_msg',
    'amdgpu_vcn_dec_get_create_msg', 'amdgpu_vcn_dec_get_destroy_msg',
    'amdgpu_vcn_dec_sw_send_msg',
]
pieces = []
for name in names:
    start = re.search(r'^static[^\n]*\b'+name+r'\s*\(', source, re.M)
    if not start:
        raise SystemExit(f'Missing Linux constructor: {name}')
    opening = source.index('{', start.start())
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    pieces.append(source[start.start():end])
struct = re.search(r'struct amdgpu_vcn_decode_buffer\s*\{[^}]*\};', header)
if not struct:
    raise SystemExit('Missing native decode buffer')
defines = []
for name in ['AMDGPU_VCN_IB_FLAG_DECODE_BUFFER', 'AMDGPU_VCN_CMD_FLAG_MSG_BUFFER']:
    match = re.search(r'^#define\s+'+name+r'\s+[^\n]+', header, re.M)
    if not match:
        raise SystemExit(f'Missing native define: {name}')
    defines.append(match[0])
(out/'native_vcn_test_funcs.h').write_text('\n'.join(defines+[struct[0]]+pieces)+'\n')
rust = r'''
use std::collections::BTreeMap;
#[derive(Debug, PartialEq, Eq)]
enum Error { Invalid }
#[allow(dead_code)]
#[path = "IB_WORDS_PATH"]
mod words;
fn main() {
    let reference = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let native: BTreeMap<_, _> = reference.lines().map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.next().unwrap();
        (name, fields.map(|v| u32::from_str_radix(v, 16).unwrap()).collect::<Vec<_>>())
    }).collect();
    let base = 0x8_1000_0000;
    assert_eq!(words::encode(base, true).unwrap().as_slice(), native["encode_create"]);
    assert_eq!(words::encode(base, false).unwrap().as_slice(), native["encode_destroy"]);
    assert_eq!(words::decode_message(true).as_slice(), native["decode_create_message"]);
    assert_eq!(words::decode_message(false).as_slice(), native["decode_destroy_message"]);
    assert_eq!(words::decode(base+words::DECODE_CREATE_MSG).unwrap().as_slice(), native["decode_create"]);
    assert_eq!(words::decode(base+words::DECODE_DESTROY_MSG).unwrap().as_slice(), native["decode_destroy"]);
    for invalid in [0, base+4, 1u64<<48] {
        assert_eq!(words::encode(invalid, true), Err(Error::Invalid));
        assert_eq!(words::decode(invalid), Err(Error::Invalid));
    }
}
'''.replace('IB_WORDS_PATH', str(gpu/'src/amdgpu_vcn_navi48_ib_words.rs'))
(out/'harness.rs').write_text(rust)
PY
cc -Wall -Wextra -Werror -Wno-unused-parameter -Wno-sign-compare -I"$ref_dir" \
    "$test_dir/ib_reference.c" -o "$ref_dir/native_check"
"$ref_dir/native_check" > "$ref_dir/native_words.txt"
rustc --edition=2021 "$ref_dir/harness.rs" -o "$ref_dir/rust_check"
"$ref_dir/rust_check" "$ref_dir/native_words.txt"
printf '%s\n' 'VCN unified session IBs match unchanged Linux constructors.'
