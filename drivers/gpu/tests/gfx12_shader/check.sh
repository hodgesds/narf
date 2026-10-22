#!/bin/sh
# LLVM 22+ with the AMDGPU target; LINUX_SRC may select another Linux tree.
# PATH=/usr/lib/llvm/22/bin:$PATH sh drivers/gpu/tests/gfx12_shader/check.sh
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
linux_src=${LINUX_SRC:-/usr/src/linux}
scratch_dir=$(mktemp -d /tmp/narf-gfx12-shader.XXXXXX)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM
for target in gfx1200 gfx1201; do
"${LLVM_MC:-llvm-mc}" -triple=amdgcn-amd-amdhsa -mcpu="$target" \
    -filetype=obj "$test_dir/proof.s" -o "$scratch_dir/proof.o"
"${LLVM_OBJCOPY:-llvm-objcopy}" -O binary --only-section=.text \
    "$scratch_dir/proof.o" "$scratch_dir/proof.bin"
python3 - "$test_dir/../../src/amdgpu_gfx12_shader.rs" "$scratch_dir/proof.bin" "$target" <<'PY'
import pathlib
import re
import struct
import sys

source = pathlib.Path(sys.argv[1]).read_text()
array = re.search(r"pub const PROGRAM: \[u32; \d+\] = \[(.*?)\];", source, re.S)
assert array, "missing Rust shader words"
words = [int(v.replace("_", ""), 0)
         for v in re.findall(r"\b(?:0x[0-9a-fA-F_]+|\d+)\b", array[1])]
expected = struct.pack("<" + "I" * len(words), *words)
actual = pathlib.Path(sys.argv[2]).read_bytes()
assert actual == expected, f"LLVM {sys.argv[3]} encoding differs: {actual.hex()}"
print(f"{sys.argv[3]} shader: {len(words)} dwords match LLVM assembly")
PY
done
"${CC:-cc}" -Wall -Wextra -Werror \
    -I"$linux_src/drivers/gpu/drm/amd/include" \
    -I"$linux_src/drivers/gpu/drm/amd/amdgpu" \
    "$test_dir/../gfx12_shader.c" -o "$scratch_dir/headers"
"$scratch_dir/headers"
echo 'GC12 shader registers, dispatch and cache fields match Linux headers'
