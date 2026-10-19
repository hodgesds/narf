#!/usr/bin/env bash
set -euo pipefail
linux_tree="${1:-/usr/src/linux}"
test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"
ref_dir="$(mktemp -d /tmp/narf-vcn5-headers.XXXXXX)"
# Extract only the standalone protocol defines; amdgpu_vcn.h otherwise
# requires an entire configured Linux kernel to include on the host.
python3 - "$linux_tree/drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.h" "$ref_dir/commands.h" <<'PY'
from pathlib import Path
import re
import sys
names = {
    'VCN_ENC_CMD_NO_OP', 'VCN_ENC_CMD_END', 'VCN_ENC_CMD_IB',
    'VCN_ENC_CMD_FENCE', 'VCN_ENC_CMD_TRAP', 'VCN_ENC_CMD_REG_WRITE',
    'VCN_ENC_CMD_REG_WAIT', 'AMDGPU_VCN_STACK_SIZE', 'AMDGPU_VCN_CONTEXT_SIZE',
    'AMDGPU_FW_SHARED_FLAG_0_UNIFIED_QUEUE', 'AMDGPU_VCN_SMU_DPM_INTERFACE_FLAG',
    'AMDGPU_VCN_SMU_DPM_INTERFACE_DGPU',
}
lines = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    match = re.match(r'^#define\s+(\w+)\s+', line)
    if match and match[1] in names:
        lines[match[1]] = line
if lines.keys() != names:
    raise SystemExit(f'Missing VCN reference defines: {names - lines.keys()}')
Path(sys.argv[2]).write_text('\n'.join(lines.values()) + '\n')
PY
cc -Wall -Wextra -Werror -include "$ref_dir/commands.h" \
    -I"$linux_tree/drivers/gpu/drm/amd/include" \
    "$test_dir/vcn5_transport.c" -o "$ref_dir/check"
printf '%s\n' 'VCN5 register, command and shared-memory definitions match Linux.'
