#!/usr/bin/env bash
# Compare native TMDS420 deep-color fixtures with Linux's clock helper.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
python3 - "${1:-/usr/src/linux}" "$here/harness.c" <<'PY'
from pathlib import Path
import subprocess
import sys
import tempfile

linux, harness = map(Path, sys.argv[1:])
source = (linux / 'drivers/gpu/drm/display/drm_hdmi_helper.c').read_text()
name = 'drm_hdmi_compute_mode_clock('
at = source.index('\n' + name) + 1
start = source.rfind('\n', 0, at - 1) + 1
end = source.index('\n}', at) + 2
function = source[start:end]
assert function.startswith('unsigned long long\n' + name)
text = harness.read_text().replace('/* LINUX_FUNCTION */', function)
with tempfile.TemporaryDirectory(prefix='narf-hdmi-formats-') as tmp:
    src, exe = Path(tmp) / 'reference.c', Path(tmp) / 'reference'
    src.write_text(text)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
PY
python3 "$here/encoding-check.py" "${1:-/usr/src/linux}" "$here"
