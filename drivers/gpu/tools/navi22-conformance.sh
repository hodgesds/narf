#!/usr/bin/env bash
# Navi22 (RX 6750 XT) Linux conformance harness: constants vs Linux headers,
# and NARF firmware parsers vs Linux header parsing of the real blobs.
# See drivers/gpu/research/navi22-conformance.md. Exits nonzero on any mismatch.
#
#   LINUX_SRC  Linux tree (default ~/git/linux)
#   FW_DIR     imported NARF-wrapped firmware (default <repo>/target/firmware/amdgpu)
#   SYS_FW     distribution firmware for the byte-identity check (default /lib/firmware/amdgpu)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
linux="${LINUX_SRC:-$HOME/git/linux}"
fw="${FW_DIR:-$repo/target/firmware/amdgpu}"
sysfw="${SYS_FW:-/lib/firmware/amdgpu}"
amd="$linux/drivers/gpu/drm/amd"
tool="$here/navi22_conformance"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

step() { printf '\n== %s\n' "$*"; }

step "constant checker self-test (review boot blockers must be caught)"
python3 -I "$tool/check_constants.py" --linux "$linux" --selftest || fail=1

step "Navi22 constants vs Linux headers"
python3 -I "$tool/check_constants.py" --linux "$linux" "$@" || fail=1

step "SMU11 metrics/PPTable layouts (tests/smu11_metrics.c)"
if cc -Wall -Wextra -Werror '-D__counted_by(x)=' \
	-I"$amd/pm/swsmu/inc/pmfw_if" -I"$amd/pm/swsmu/inc" -I"$amd/include" \
	"$repo/drivers/gpu/tests/smu11_metrics.c" -o "$work/smu11_metrics"; then
	echo "smu11_metrics: PASS"
else
	echo "smu11_metrics: FAIL"
	fail=1
fi

step "firmware parsers vs Linux header parsing ($fw)"
if [ ! -e "$fw/navy_flounder_sos.bin" ]; then
	echo "missing $fw/navy_flounder_*.bin (run cargo xtask import-firmware)"
	fail=1
else
	cc -Wall -Wextra -Wno-unused-parameter -I"$amd/amdgpu" -I"$amd/include" \
		"$tool/fw/linux_ucode.c" -o "$work/linux_ucode"
	rustc --edition 2021 -O "$tool/fw/narf_ucode.rs" -o "$work/narf_ucode"
	"$work/linux_ucode" "$fw" >"$work/linux.txt"
	"$work/narf_ucode" "$fw" >"$work/narf.txt"
	if diff -u "$work/linux.txt" "$work/narf.txt"; then
		echo "firmware: PASS ($(grep -c . "$work/linux.txt") records identical)"
	else
		echo "firmware: FAIL (- Linux expectation, + NARF parser)"
		fail=1
	fi
	if command -v zstd >/dev/null && ls "$sysfw"/navy_flounder_*.bin* >/dev/null 2>&1; then
		for f in "$fw"/navy_flounder_*.bin; do
			name="$(basename "$f")"
			if [ -e "$sysfw/$name.zst" ]; then
				zstd -qdc <"$sysfw/$name.zst" >"$work/sys.bin" || { echo "$name: cannot decompress"; fail=1; continue; }
			elif [ -e "$sysfw/$name" ]; then
				cp "$sysfw/$name" "$work/sys.bin"
			else
				continue
			fi
			python3 -I - "$f" "$work/sys.bin" <<'EOF' || fail=1
import struct, sys
b = open(sys.argv[1], "rb").read()
if b[-4:] == b"NRFW":
    mlen = struct.unpack_from("<I", b, len(b) - 8)[0]
    b = b[:len(b) - 8 - mlen - 96]
s = open(sys.argv[2], "rb").read()
name = sys.argv[1].rsplit("/", 1)[-1]
print("%s: %s" % (name, "payload identical to distribution blob" if b == s else "DIFFERS from distribution blob"))
sys.exit(0 if b == s else 1)
EOF
		done
	fi
fi

echo
if [ "$fail" -ne 0 ]; then
	echo "navi22-conformance: FAIL"
	exit 1
fi
echo "navi22-conformance: PASS"
