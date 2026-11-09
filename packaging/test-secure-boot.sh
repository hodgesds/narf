#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
if [[ ${1:-} == --limine ]]; then
    exec packaging/test-secure-boot-limine.sh
fi
if [[ ${NARF_UEFI_SKIP_BASE_ISO_BOOT:-0} != 1 ]]; then
    cargo xtask efi-image --smoke
fi
exec python3 packaging/test-native-secure-boot.py "${NARF_NATIVE_EFI:-target/narf-x86_64-smoke.efi}"
