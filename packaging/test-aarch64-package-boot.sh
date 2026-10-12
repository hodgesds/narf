#!/usr/bin/env bash
set -euo pipefail

# End-to-end native aarch64 package path:
# AAVMF -> package-owned NARF EFI loader -> digest-bound packaged kernel.
root=$(git rev-parse --show-toplevel)
cd "$root"

if [[ ${NARF_UEFI_SKIP_BASE_ISO_BOOT:-0} != 1 ]]; then
    cargo xtask iso-boot --arch=aarch64
fi

for command_name in mformat mcopy qemu-system-aarch64 sfdisk; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "aarch64 packaged UEFI boot test requires $command_name" >&2
        exit 1
    }
done

aavmf=${AAVMF_CODE:-}
if [[ -z $aavmf ]]; then
    for candidate in \
        /usr/share/AAVMF/AAVMF_CODE.fd \
        /usr/share/AAVMF/AAVMF_CODE.ms.fd \
        /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
        /usr/share/qemu/edk2-aarch64-code.fd \
        /usr/share/edk2/aarch64/QEMU_EFI.fd \
        /usr/share/edk2-armvirt/aarch64/QEMU_EFI.fd
    do
        if [[ -f $candidate ]]; then
            aavmf=$candidate
            break
        fi
    done
fi
[[ -f $aavmf ]] || {
    echo "aarch64 packaged UEFI boot test cannot find AAVMF; set AAVMF_CODE" >&2
    exit 1
}

loader=$root/target/narf-uefi-aarch64/narf.efi
dtb=$root/target/qemu-virt.dtb
[[ -f $loader && -s $dtb ]] || {
    echo "aarch64 packaged UEFI boot test requires the preceding iso-boot artifacts" >&2
    exit 1
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/narf-package-aarch64-uefi.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

packaging/build-release.sh \
    --version 0.0.0-aarch64-uefi-test \
    --arch aarch64 \
    --skip-build \
    --formats tar \
    --uefi-loader "$loader" \
    --output "$tmp/packages"

mkdir -p "$tmp/tree" "$tmp/esp/EFI/BOOT"
tar -xzf "$tmp/packages/narf-0.0.0-aarch64-uefi-test-aarch64.tar.gz" -C "$tmp/tree"
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install \
    --esp "$tmp/esp" --no-manager-hooks --quiet
cp "$tmp/esp/EFI/NARF/narf.efi" "$tmp/esp/EFI/BOOT/BOOTAA64.EFI"

truncate -s 160M "$tmp/esp.img"
sfdisk "$tmp/esp.img" >/dev/null <<'EOF'
label: gpt
unit: sectors
first-lba: 2048

start=2048, size=325599, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
EOF
mformat -i "$tmp/esp.img@@1048576" -T 325599 -F -v NARF_AA64 ::
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/EFI" ::/
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/loader" ::/

boot_image() {
    local image=$1 log=$2 timeout_secs=$3
    timeout "$timeout_secs" qemu-system-aarch64 \
        -machine "virt,gic-version=3,mte=on,highmem-ecam=off,acpi=off,dtb=$dtb" \
        -cpu max \
        -smp 2 \
        -m 512M \
        -bios "$aavmf" \
        -drive "if=none,id=esp,format=raw,readonly=on,file=$image" \
        -device virtio-blk-pci,drive=esp,disable-legacy=on,disable-modern=off \
        -serial stdio \
        -display none \
        -no-reboot \
        -semihosting \
        >"$log" 2>&1
}

if ! boot_image "$tmp/esp.img" "$tmp/positive.log" \
    "${XTASK_BOOT_SMOKE_TIMEOUT_SECS:-180}" ||
    ! grep -Fq 'boot-smoke: clean exit' "$tmp/positive.log" ||
    grep -Eq '\*\*\* KERNEL PANIC \*\*\*|panicked at|double fault|kernel page fault' "$tmp/positive.log"
then
    tail -200 "$tmp/positive.log" >&2
    echo "packaged aarch64 UEFI boot failed" >&2
    exit 1
fi

cp "$tmp/esp.img" "$tmp/tampered.img"
cp "$tmp/esp/EFI/NARF/narf-frame" "$tmp/tampered-kernel"
printf x >>"$tmp/tampered-kernel"
mcopy -o -i "$tmp/tampered.img@@1048576" "$tmp/tampered-kernel" \
    ::/EFI/NARF/narf-frame
set +e
boot_image "$tmp/tampered.img" "$tmp/tampered.log" 20
tampered_status=$?
set -e
if [[ $tampered_status -eq 0 ]] || grep -Fq 'boot-smoke: clean exit' "$tmp/tampered.log"; then
    tail -200 "$tmp/tampered.log" >&2
    echo "aarch64 UEFI loader accepted a tampered packaged kernel" >&2
    exit 1
fi

echo "packaged aarch64 UEFI boot passed and rejected a tampered kernel"
