#!/usr/bin/env bash
set -euo pipefail

# End-to-end native-package UEFI path:
# OVMF -> installed-style GRUB -> /EFI/NARF/narf.efi (Limine) -> packaged kernel.
# The ordinary iso-boot gate runs first unless its boot-smoke kernel was built
# immediately before this script.
root=$(git rev-parse --show-toplevel)
cd "$root"

if [[ ${NARF_UEFI_SKIP_BASE_ISO_BOOT:-0} != 1 ]]; then
    cargo xtask iso-boot --arch=x86_64
fi

for command_name in grub-mkimage mformat mcopy qemu-system-x86_64 sfdisk; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "packaged UEFI boot test requires $command_name" >&2
        exit 1
    }
done

limine_efi=${NARF_LIMINE_EFI:-}
if [[ -z $limine_efi && -n ${LIMINE_PATH:-} ]]; then
    limine_efi=$LIMINE_PATH/BOOTX64.EFI
fi
if [[ -z $limine_efi ]]; then
    limine_efi=$root/target/iso-x86_64/EFI/BOOT/BOOTX64.EFI
fi
[[ -f $limine_efi ]] || {
    echo "packaged UEFI boot test cannot find BOOTX64.EFI" >&2
    exit 1
}

ovmf=${OVMF_CODE:-}
if [[ -z $ovmf ]]; then
    for candidate in \
        /usr/share/edk2/x64/OVMF.4m.fd \
        /usr/share/edk2-ovmf/x64/OVMF.4m.fd \
        /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
        /usr/share/edk2/x64/OVMF_CODE.fd \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/edk2/OvmfX64/OVMF_CODE.fd
    do
        if [[ -f $candidate ]]; then
            ovmf=$candidate
            break
        fi
    done
fi
[[ -f $ovmf ]] || {
    echo "packaged UEFI boot test cannot find OVMF_CODE.fd; set OVMF_CODE" >&2
    exit 1
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/narf-package-uefi.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

NARF_SKIP_GRUB_CHECK=0 packaging/build-release.sh \
    --version 0.0.0-uefi-test \
    --skip-build \
    --formats tar \
    --limine-efi "$limine_efi" \
    --output "$tmp/packages"

mkdir -p "$tmp/tree" "$tmp/esp"
tar -xzf "$tmp/packages/narf-0.0.0-uefi-test-x86_64.tar.gz" -C "$tmp/tree"
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install \
    --esp "$tmp/esp" --no-manager-hooks --quiet

{
    echo 'set timeout=0'
    echo 'set default=0'
    NARF_BOOT_DIR="$tmp/tree/boot" "$tmp/tree/etc/grub.d/42_narf"
} >"$tmp/grub.cfg"

mkdir -p "$tmp/esp/EFI/BOOT"
mkdir -p "$tmp/esp/boot/grub"
cp "$tmp/grub.cfg" "$tmp/esp/boot/grub/grub.cfg"
grub-mkimage \
    --format=x86_64-efi \
    --prefix=/boot/grub \
    --output="$tmp/esp/EFI/BOOT/BOOTX64.EFI" \
    part_gpt fat normal configfile search search_fs_file chain test sleep

# Use the GPT + ESP layout installed machines actually have. A partitionless
# FAT image does not provide the same EFI device path to a chainloaded loader.
truncate -s 160M "$tmp/esp.img"
sfdisk "$tmp/esp.img" >/dev/null <<'EOF'
label: gpt
unit: sectors
first-lba: 2048

start=2048, size=325599, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
EOF
mformat -i "$tmp/esp.img@@1048576" -T 325599 -F -v NARF_UEFI ::
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/EFI" ::/
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/loader" ::/
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/boot" ::/

timeout_secs=${XTASK_BOOT_SMOKE_TIMEOUT_SECS:-180}
set +e
timeout "$timeout_secs" qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf" \
    -machine q35 \
    -cpu max \
    -smp 2 \
    -m 2048M \
    -drive "format=raw,file=$tmp/esp.img" \
    -boot order=c \
    -serial stdio \
    -display none \
    -no-reboot \
    >"$tmp/serial.log" 2>&1
qemu_status=$?
set -e

if [[ $qemu_status -ne 0 ]] ||
    ! grep -Fq 'boot-smoke: clean exit' "$tmp/serial.log" ||
    grep -Eq '\*\*\* KERNEL PANIC \*\*\*|panicked at|double fault|general protection|kernel page fault' "$tmp/serial.log"
then
    tail -200 "$tmp/serial.log" >&2
    echo "packaged UEFI boot failed (QEMU status $qemu_status)" >&2
    exit 1
fi

echo "packaged UEFI boot passed: OVMF -> GRUB -> Limine -> NARF"
