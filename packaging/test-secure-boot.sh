#!/usr/bin/env bash
set -euo pipefail

# Secure Boot acceptance path:
# enrolled OVMF -> signed/config-bound Limine -> hash-bound packaged kernel.
# A second boot changes one kernel byte and must not reach NARF.
root=$(git rev-parse --show-toplevel)
cd "$root"

if [[ ${NARF_UEFI_SKIP_BASE_ISO_BOOT:-0} != 1 ]]; then
    cargo xtask iso-boot --arch=x86_64
fi

for command_name in openssl sbsign sbverify virt-fw-vars mformat mcopy qemu-system-x86_64 sfdisk; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Secure Boot test requires $command_name" >&2
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
    echo "Secure Boot test cannot find BOOTX64.EFI" >&2
    exit 1
}

secure_code=${OVMF_SECURE_CODE:-}
secure_vars=${OVMF_SECURE_VARS:-}
if [[ -z $secure_code || -z $secure_vars ]]; then
    while IFS='|' read -r code vars; do
        if [[ -f $code && -f $vars ]]; then
            secure_code=$code
            secure_vars=$vars
            break
        fi
    done <<'EOF'
/usr/share/OVMF/OVMF_CODE_4M.secboot.fd|/usr/share/OVMF/OVMF_VARS_4M.fd
/usr/share/OVMF/OVMF_CODE.secboot.fd|/usr/share/OVMF/OVMF_VARS.fd
/usr/share/edk2/x64/OVMF_CODE.secboot.fd|/usr/share/edk2/x64/OVMF_VARS.fd
/usr/share/edk2/OvmfX64/OVMF_CODE_4M.secboot.fd|/usr/share/edk2/OvmfX64/OVMF_VARS_4M.fd
/usr/share/edk2/OvmfX64/OVMF_CODE.secboot.fd|/usr/share/edk2/OvmfX64/OVMF_VARS.fd
EOF
fi
[[ -f $secure_code && -f $secure_vars ]] || {
    echo "Secure Boot-capable OVMF code/vars not found" >&2
    exit 1
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/narf-secure-boot.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

openssl req -new -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=NARF CI Secure Boot/' \
    -keyout "$tmp/db.key" -out "$tmp/db.crt" >/dev/null 2>&1

NARF_SKIP_GRUB_CHECK=0 packaging/build-release.sh \
    --version 0.0.0-secure-boot-test \
    --skip-build \
    --formats tar \
    --limine-efi "$limine_efi" \
    --secure-boot-key "$tmp/db.key" \
    --secure-boot-cert "$tmp/db.crt" \
    --output "$tmp/packages"

mkdir -p "$tmp/tree" "$tmp/esp/EFI/BOOT"
tar -xzf "$tmp/packages/narf-0.0.0-secure-boot-test-x86_64.tar.gz" -C "$tmp/tree"
grep -Fx yes "$tmp/tree/usr/lib/narf/uefi/secure-boot-signed" >/dev/null
sbverify --cert "$tmp/db.crt" "$tmp/tree/usr/lib/narf/uefi/narf.efi" >/dev/null

NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install \
    --esp "$tmp/esp" --no-manager-hooks --quiet
cp "$tmp/esp/EFI/NARF/narf.efi" "$tmp/esp/EFI/BOOT/BOOTX64.EFI"

truncate -s 160M "$tmp/esp.img"
sfdisk "$tmp/esp.img" >/dev/null <<'EOF'
label: gpt
unit: sectors
first-lba: 2048

start=2048, size=325599, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
EOF
mformat -i "$tmp/esp.img@@1048576" -T 325599 -F -v NARF_SECURE ::
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/EFI" ::/
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/boot" ::/
mcopy -s -i "$tmp/esp.img@@1048576" "$tmp/esp/loader" ::/

# --enroll-cert sets up PK/KEK but Ubuntu's virt-firmware otherwise leaves db
# with its default Microsoft certificates. Keep this test policy isolated and
# add the ephemeral signer explicitly so OVMF may execute the signed loader.
virt-fw-vars --input "$secure_vars" --output "$tmp/enrolled-vars.fd" \
    --enroll-cert "$tmp/db.crt" --no-microsoft \
    --add-db 8c8b13fd-3c1f-4dce-92d9-2a76e88d9fe8 "$tmp/db.crt" \
    --secure-boot

boot_image() {
    local image=$1 vars=$2 log=$3 timeout_secs=$4
    timeout "$timeout_secs" qemu-system-x86_64 \
        -machine q35,smm=on \
        -global driver=cfi.pflash01,property=secure,value=on \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$secure_code" \
        -drive "if=pflash,format=raw,unit=1,file=$vars" \
        -cpu max \
        -smp 2 \
        -m 2048M \
        -drive "format=raw,file=$image" \
        -boot order=c \
        -serial stdio \
        -display none \
        -no-reboot \
        >"$log" 2>&1
}

cp "$tmp/enrolled-vars.fd" "$tmp/positive-vars.fd"
if ! boot_image "$tmp/esp.img" "$tmp/positive-vars.fd" "$tmp/positive.log" \
    "${XTASK_BOOT_SMOKE_TIMEOUT_SECS:-180}" ||
    ! grep -Fq 'boot-smoke: clean exit' "$tmp/positive.log" ||
    grep -Eq '\*\*\* KERNEL PANIC \*\*\*|panicked at|double fault|general protection|kernel page fault' "$tmp/positive.log"
then
    tail -200 "$tmp/positive.log" >&2
    echo "signed Secure Boot path failed" >&2
    exit 1
fi

cp "$tmp/esp.img" "$tmp/tampered.img"
cp "$tmp/esp/EFI/NARF/narf-frame" "$tmp/tampered-kernel"
printf x >>"$tmp/tampered-kernel"
mcopy -o -i "$tmp/tampered.img@@1048576" "$tmp/tampered-kernel" \
    ::/EFI/NARF/narf-frame
cp "$tmp/enrolled-vars.fd" "$tmp/tampered-vars.fd"
set +e
boot_image "$tmp/tampered.img" "$tmp/tampered-vars.fd" "$tmp/tampered.log" 20
tampered_status=$?
set -e
if [[ $tampered_status -eq 0 ]] || grep -Fq 'boot-smoke: clean exit' "$tmp/tampered.log"; then
    tail -200 "$tmp/tampered.log" >&2
    echo "Secure Boot accepted a tampered NARF kernel" >&2
    exit 1
fi

echo "Secure Boot passed: enrolled OVMF accepted the signed chain and rejected a tampered kernel"
