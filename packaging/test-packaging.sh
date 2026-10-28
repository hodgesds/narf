#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p target/x86_64-unknown-none/release
{
    printf 'MZ'
    dd if=/dev/zero bs=1 count=58 2>/dev/null
    printf '\100\000\000\000PE\000\000\144\206'
} >"$tmp/BOOTX64.EFI"
printf '%s' '++CONFIG_B2SUM_SIGNATURE++' >>"$tmp/BOOTX64.EFI"
printf '%0128d' 0 >>"$tmp/BOOTX64.EFI"
cat >"$tmp/limine-tool" <<'EOF'
#!/bin/sh
set -eu
[ "$1" = enroll-config ]
[ -f "$2" ]
case "$3" in
    *[!0-9a-f]*|'') exit 1 ;;
esac
[ "${#3}" -eq 128 ]
printf '\nNARF_TEST_CONFIG_BLAKE2B=%s\n' "$3" >>"$2"
EOF
chmod +x "$tmp/limine-tool"

python3 - "$tmp/BOOTAA64.EFI" <<'PY'
import pathlib, sys
image = bytearray(b'MZ' + bytes(58) + bytes((64, 0, 0, 0)) + b'PE\0\0' + bytes((0x64, 0xaa)))
image += bytes(256)
image += b'NARF_KERNEL_BLAKE2B=' + bytes([0xa5]) * 64
pathlib.Path(sys.argv[1]).write_bytes(image)
PY

for path in \
    target/x86_64-unknown-none/release/narf-frame \
    target/narf-frame-aarch64.efi-elf
do
    if [[ ! -e $path ]]; then
        printf 'packaging-test-fixture\n' >"$path"
        printf '%s\n' "$path" >>"$tmp/created"
    fi
done

formats=tar,gentoo
if command -v dpkg-deb >/dev/null 2>&1; then
    formats=$formats,deb
fi
NARF_SKIP_GRUB_CHECK=1 packaging/build-release.sh --version 0.0.0-test.1 --skip-build \
    --limine-efi "$tmp/BOOTX64.EFI" \
    --formats "$formats" --output "$tmp/out" --source-date-epoch 1700000000
test -f "$tmp/out/narf-0.0.0-test.1-x86_64.tar.gz"
gentoo_ebuild=$tmp/out/gentoo/sys-kernel/narf-kernel/narf-kernel-0.0.0-test.1.ebuild
test -f "$gentoo_ebuild"
grep -F 'releases/download/v0.0.0-test.1/narf-0.0.0-test.1-x86_64.tar.gz' \
    "$gentoo_ebuild" >/dev/null
grep -F '[[ -z ${REPLACED_BY_VERSION} ]]' "$gentoo_ebuild" >/dev/null
test -f "$tmp/out/release-manifest.json"
(cd "$tmp/out" && sha256sum -c SHA256SUMS)
tar -tzf "$tmp/out/narf-0.0.0-test.1-x86_64.tar.gz" |
    grep -F './boot/narf-kernel-0.0.0-test.1' >/dev/null
for packaged_path in \
    ./usr/bin/narf-uefi \
    ./usr/lib/narf/uefi/narf.efi \
    ./usr/lib/narf/uefi/narf-frame \
    ./usr/lib/narf/uefi/version \
    ./usr/lib/narf/uefi/arch \
    ./usr/lib/narf/uefi/loader-kind \
    ./usr/lib/narf/uefi/kernel.blake2b \
    ./usr/lib/narf/uefi/limine.conf \
    ./usr/lib/narf/uefi/secure-boot-signed \
    ./usr/share/licenses/narf/LIMINE
do
    tar -tzf "$tmp/out/narf-0.0.0-test.1-x86_64.tar.gz" |
        grep -F "$packaged_path" >/dev/null
done

if command -v dpkg-deb >/dev/null 2>&1; then
    deb="$tmp/out/narf-kernel_0.0.0-test.1_amd64.deb"
    test -f "$deb"
    dpkg-deb --contents "$deb" | grep -F './usr/bin/narf-uefi' >/dev/null
    dpkg-deb --contents "$deb" | grep -F './usr/lib/narf/uefi/narf.efi' >/dev/null
    mkdir -p "$tmp/deb-control"
    dpkg-deb --control "$deb" "$tmp/deb-control"
    grep -F 'Depends: util-linux' "$tmp/deb-control/control" >/dev/null
    sh -n "$tmp/deb-control/postinst" "$tmp/deb-control/prerm" "$tmp/deb-control/postrm"
fi

# Exercise the exact package-owned payload without touching the host ESP or
# boot-manager state.
mkdir -p "$tmp/tree" "$tmp/esp"
tar -xzf "$tmp/out/narf-0.0.0-test.1-x86_64.tar.gz" -C "$tmp/tree"
packaging/bind-limine-config.py "$tmp/BOOTX64.EFI" \
    "$tmp/tree/usr/lib/narf/uefi/limine.conf" "$tmp/expected-BOOTX64.EFI"
cmp "$tmp/expected-BOOTX64.EFI" "$tmp/tree/usr/lib/narf/uefi/narf.efi"
packaging/bind-limine-config.py "$tmp/expected-BOOTX64.EFI" \
    "$tmp/tree/usr/lib/narf/uefi/limine.conf" "$tmp/rebound-BOOTX64.EFI"
cmp "$tmp/expected-BOOTX64.EFI" "$tmp/rebound-BOOTX64.EFI"
printf 'different config\n' >"$tmp/different-limine.conf"
if packaging/bind-limine-config.py "$tmp/expected-BOOTX64.EFI" \
    "$tmp/different-limine.conf" "$tmp/wrong-BOOTX64.EFI" >/dev/null 2>&1
then
    echo "Limine binder accepted a loader bound to a different configuration" >&2
    exit 1
fi
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install --esp "$tmp/esp" --no-manager-hooks
cmp "$tmp/tree/usr/lib/narf/uefi/narf.efi" "$tmp/esp/EFI/NARF/narf.efi"
cmp "$tmp/tree/boot/narf-kernel-0.0.0-test.1" "$tmp/esp/EFI/NARF/narf-frame"
grep -F 'path: boot():/EFI/NARF/narf-frame' "$tmp/esp/EFI/NARF/limine.conf" >/dev/null
grep -E 'path: boot\(\):/EFI/NARF/narf-frame#[0-9a-f]{128}$' \
    "$tmp/esp/EFI/NARF/limine.conf" >/dev/null
cmp "$tmp/esp/EFI/NARF/limine.conf" "$tmp/esp/boot/limine/limine.conf"
grep -F 'efi /EFI/NARF/narf.efi' "$tmp/esp/loader/entries/narf.conf" >/dev/null
if NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
    NARF_UEFI_STATE_DIR="$tmp/state" \
    "$tmp/tree/usr/bin/narf-uefi" status --esp "$tmp/esp" >/dev/null 2>&1
then
    echo "narf-uefi accepted a non-FAT --esp without the test override" >&2
    exit 1
fi
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" status --esp "$tmp/esp" >/dev/null
printf 'stale' >>"$tmp/esp/EFI/NARF/narf-frame"
if NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
    NARF_UEFI_STATE_DIR="$tmp/state" \
    NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" status --esp "$tmp/esp" >/dev/null 2>&1
then
    echo "narf-uefi status accepted a stale ESP kernel" >&2
    exit 1
fi
cp "$tmp/tree/usr/lib/narf/uefi/narf-frame" "$tmp/esp/EFI/NARF/narf-frame"

mkdir -p "$tmp/mock-bin"
printf '%s\n' '#!/bin/sh' 'set -eu' '[ "$1" = --target=fs_uuid ]' 'case "$2" in */EFI/NARF/narf.efi) ;; *) exit 1 ;; esac' 'echo 6D89-28C5' >"$tmp/mock-bin/grub-probe"
chmod +x "$tmp/mock-bin/grub-probe"
NARF_STATE_DIR="$tmp/state" NARF_BOOT_DIR="$tmp/tree/boot" \
    PATH="$tmp/mock-bin:$PATH" "$tmp/tree/etc/grub.d/42_narf" >"$tmp/grub.cfg"
grep -F 'if [ "${grub_platform}" = "efi" ]' "$tmp/grub.cfg" >/dev/null
grep -F 'search --no-floppy --fs-uuid --set=narf_esp 6D89-28C5' "$tmp/grub.cfg" >/dev/null
if grep -F 'search --no-floppy --file --set=narf_esp /EFI/NARF/narf.efi' "$tmp/grub.cfg" >/dev/null; then
    echo "GRUB menu searched all ESPs instead of the package ESP UUID" >&2
    exit 1
fi
grep -F 'set root=$narf_esp' "$tmp/grub.cfg" >/dev/null
grep -F 'chainloader /EFI/NARF/narf.efi' "$tmp/grub.cfg" >/dev/null
grep -F 'search --no-floppy --file --set=narf_root /narf-kernel-0.0.0-test.1' "$tmp/grub.cfg" >/dev/null
grep -F 'search --no-floppy --file --set=narf_root /boot/narf-kernel-0.0.0-test.1' "$tmp/grub.cfg" >/dev/null

NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" remove --esp "$tmp/esp" --no-manager-hooks
test ! -e "$tmp/esp/EFI/NARF/narf.efi"
test ! -e "$tmp/esp/EFI/NARF/narf-frame"
test ! -e "$tmp/esp/boot/limine/limine.conf"
test ! -e "$tmp/esp/loader/entries/narf.conf"

# An administrator can opt into sbctl signing once. The helper remembers that
# local policy and re-signs future package upgrades before publishing the EFI
# entry, without storing or reading private-key files itself.
mkdir -p "$tmp/mock-bin" "$tmp/sbctl-esp"
cat >"$tmp/mock-bin/sbctl" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    sign)
        shift
        [ "$1" = --output ]
        output=$2
        input=$3
        cp "$input" "$output"
        printf '\nNARF_TEST_SBCTL_SIGNATURE\n' >>"$output"
        ;;
    verify)
        grep -aFq NARF_TEST_SBCTL_SIGNATURE "$2"
        ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$tmp/mock-bin/sbctl"
PATH="$tmp/mock-bin:$PATH" \
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/sbctl-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install --esp "$tmp/sbctl-esp" \
    --sign-with-sbctl --no-manager-hooks --quiet
grep -aFq NARF_TEST_SBCTL_SIGNATURE "$tmp/sbctl-esp/EFI/NARF/narf.efi"
PATH="$tmp/mock-bin:$PATH" \
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/sbctl-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" status --esp "$tmp/sbctl-esp" \
    --no-manager-hooks --quiet
recorded_signed_hash=$(sed -n '1p' "$tmp/sbctl-state/sbctl-sign")
installed_signed_hash=$(sha256sum "$tmp/sbctl-esp/EFI/NARF/narf.efi" | awk '{print $1}')
test "${#recorded_signed_hash}" -eq 64
test "$recorded_signed_hash" = "$installed_signed_hash"
printf '\nNARF_TEST_TAMPER\n' >>"$tmp/sbctl-esp/EFI/NARF/narf.efi"
if PATH="$tmp/mock-bin:$PATH" \
    NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
    NARF_UEFI_STATE_DIR="$tmp/sbctl-state" \
    NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" status --esp "$tmp/sbctl-esp" \
        --no-manager-hooks --quiet >/dev/null 2>&1
then
    echo "narf-uefi status accepted a modified locally signed loader" >&2
    exit 1
fi
# No flag on the second install: the saved administrator policy still signs.
PATH="$tmp/mock-bin:$PATH" \
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/sbctl-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install --esp "$tmp/sbctl-esp" \
    --no-manager-hooks --quiet
grep -aFq NARF_TEST_SBCTL_SIGNATURE "$tmp/sbctl-esp/EFI/NARF/narf.efi"
# An explicit opt-out replaces the local signature with the package payload
# and removes the persisted signing preference.
PATH="$tmp/mock-bin:$PATH" \
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/sbctl-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install --esp "$tmp/sbctl-esp" \
    --no-sbctl-sign --no-manager-hooks --quiet
cmp "$tmp/tree/usr/lib/narf/uefi/narf.efi" "$tmp/sbctl-esp/EFI/NARF/narf.efi"
test ! -e "$tmp/sbctl-state/sbctl-sign"
PATH="$tmp/mock-bin:$PATH" \
NARF_UEFI_STATE_DIR="$tmp/sbctl-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" remove --esp "$tmp/sbctl-esp" \
    --no-manager-hooks --quiet

# An existing Limine installation owns its own config. NARF may install its
# isolated payload and native menu registration, but must not shadow that
# boot policy with the GRUB-only fallback.
mkdir -p "$tmp/esp/EFI/BOOT"
printf 'host Limine 99.0\n' >"$tmp/esp/EFI/BOOT/BOOTX64.EFI"
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install --esp "$tmp/esp" --no-manager-hooks
test -f "$tmp/esp/EFI/NARF/narf.efi"
test ! -e "$tmp/esp/boot/limine/limine.conf"
grep -F 'host Limine 99.0' "$tmp/esp/EFI/BOOT/BOOTX64.EFI" >/dev/null
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" remove --esp "$tmp/esp" --no-manager-hooks
grep -F 'host Limine 99.0' "$tmp/esp/EFI/BOOT/BOOTX64.EFI" >/dev/null
sh -n "$tmp/tree/usr/bin/narf-uefi" "$tmp/tree/etc/grub.d/42_narf"

# A pre-package hardware entry may still boot ESP:/boot/narf-frame, with
# firmware and a root-rw graphical command line. Adopting it must refresh the
# image it actually loads, preserve policy, and persist across package hooks.
host_esp=$tmp/host-esp
host_state=$tmp/host-state
host_config=$host_esp/boot/limine/limine.conf
mkdir -p "$host_esp/boot/limine" "$host_esp/EFI/BOOT"
printf 'host Limine 99.0\n' >"$host_esp/EFI/BOOT/BOOTX64.EFI"
printf 'old hardware kernel\n' >"$host_esp/boot/narf-frame"
printf 'firmware initramfs\n' >"$host_esp/boot/initramfs.cpio"
cat >"$host_config" <<'EOF'
timeout: 5
default_entry: 2
/NARF KDE Plasma (read-write)
    protocol: multiboot2
    path: boot():/boot/narf-frame
    kernel_cmdline: narf.disks=root-rw root=UUID=test rw systemd_pid1 systemd.unit=graphical.target
    module_path: boot():/boot/initramfs.cpio
    module_string: initramfs
/CachyOS
    protocol: linux
    path: boot():/vmlinuz-linux-cachyos
EOF
cp "$host_config" "$tmp/host-original.conf"
cp "$host_esp/boot/narf-frame" "$tmp/host-original-kernel"
host_uefi() {
    NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
    NARF_UEFI_STATE_DIR="$host_state" NARF_UEFI_ALLOW_NON_ESP=1 \
        "$tmp/tree/usr/bin/narf-uefi" "$@" --esp "$host_esp" --no-manager-hooks --quiet
}
host_uefi install --limine-config "$host_config"
cmp "$tmp/tree/usr/lib/narf/uefi/narf-frame" "$host_esp/boot/narf-frame"
cmp "$tmp/host-original-kernel" "$host_state/limine-kernel-before-package"
cmp "$tmp/host-original.conf" "$host_config"
grep -Fx 'firmware initramfs' "$host_esp/boot/initramfs.cpio" >/dev/null
host_uefi status | grep -Fx 'host Limine kernel matches package: yes' >/dev/null
printf 'stale hardware kernel\n' >"$host_esp/boot/narf-frame"
if host_uefi status >"$tmp/host-status.log" 2>&1; then
    echo 'status accepted the stale kernel selected by the host Limine entry' >&2
    exit 1
fi
grep -F 'stale: host Limine entry loads a different NARF kernel' "$tmp/host-status.log" >/dev/null
host_uefi install
cmp "$tmp/tree/usr/lib/narf/uefi/narf-frame" "$host_esp/boot/narf-frame"
cmp "$tmp/host-original-kernel" "$host_state/limine-kernel-before-package"
cmp "$tmp/host-original.conf" "$host_config"

# Ambiguous menus and hash-pinned older images must fail before publishing
# any payload. The administrator must first disambiguate the selected entry.
cat >>"$host_config" <<'EOF'
/NARF duplicate
    protocol: multiboot2
    path: boot():/boot/narf-frame
EOF
printf 'do not overwrite\n' >"$host_esp/boot/narf-frame"
printf 'do not overwrite\n' >"$host_esp/EFI/NARF/narf-frame"
if host_uefi install >/dev/null 2>&1; then
    echo 'install accepted multiple host NARF entries' >&2
    exit 1
fi
grep -Fx 'do not overwrite' "$host_esp/boot/narf-frame" >/dev/null
grep -Fx 'do not overwrite' "$host_esp/EFI/NARF/narf-frame" >/dev/null
sed 's@path: boot():/boot/narf-frame$@path: boot():/boot/narf-frame#old-digest@' \
    "$tmp/host-original.conf" >"$host_config"
if host_uefi install >/dev/null 2>&1; then
    echo 'install accepted a host entry pinned to an older kernel digest' >&2
    exit 1
fi
grep -Fx 'do not overwrite' "$host_esp/boot/narf-frame" >/dev/null
if host_uefi install --limine-config "$tmp/host-original.conf" >/dev/null 2>&1; then
    echo 'install accepted a host config outside the selected ESP' >&2
    exit 1
fi
cp "$tmp/host-original.conf" "$host_config"
host_uefi install
host_uefi status >/dev/null
host_uefi remove
test ! -e "$host_state/limine-config"
cmp "$tmp/host-original.conf" "$host_config"
cmp "$tmp/tree/usr/lib/narf/uefi/narf-frame" "$host_esp/boot/narf-frame"

# Exercise the source-installable Cargo frontend as well as the underlying
# release builder. It must produce the same package layout without installing
# anything on the host.
NARF_LIMINE_EFI=/does/not/exist NARF_SKIP_GRUB_CHECK=1 \
    cargo run -q -p cargo-narf -- narf package --version 0.0.0-test.1 \
    --limine-efi "$tmp/BOOTX64.EFI" \
    --limine-tool "$tmp/limine-tool" \
    --formats tar --skip-build --output "$tmp/cargo-out" \
    --source-date-epoch 1700000000
test -f "$tmp/cargo-out/narf-0.0.0-test.1-x86_64.tar.gz"
tar -tzf "$tmp/cargo-out/narf-0.0.0-test.1-x86_64.tar.gz" |
    grep -F './boot/narf-kernel-0.0.0-test.1' >/dev/null

# Exercise explicit distribution signing without requiring a real private key
# in the ordinary layout test. test-secure-boot.sh covers real sbsign/sbverify
# and firmware enforcement with an ephemeral certificate.
mkdir -p "$tmp/mock-sign-bin"
printf test-key >"$tmp/db.key"
printf test-cert >"$tmp/db.crt"
cat >"$tmp/mock-sign-bin/sbsign" <<'EOF'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case "$1" in
        --key|--cert) shift 2 ;;
        --output) output=$2; shift 2 ;;
        *) input=$1; shift ;;
    esac
done
cp "$input" "$output"
printf '\nNARF_TEST_SBSIGN_SIGNATURE\n' >>"$output"
EOF
cat >"$tmp/mock-sign-bin/sbverify" <<'EOF'
#!/bin/sh
set -eu
grep -aFq NARF_TEST_SBSIGN_SIGNATURE "$3"
EOF
chmod +x "$tmp/mock-sign-bin/sbsign" "$tmp/mock-sign-bin/sbverify"
PATH="$tmp/mock-sign-bin:$PATH" NARF_SKIP_GRUB_CHECK=1 \
    packaging/build-release.sh --version 0.0.0-signed-test --skip-build \
    --limine-efi "$tmp/BOOTX64.EFI" --formats tar \
    --secure-boot-key "$tmp/db.key" --secure-boot-cert "$tmp/db.crt" \
    --output "$tmp/signed-out" --source-date-epoch 1700000000
mkdir -p "$tmp/signed-tree"
tar -xzf "$tmp/signed-out/narf-0.0.0-signed-test-x86_64.tar.gz" \
    -C "$tmp/signed-tree"
grep -Fx yes "$tmp/signed-tree/usr/lib/narf/uefi/secure-boot-signed" >/dev/null
grep -aFq NARF_TEST_SBSIGN_SIGNATURE "$tmp/signed-tree/usr/lib/narf/uefi/narf.efi"

# Native aarch64 packages use NARF's own EFI loader. The package builder binds
# it to the exact stripped kernel, and the administrator helper emits an AA64
# BLS entry without installing Limine configuration files. A mock rpmbuild
# also checks that cross-generated RPMs select their declared target instead
# of inheriting the x86_64 CI container architecture.
cat >"$tmp/mock-bin/rpmbuild" <<'EOF'
#!/bin/sh
set -eu
target=
top=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target) target=$2; shift 2 ;;
        --define)
            case "$2" in
                '_topdir '*) top=${2#_topdir } ;;
            esac
            shift 2
            ;;
        *) shift ;;
    esac
done
[ "$target" = aarch64 ]
[ -n "$top" ]
mkdir -p "$top/RPMS/$target"
printf 'mock aarch64 rpm\n' >"$top/RPMS/$target/narf-kernel-test.$target.rpm"
printf '%s\n' "$target" >"$NARF_TEST_RPM_LOG"
EOF
chmod +x "$tmp/mock-bin/rpmbuild"
arm_formats=tar,rpm
if command -v dpkg-deb >/dev/null 2>&1; then
    arm_formats=tar,rpm,deb
fi
PATH="$tmp/mock-bin:$PATH" NARF_TEST_RPM_LOG="$tmp/rpm-target" \
    packaging/build-release.sh --version 0.0.0-test.1 --arch aarch64 --skip-build \
    --uefi-loader "$tmp/BOOTAA64.EFI" --formats "$arm_formats" \
    --output "$tmp/arm-out" --source-date-epoch 1700000000
test -f "$tmp/arm-out/narf-0.0.0-test.1-aarch64.tar.gz"
grep -Fx aarch64 "$tmp/rpm-target" >/dev/null
test -f "$tmp/arm-out/narf-kernel-test.aarch64.rpm"
if command -v dpkg-deb >/dev/null 2>&1; then
    test -f "$tmp/arm-out/narf-kernel_0.0.0-test.1_arm64.deb"
    test "$(dpkg-deb --field "$tmp/arm-out/narf-kernel_0.0.0-test.1_arm64.deb" Architecture)" = arm64
fi
PATH="$tmp/mock-sign-bin:$PATH" \
    packaging/build-release.sh --version 0.0.0-arm-signed-test \
    --arch aarch64 --skip-build --uefi-loader "$tmp/BOOTAA64.EFI" \
    --formats tar --secure-boot-key "$tmp/db.key" \
    --secure-boot-cert "$tmp/db.crt" --output "$tmp/arm-signed-out" \
    --source-date-epoch 1700000000
mkdir -p "$tmp/arm-signed-tree"
tar -xzf "$tmp/arm-signed-out/narf-0.0.0-arm-signed-test-aarch64.tar.gz" \
    -C "$tmp/arm-signed-tree"
grep -Fx yes \
    "$tmp/arm-signed-tree/usr/lib/narf/uefi/secure-boot-signed" >/dev/null
grep -aFq NARF_TEST_SBSIGN_SIGNATURE \
    "$tmp/arm-signed-tree/usr/lib/narf/uefi/narf.efi"
mkdir -p "$tmp/arm-tree" "$tmp/arm-esp"
tar -xzf "$tmp/arm-out/narf-0.0.0-test.1-aarch64.tar.gz" -C "$tmp/arm-tree"
grep -Fx aarch64 "$tmp/arm-tree/usr/lib/narf/uefi/arch" >/dev/null
grep -Fx narf "$tmp/arm-tree/usr/lib/narf/uefi/loader-kind" >/dev/null
test ! -e "$tmp/arm-tree/usr/lib/narf/uefi/limine.conf"
packaging/bind-aarch64-uefi.py "$tmp/BOOTAA64.EFI" \
    target/narf-frame-aarch64.efi-elf "$tmp/expected-BOOTAA64.EFI"
cmp "$tmp/expected-BOOTAA64.EFI" "$tmp/arm-tree/usr/lib/narf/uefi/narf.efi"
packaging/bind-aarch64-uefi.py "$tmp/expected-BOOTAA64.EFI" \
    target/narf-frame-aarch64.efi-elf "$tmp/rebound-BOOTAA64.EFI"
cmp "$tmp/expected-BOOTAA64.EFI" "$tmp/rebound-BOOTAA64.EFI"
printf 'different kernel\n' >"$tmp/different-arm-kernel"
if packaging/bind-aarch64-uefi.py "$tmp/expected-BOOTAA64.EFI" \
    "$tmp/different-arm-kernel" "$tmp/wrong-BOOTAA64.EFI" >/dev/null 2>&1
then
    echo "aarch64 binder accepted a loader bound to a different kernel" >&2
    exit 1
fi
NARF_UEFI_SOURCE_DIR="$tmp/arm-tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/arm-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/arm-tree/usr/bin/narf-uefi" install \
    --esp "$tmp/arm-esp" --no-manager-hooks --quiet
grep -F 'architecture aa64' "$tmp/arm-esp/loader/entries/narf.conf" >/dev/null
test ! -e "$tmp/arm-esp/EFI/NARF/limine.conf"
test ! -e "$tmp/arm-esp/boot/limine/limine.conf"
NARF_UEFI_SOURCE_DIR="$tmp/arm-tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/arm-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/arm-tree/usr/bin/narf-uefi" status \
    --esp "$tmp/arm-esp" --no-manager-hooks --quiet
NARF_UEFI_SOURCE_DIR="$tmp/arm-tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/arm-state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/arm-tree/usr/bin/narf-uefi" remove \
    --esp "$tmp/arm-esp" --no-manager-hooks --quiet

if [[ -f $tmp/created ]]; then
    while IFS= read -r path; do rm -f "$path"; done <"$tmp/created"
fi
echo "packaging tests passed"
