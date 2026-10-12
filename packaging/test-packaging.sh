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
for path in target/x86_64-unknown-none/release/narf-frame
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
test -f "$tmp/out/gentoo/sys-kernel/narf-kernel/narf-kernel-0.0.0-test.1.ebuild"
test -f "$tmp/out/release-manifest.json"
(cd "$tmp/out" && sha256sum -c SHA256SUMS)
tar -tzf "$tmp/out/narf-0.0.0-test.1-x86_64.tar.gz" |
    grep -F './boot/narf-kernel-0.0.0-test.1' >/dev/null
for packaged_path in \
    ./usr/bin/narf-uefi \
    ./usr/lib/narf/uefi/narf.efi \
    ./usr/lib/narf/uefi/narf-frame \
    ./usr/lib/narf/uefi/version \
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
NARF_UEFI_SOURCE_DIR="$tmp/tree/usr/lib/narf/uefi" \
NARF_UEFI_STATE_DIR="$tmp/state" \
NARF_UEFI_ALLOW_NON_ESP=1 \
    "$tmp/tree/usr/bin/narf-uefi" install --esp "$tmp/esp" --no-manager-hooks
cmp "$tmp/BOOTX64.EFI" "$tmp/esp/EFI/NARF/narf.efi"
cmp "$tmp/tree/boot/narf-kernel-0.0.0-test.1" "$tmp/esp/EFI/NARF/narf-frame"
grep -F 'path: boot():/EFI/NARF/narf-frame' "$tmp/esp/EFI/NARF/limine.conf" >/dev/null
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

NARF_BOOT_DIR="$tmp/tree/boot" "$tmp/tree/etc/grub.d/42_narf" >"$tmp/grub.cfg"
grep -F 'if [ "${grub_platform}" = "efi" ]' "$tmp/grub.cfg" >/dev/null
grep -F 'search --no-floppy --file --set=narf_esp /EFI/NARF/narf.efi' "$tmp/grub.cfg" >/dev/null
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

# Exercise the source-installable Cargo frontend as well as the underlying
# release builder. It must produce the same package layout without installing
# anything on the host.
NARF_LIMINE_EFI=/does/not/exist cargo run -q -p cargo-narf -- narf package --version 0.0.0-test.1 \
    --limine-efi "$tmp/BOOTX64.EFI" \
    --formats tar --skip-build --output "$tmp/cargo-out" \
    --source-date-epoch 1700000000
test -f "$tmp/cargo-out/narf-0.0.0-test.1-x86_64.tar.gz"
tar -tzf "$tmp/cargo-out/narf-0.0.0-test.1-x86_64.tar.gz" |
    grep -F './boot/narf-kernel-0.0.0-test.1' >/dev/null

if [[ -f $tmp/created ]]; then
    while IFS= read -r path; do rm -f "$path"; done <"$tmp/created"
fi
echo "packaging tests passed"
