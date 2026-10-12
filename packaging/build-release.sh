#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: packaging/build-release.sh --version VERSION
       [--formats all|deb,rpm,arch,gentoo,tar] [--skip-build]
       [--arch auto|x86_64|aarch64] [--output DIR] [--source-date-epoch EPOCH]
       [--uefi-loader FILE] [--limine-efi FILE] [--limine-tool FILE]
       [--secure-boot-key FILE --secure-boot-cert FILE]
EOF
    exit 2
}

version=
arch=auto
formats=all
skip_build=0
output=
source_epoch=${SOURCE_DATE_EPOCH:-}
limine_efi=${NARF_LIMINE_EFI:-}
uefi_loader=${NARF_UEFI_LOADER:-}
limine_tool=${NARF_LIMINE_TOOL:-}
secure_boot_key=${NARF_SECURE_BOOT_KEY:-}
secure_boot_cert=${NARF_SECURE_BOOT_CERT:-}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) [[ $# -ge 2 ]] || usage; version=${2#v}; shift 2 ;;
        --arch) [[ $# -ge 2 ]] || usage; arch=$2; shift 2 ;;
        --formats) [[ $# -ge 2 ]] || usage; formats=$2; shift 2 ;;
        --skip-build) skip_build=1; shift ;;
        --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
        --source-date-epoch) [[ $# -ge 2 ]] || usage; source_epoch=$2; shift 2 ;;
        --limine-efi) [[ $# -ge 2 ]] || usage; limine_efi=$2; shift 2 ;;
        --uefi-loader) [[ $# -ge 2 ]] || usage; uefi_loader=$2; shift 2 ;;
        --limine-tool) [[ $# -ge 2 ]] || usage; limine_tool=$2; shift 2 ;;
        --secure-boot-key) [[ $# -ge 2 ]] || usage; secure_boot_key=$2; shift 2 ;;
        --secure-boot-cert) [[ $# -ge 2 ]] || usage; secure_boot_cert=$2; shift 2 ;;
        *) usage ;;
    esac
done
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
    { echo "invalid or missing semantic version: ${version:-<empty>}" >&2; exit 1; }
if [[ $arch == auto ]]; then
    case "$(uname -m)" in
        x86_64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *)
            echo "cannot infer NARF package architecture from $(uname -m); pass --arch" >&2
            exit 1
            ;;
    esac
fi
[[ $arch == x86_64 || $arch == aarch64 ]] || {
    echo "unsupported architecture: $arch" >&2
    exit 1
}
if [[ -n $limine_efi ]]; then
    [[ $arch == x86_64 ]] || {
        echo "--limine-efi is x86_64-only; use --uefi-loader for aarch64" >&2
        exit 1
    }
    [[ -z $uefi_loader ]] || {
        echo "pass only one of --limine-efi and --uefi-loader" >&2
        exit 1
    }
    uefi_loader=$limine_efi
fi
if [[ -n $secure_boot_key || -n $secure_boot_cert ]]; then
    [[ -f $secure_boot_key && -f $secure_boot_cert ]] || {
        echo "--secure-boot-key and --secure-boot-cert must name existing files and be used together" >&2
        exit 1
    }
fi

root=$(git rev-parse --show-toplevel)
cd "$root"
output=${output:-target/release-assets/$version}
[[ $output = /* ]] || output=$root/$output
source_epoch=${source_epoch:-$(git log -1 --format=%ct)}
[[ $source_epoch =~ ^[0-9]+$ ]] ||
    { echo "SOURCE_DATE_EPOCH must be an integer" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case "$arch" in
    x86_64)
        target_triple=x86_64-unknown-none
        loader_kind=limine
        pe_machine=6486
        deb_arch=amd64
        rpm_arch=x86_64
        arch_pkg_arch=x86_64
        gentoo_keyword=amd64
        rpm_license='GPL-2.0-or-later AND BSD-2-Clause'
        arch_license="'GPL-2.0-or-later' 'BSD-2-Clause'"
        gentoo_license='GPL-2+ BSD-2'
        if [[ $skip_build -eq 0 ]]; then
            SOURCE_DATE_EPOCH=$source_epoch cargo xtask build --arch=x86_64
        fi
        kernel=$root/target/$target_triple/release/narf-frame
        ;;
    aarch64)
        target_triple=aarch64-unknown-none
        loader_kind=narf
        pe_machine=64aa
        deb_arch=arm64
        rpm_arch=aarch64
        arch_pkg_arch=aarch64
        gentoo_keyword=arm64
        rpm_license='GPL-2.0-or-later'
        arch_license="'GPL-2.0-or-later'"
        gentoo_license='GPL-2+'
        if [[ $skip_build -eq 0 ]]; then
            SOURCE_DATE_EPOCH=$source_epoch cargo xtask image --arch=aarch64
        fi
        kernel=$root/target/narf-frame-aarch64.efi-elf
        ;;
esac

[[ -f $kernel ]] || {
    echo "missing canonical $arch kernel artifact: $kernel" >&2
    echo "run without --skip-build to build it" >&2
    exit 1
}
if [[ $arch == x86_64 && ${NARF_SKIP_GRUB_CHECK:-0} != 1 ]] &&
    command -v grub-file >/dev/null 2>&1; then
    grub-file --is-x86-multiboot2 "$kernel" || {
        echo "kernel does not contain a valid Multiboot2 header" >&2
        exit 1
    }
fi

if [[ -z $uefi_loader ]]; then
    if [[ $arch == x86_64 ]]; then
        candidates=(
            "$root/target/narf-uefi/BOOTX64.EFI"
            "$root/target/iso-x86_64/EFI/BOOT/BOOTX64.EFI"
        )
        if [[ -n ${LIMINE_PATH:-} ]]; then
            candidates+=("$LIMINE_PATH/BOOTX64.EFI")
        fi
        candidates+=(
            /usr/share/limine/BOOTX64.EFI
            /usr/local/share/limine/BOOTX64.EFI
            "$root/vendor/limine/BOOTX64.EFI"
        )
    else
        candidates=(
            "$root/target/uefi-loader/aarch64-unknown-uefi/release/narf-uefi-loader.efi"
            "$root/target/narf-uefi-aarch64/narf.efi"
        )
    fi
    for candidate in "${candidates[@]}"; do
        if [[ -f $candidate ]]; then
            uefi_loader=$candidate
            break
        fi
    done
fi
[[ -f $uefi_loader ]] || {
    echo "missing $arch UEFI loader" >&2
    echo "pass --uefi-loader FILE or run without --skip-build" >&2
    exit 1
}

validate_efi() {
    local image=$1 magic pe_offset pe_header
    magic=$(od -An -tx1 -N2 "$image" | tr -d ' \n')
    pe_offset=$(od -An -tu4 -j60 -N4 "$image" | tr -d ' \n')
    if [[ $pe_offset =~ ^[0-9]+$ ]] && ((pe_offset <= 1048576)); then
        pe_header=$(dd if="$image" bs=1 skip="$pe_offset" count=6 2>/dev/null |
            od -An -tx1 | tr -d ' \n')
    else
        pe_header=
    fi
    [[ $magic == 4d5a && $pe_header == "50450000$pe_machine" ]] || {
        echo "$image is not a $arch PE/COFF EFI executable" >&2
        return 1
    }
}
validate_efi "$uefi_loader"

kernel_b2sum=$(b2sum -l 512 "$kernel" | awk '{print $1}')
bound_loader=$work/narf.efi
if [[ $loader_kind == limine ]]; then
    config=$work/limine.conf
    cat >"$config" <<EOF
# Managed by narf-uefi
timeout: 5
serial: yes
verbose: yes
quiet: no
default_entry: 1

/NARF $version
    protocol: multiboot2
    path: boot():/EFI/NARF/narf-frame#$kernel_b2sum
EOF
    if [[ -z $limine_tool ]]; then
        if [[ -n ${LIMINE_PATH:-} && -x $LIMINE_PATH/limine ]]; then
            limine_tool=$LIMINE_PATH/limine
        elif command -v limine >/dev/null 2>&1; then
            limine_tool=$(command -v limine)
        fi
    fi
    if [[ -n $limine_tool ]]; then
        [[ -x $limine_tool ]] || {
            echo "Limine host tool is not executable: $limine_tool" >&2
            exit 1
        }
        cp "$uefi_loader" "$bound_loader"
        config_b2sum=$(b2sum -l 512 "$config" | awk '{print $1}')
        "$limine_tool" enroll-config "$bound_loader" "$config_b2sum"
    else
        packaging/bind-limine-config.py "$uefi_loader" "$config" "$bound_loader"
    fi
    verified_loader=$work/narf.efi.verified
    packaging/bind-limine-config.py "$bound_loader" "$config" "$verified_loader"
    mv "$verified_loader" "$bound_loader"
else
    packaging/bind-aarch64-uefi.py "$uefi_loader" "$kernel" "$bound_loader"
fi

secure_boot_signed=no
if [[ -n $secure_boot_key ]]; then
    command -v sbsign >/dev/null 2>&1 || {
        echo "Secure Boot signing requires sbsign" >&2
        exit 1
    }
    command -v sbverify >/dev/null 2>&1 || {
        echo "Secure Boot signing requires sbverify" >&2
        exit 1
    }
    signed_loader=$work/narf.efi.signed
    sbsign --key "$secure_boot_key" --cert "$secure_boot_cert" \
        --output "$signed_loader" "$bound_loader"
    sbverify --cert "$secure_boot_cert" "$signed_loader"
    mv "$signed_loader" "$bound_loader"
    secure_boot_signed=yes
fi
validate_efi "$bound_loader"

stage=$work/stage
mkdir -p "$stage/boot" "$stage/etc/grub.d" \
    "$stage/usr/bin" "$stage/usr/lib/narf/uefi" \
    "$stage/usr/share/doc/narf" "$stage/usr/share/licenses/narf"
install -m 0644 "$kernel" "$stage/boot/narf-kernel-$version"
install -m 0755 packaging/42_narf "$stage/etc/grub.d/42_narf"
install -m 0755 packaging/narf-uefi "$stage/usr/bin/narf-uefi"
install -m 0644 "$bound_loader" "$stage/usr/lib/narf/uefi/narf.efi"
install -m 0644 "$kernel" "$stage/usr/lib/narf/uefi/narf-frame"
printf '%s\n' "$version" >"$stage/usr/lib/narf/uefi/version"
printf '%s\n' "$arch" >"$stage/usr/lib/narf/uefi/arch"
printf '%s\n' "$loader_kind" >"$stage/usr/lib/narf/uefi/loader-kind"
printf '%s\n' "$kernel_b2sum" >"$stage/usr/lib/narf/uefi/kernel.blake2b"
printf '%s\n' "$secure_boot_signed" >"$stage/usr/lib/narf/uefi/secure-boot-signed"
if [[ $loader_kind == limine ]]; then
    install -m 0644 "$config" "$stage/usr/lib/narf/uefi/limine.conf"
fi
install -m 0644 LICENSE README.md "$stage/usr/share/doc/narf/"
install -m 0644 packaging/README.md "$stage/usr/share/doc/narf/PACKAGING.md"
if [[ $loader_kind == limine ]]; then
    install -m 0644 packaging/LIMINE-LICENSE "$stage/usr/share/licenses/narf/LIMINE"
fi
find "$stage" -exec touch -h -d "@$source_epoch" {} +

rm -rf "$output"
mkdir -p "$output"
payload="narf-${version}-${arch}"
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
    -C "$stage" -czf "$output/$payload.tar.gz" .

requested() {
    [[ $formats == all || ,$formats, == *",$1,"* ]]
}
need() {
    if command -v "$1" >/dev/null 2>&1; then return 0; fi
    if [[ $formats == all ]]; then
        echo "skipping $2: $1 is unavailable" >&2
        return 1
    fi
    echo "cannot build requested $2 package: install $1" >&2
    exit 1
}

build_deb() {
    need dpkg-deb deb || return
    local tree=$work/deb
    cp -a "$stage" "$tree"
    mkdir -p "$tree/DEBIAN"
    cat >"$tree/DEBIAN/control" <<EOF
Package: narf-kernel
Version: $version
Section: kernel
Priority: optional
Architecture: $deb_arch
Maintainer: NARF maintainers
Depends: util-linux
Suggests: grub-common
Homepage: https://github.com/hodgesds/narf
Description: NARF framekernel boot image
 NARF is an async-first framekernel with hardware-isolated domains.
EOF
    cat >"$tree/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
/usr/bin/narf-uefi install || \
    echo "narf-kernel: warning: UEFI payload installation failed" >&2
if command -v update-grub >/dev/null 2>&1; then update-grub; fi
exit 0
EOF
    cat >"$tree/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "${1:-}" = remove ]; then
    /usr/bin/narf-uefi remove || \
        echo "narf-kernel: warning: UEFI payload removal failed" >&2
fi
exit 0
EOF
    cat >"$tree/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v update-grub >/dev/null 2>&1; then update-grub; fi
exit 0
EOF
    chmod 0755 "$tree/DEBIAN/postinst" "$tree/DEBIAN/prerm" "$tree/DEBIAN/postrm"
    find "$tree" -exec touch -h -d "@$source_epoch" {} +
    dpkg-deb --root-owner-group --build "$tree" "$output/narf-kernel_${version}_${deb_arch}.deb"
}

build_rpm() {
    need rpmbuild rpm || return
    local top=$work/rpmbuild spec=$work/narf-kernel.spec
    mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    cp "$output/$payload.tar.gz" "$top/SOURCES/"
    cat >"$spec" <<EOF
Name: narf-kernel
Version: $version
Release: 1%{?dist}
Summary: NARF framekernel boot image
License: $rpm_license
URL: https://github.com/hodgesds/narf
Source0: $payload.tar.gz
BuildArch: $rpm_arch
Requires: coreutils, grep, sed, util-linux
Suggests: grub2-tools, sbctl

%description
NARF is an async-first framekernel with hardware-isolated domains.

%prep
%setup -q -c -T
tar -xzf %{SOURCE0}

%install
mkdir -p %{buildroot}
cp -a boot etc usr %{buildroot}/

%files
/boot/narf-kernel-$version
/etc/grub.d/42_narf
/usr/bin/narf-uefi
/usr/lib/narf/uefi/
/usr/share/doc/narf/
/usr/share/licenses/narf/

%post
/usr/bin/narf-uefi install || \
  echo "narf-kernel: warning: UEFI payload installation failed" >&2
if command -v grub2-mkconfig >/dev/null 2>&1; then
  grub2-mkconfig -o /boot/grub2/grub.cfg
fi

%preun
if [ \$1 -eq 0 ]; then
  /usr/bin/narf-uefi remove || \
    echo "narf-kernel: warning: UEFI payload removal failed" >&2
fi

%postun
if command -v grub2-mkconfig >/dev/null 2>&1; then
  grub2-mkconfig -o /boot/grub2/grub.cfg
fi
EOF
    rpmbuild --target "$rpm_arch" --define "_topdir $top" \
        --define "_source_date_epoch $source_epoch" -bb "$spec"
    find "$top/RPMS" -type f -name '*.rpm' -exec cp {} "$output/" \;
}

build_arch() {
    need makepkg arch || return
    local dir=$work/arch makepkg_bin
    makepkg_bin=$(command -v makepkg)
    mkdir -p "$dir"
    cp "$output/$payload.tar.gz" "$dir/"
    local sum
    sum=$(sha256sum "$dir/$payload.tar.gz" | awk '{print $1}')
    cat >"$dir/PKGBUILD" <<EOF
pkgname=narf-kernel
pkgver=$version
pkgrel=1
pkgdesc='NARF framekernel boot image'
arch=('$arch_pkg_arch')
url='https://github.com/hodgesds/narf'
license=($arch_license)
depends=('coreutils' 'grep' 'sed' 'util-linux')
optdepends=('grub: GRUB BIOS or UEFI menu integration'
            'limine-tool: CachyOS Limine menu integration'
            'refind: automatic EFI loader discovery'
            'sbctl: local Secure Boot signing and key management')
source=('$payload.tar.gz')
sha256sums=('$sum')
install=narf-kernel.install
package() {
  cp -a "\$srcdir/boot" "\$srcdir/etc" "\$srcdir/usr" "\$pkgdir/"
}
EOF
    cat >"$dir/narf-kernel.install" <<'EOF'
post_install() {
  /usr/bin/narf-uefi install ||
    echo 'narf-kernel: warning: UEFI payload installation failed' >&2
  if command -v grub-mkconfig >/dev/null; then
    grub-mkconfig -o /boot/grub/grub.cfg
  fi
}
post_upgrade() { post_install; }
pre_remove() {
  /usr/bin/narf-uefi remove ||
    echo 'narf-kernel: warning: UEFI payload removal failed' >&2
}
post_remove() {
  if command -v grub-mkconfig >/dev/null; then
    grub-mkconfig -o /boot/grub/grub.cfg
  fi
}
EOF
    if [[ $(id -u) -eq 0 ]]; then
        need runuser arch || return
        id nobody >/dev/null 2>&1 || {
            echo "cannot build Arch package as root: the nobody account is unavailable" >&2
            exit 1
        }
        local nobody_group
        nobody_group=$(id -gn nobody)
        chmod 0711 "$work"
        chown -R "nobody:$nobody_group" "$dir"
        (cd "$dir" && runuser -u nobody -- env SOURCE_DATE_EPOCH="$source_epoch" \
            "$makepkg_bin" --noconfirm --nodeps --ignorearch)
    else
        (cd "$dir" && SOURCE_DATE_EPOCH=$source_epoch \
            "$makepkg_bin" --noconfirm --nodeps --ignorearch)
    fi
    find "$dir" -maxdepth 1 -type f -name '*.pkg.tar.*' -exec cp {} "$output/" \;
}

build_gentoo() {
    local dir=$output/gentoo/sys-kernel/narf-kernel
    mkdir -p "$dir"
    cp "$output/$payload.tar.gz" "$dir/"
    cat >"$dir/narf-kernel-${version}.ebuild" <<EOF
EAPI=8
DESCRIPTION="NARF framekernel boot image"
HOMEPAGE="https://github.com/hodgesds/narf"
SRC_URI="https://github.com/hodgesds/narf/releases/download/v$version/$payload.tar.gz"
LICENSE="$gentoo_license"
SLOT="0"
KEYWORDS="~$gentoo_keyword"
RDEPEND="sys-apps/coreutils sys-apps/grep sys-apps/sed sys-apps/util-linux"

src_unpack() {
    mkdir -p "\${S}" || die
    cd "\${S}" || die
    unpack "\${A}"
}
src_install() {
    cp -a boot etc usr "\${D}/" || die
}
pkg_postinst() {
    /usr/bin/narf-uefi install || ewarn "NARF UEFI payload installation failed"
    if command -v grub-mkconfig >/dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg || die
    fi
}
pkg_prerm() {
    if [[ -z \${REPLACED_BY_VERSION} ]]; then
        /usr/bin/narf-uefi remove || ewarn "NARF UEFI payload removal failed"
    fi
}
EOF
}

requested deb && build_deb
requested rpm && build_rpm
requested arch && build_arch
requested gentoo && build_gentoo
if [[ $formats != all ]]; then
    IFS=, read -ra selected <<<"$formats"
    for format in "${selected[@]}"; do
        [[ $format =~ ^(deb|rpm|arch|gentoo|tar)$ ]] ||
            { echo "unknown format: $format" >&2; exit 1; }
    done
fi

commit=$(git rev-parse HEAD)
python3 - "$output" "$version" "$commit" "$source_epoch" <<'PY'
import hashlib, json, pathlib, sys
out, version, commit, epoch = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
files = []
for path in sorted(p for p in out.rglob("*") if p.is_file()):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    files.append({"path": str(path.relative_to(out)), "sha256": digest, "size": path.stat().st_size})
(out / "release-manifest.json").write_text(json.dumps({
    "schema_version": 1, "version": version, "git_commit": commit,
    "source_date_epoch": epoch, "artifacts": files,
}, indent=2) + "\n")
PY
(cd "$output" && find . -type f ! -name SHA256SUMS -printf '%P\n' | sort |
    xargs sha256sum >SHA256SUMS)
echo "release assets: $output"
