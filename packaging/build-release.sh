#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: packaging/build-release.sh --version VERSION
       [--formats all|deb,rpm,arch,gentoo,tar] [--skip-build]
       [--output DIR] [--source-date-epoch EPOCH]
EOF
    exit 2
}

version=
formats=all
skip_build=0
output=
source_epoch=${SOURCE_DATE_EPOCH:-}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) [[ $# -ge 2 ]] || usage; version=${2#v}; shift 2 ;;
        --formats) [[ $# -ge 2 ]] || usage; formats=$2; shift 2 ;;
        --skip-build) skip_build=1; shift ;;
        --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
        --source-date-epoch) [[ $# -ge 2 ]] || usage; source_epoch=$2; shift 2 ;;
        *) usage ;;
    esac
done
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
    { echo "invalid or missing semantic version: ${version:-<empty>}" >&2; exit 1; }

root=$(git rev-parse --show-toplevel)
cd "$root"
output=${output:-target/release-assets/$version}
[[ $output = /* ]] || output=$root/$output
source_epoch=${source_epoch:-$(git log -1 --format=%ct)}
[[ $source_epoch =~ ^[0-9]+$ ]] ||
    { echo "SOURCE_DATE_EPOCH must be an integer" >&2; exit 1; }

if [[ $skip_build -eq 0 ]]; then
    SOURCE_DATE_EPOCH=$source_epoch cargo xtask build --arch=x86_64
fi

kernel=$root/target/x86_64-unknown-none/release/narf-frame
[[ -f $kernel ]] || {
    echo "missing canonical kernel artifact: $kernel" >&2
    echo "run without --skip-build to build it" >&2
    exit 1
}
if [[ ${NARF_SKIP_GRUB_CHECK:-0} != 1 ]] && command -v grub-file >/dev/null 2>&1; then
    grub-file --is-x86-multiboot2 "$kernel" || {
        echo "kernel does not contain a valid Multiboot2 header" >&2
        exit 1
    }
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stage=$work/stage
mkdir -p "$stage/boot" "$stage/etc/grub.d" "$stage/usr/share/doc/narf"
install -m 0644 "$kernel" "$stage/boot/narf-frame-$version"
install -m 0755 packaging/42_narf "$stage/etc/grub.d/42_narf"
install -m 0644 LICENSE README.md "$stage/usr/share/doc/narf/"
install -m 0644 packaging/README.md "$stage/usr/share/doc/narf/PACKAGING.md"
find "$stage" -exec touch -h -d "@$source_epoch" {} +

rm -rf "$output"
mkdir -p "$output"
payload="narf-${version}-x86_64"
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
Architecture: amd64
Maintainer: NARF maintainers
Depends: grub-common
Homepage: https://github.com/hodgesds/narf
Description: NARF framekernel boot image
 NARF is an async-first framekernel with hardware-isolated domains.
EOF
    for script in postinst postrm; do
        cat >"$tree/DEBIAN/$script" <<'EOF'
#!/bin/sh
set -e
if command -v update-grub >/dev/null 2>&1; then update-grub; fi
exit 0
EOF
        chmod 0755 "$tree/DEBIAN/$script"
    done
    find "$tree" -exec touch -h -d "@$source_epoch" {} +
    dpkg-deb --root-owner-group --build "$tree" "$output/narf-kernel_${version}_amd64.deb"
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
License: GPL-2.0-or-later
URL: https://github.com/hodgesds/narf
Source0: $payload.tar.gz
BuildArch: x86_64
Requires: grub2-tools

%description
NARF is an async-first framekernel with hardware-isolated domains.

%prep
%setup -q -c -T
tar -xzf %{SOURCE0}

%install
mkdir -p %{buildroot}
cp -a boot etc usr %{buildroot}/

%files
/boot/narf-frame-$version
/etc/grub.d/42_narf
/usr/share/doc/narf/

%post
if command -v grub2-mkconfig >/dev/null 2>&1; then
  grub2-mkconfig -o /boot/grub2/grub.cfg
fi

%postun
if command -v grub2-mkconfig >/dev/null 2>&1; then
  grub2-mkconfig -o /boot/grub2/grub.cfg
fi
EOF
    rpmbuild --define "_topdir $top" --define "_source_date_epoch $source_epoch" \
        -bb "$spec"
    find "$top/RPMS" -type f -name '*.rpm' -exec cp {} "$output/" \;
}

build_arch() {
    need makepkg arch || return
    local dir=$work/arch
    mkdir -p "$dir"
    cp "$output/$payload.tar.gz" "$dir/"
    local sum
    sum=$(sha256sum "$dir/$payload.tar.gz" | awk '{print $1}')
    cat >"$dir/PKGBUILD" <<EOF
pkgname=narf-kernel
pkgver=$version
pkgrel=1
pkgdesc='NARF framekernel boot image'
arch=('x86_64')
url='https://github.com/hodgesds/narf'
license=('GPL-2.0-or-later')
depends=('grub')
source=('$payload.tar.gz')
sha256sums=('$sum')
install=narf-kernel.install
package() {
  cp -a "\$srcdir/boot" "\$srcdir/etc" "\$srcdir/usr" "\$pkgdir/"
}
EOF
    cat >"$dir/narf-kernel.install" <<'EOF'
post_install() {
  command -v grub-mkconfig >/dev/null &&
    grub-mkconfig -o /boot/grub/grub.cfg
}
post_upgrade() { post_install; }
post_remove() { post_install; }
EOF
    (cd "$dir" && SOURCE_DATE_EPOCH=$source_epoch makepkg --noconfirm --nodeps)
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
SRC_URI="$payload.tar.gz"
LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="~amd64"
RDEPEND="sys-boot/grub:2"

src_unpack() {
    mkdir -p "\${S}" || die
    cd "\${S}" || die
    unpack "\${A}"
}
src_install() {
    cp -a boot etc usr "\${D}/" || die
}
pkg_postinst() {
    if command -v grub-mkconfig >/dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg || die
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
