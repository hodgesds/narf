#!/bin/bash
# Build a Fedora 43 + KDE Plasma 6 rootfs and pack it into a NARF-mountable
# ext2 image at target/narf-fedora-vblk.img.
#
# Counterpart to REGEN_alpine_kde_rootfs.sh, but glibc instead of musl: every
# binary past the chroot is stock Fedora, linked against Fedora's own
# /lib64/ld-linux-x86-64.so.2.
#
# Fully unprivileged — the rootfs is populated by dnf5 running inside a user
# namespace with a full 65536-uid map (`unshare --map-auto`), so rpm's
# chown-to-non-root-uid calls succeed without ever being real root.
#
# The image is written to its OWN path (NOT target/narf-vblk.img) so it never
# displaces the Alpine rootfs every musl-demo / redis / oci case reads. Point
# a boot at it with NARF_VBLK_IMG=target/narf-fedora-vblk.img.
#
#   FEDORA_REBUILD_ROOTFS=1   force a clean re-download + re-install
#   FEDORA_IMG_MB=<n>         image size in MiB (default 4096)
set -e

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
OUT="$ROOT/target/narf-fedora-vblk.img"
WORK="$ROOT/target/fedora-build-work"
FEDORA_VER=43
BASE_URL="https://dl.fedoraproject.org/pub/fedora/linux/releases/$FEDORA_VER/Container/x86_64/images"
BASE_IMG="Fedora-Container-Base-Generic-$FEDORA_VER-1.6.x86_64.oci.tar.xz"
IMG_MB="${FEDORA_IMG_MB:-4096}"

mkdir -p "$WORK"

# ---------------------------------------------------------------- rootfs ---
if [ "${FEDORA_REBUILD_ROOTFS:-0}" = 1 ] || [ ! -x "$WORK/root/usr/bin/startplasma-wayland" ]; then
  echo "Downloading Fedora $FEDORA_VER container base..."
  rm -rf "$WORK/root" "$WORK/oci"
  [ -f "$WORK/fedora-base.oci.tar.xz" ] || \
    wget -qO "$WORK/fedora-base.oci.tar.xz" "$BASE_URL/$BASE_IMG"

  mkdir -p "$WORK/oci" "$WORK/root"
  tar -xJf "$WORK/fedora-base.oci.tar.xz" -C "$WORK/oci"
  # The OCI layout has one big layer blob — the rootfs tar. Pick the largest.
  LAYER=$(ls -S "$WORK/oci/blobs/sha256" | head -1)
  tar -xf "$WORK/oci/blobs/sha256/$LAYER" -C "$WORK/root"

  # Enter helper: fake-root userns + bind /dev,/sys,/proc + chroot.
  cat > "$WORK/enter.sh" <<'ENTEREOF'
#!/bin/bash
set -e
WORK="$(cd "$(dirname "$0")" && pwd)"
ROOT="$WORK/root"
cp -f /etc/resolv.conf "$ROOT/etc/resolv.conf" 2>/dev/null || true
if [ "$(id -u)" -eq 0 ]; then
  mount --rbind /dev  "$ROOT/dev" 2>/dev/null || true
  mount --rbind /sys  "$ROOT/sys" 2>/dev/null || true
  mount -t proc proc  "$ROOT/proc" 2>/dev/null || true
  mount -t tmpfs tmpfs "$ROOT/tmp" 2>/dev/null || true
  chroot "$ROOT" /usr/bin/env -i \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root TERM=dumb LANG=C.UTF-8 \
    /bin/bash -l -c "$*"
  RET=$?
  for m in $(mount | grep "$ROOT" | awk '{print $3}' | sort -r); do
    umount -l "$m" 2>/dev/null || true
  done
  exit $RET
else
  exec unshare --user --map-auto --map-root-user --mount --pid --fork --kill-child \
    /bin/bash -c '
      set -e
      ROOT="'"$ROOT"'"
      mount --rbind /dev  "$ROOT/dev"
      mount --rbind /sys  "$ROOT/sys"
      mount -t proc proc  "$ROOT/proc"
      mount -t tmpfs tmpfs "$ROOT/tmp"
      mount --make-rslave "$ROOT/dev" || true
      exec chroot "$ROOT" /usr/bin/env -i \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        HOME=/root TERM=dumb LANG=C.UTF-8 \
        /bin/bash -l -c "$*"
    ' -- "$@"
fi
ENTEREOF
  chmod +x "$WORK/enter.sh"

  echo "Installing KDE Plasma 6 with dnf5 (unprivileged userns)..."
  "$WORK/enter.sh" 'dnf -y --setopt=install_weak_deps=False install \
      plasma-workspace plasma-workspace-wayland plasma-desktop \
      kwin-wayland plasma-breeze qt6-qtwayland \
      mesa-dri-drivers mesa-libgbm mesa-libEGL \
      dbus-daemon dbus-tools \
      xrdb \
      bash coreutils util-linux procps-ng strace file less findutils \
      dejavu-sans-fonts kde-cli-tools konsole foot'
  "$WORK/enter.sh" 'dnf clean all'
fi

# --------------------------------------------------------------- staging ---
echo "Staging NARF-specific bits..."
# dbus + Plasma both refuse to start without a machine-id.
[ -s "$WORK/root/etc/machine-id" ] || \
  head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/root/etc/machine-id"

# The systemd package ships a D-Bus activation stub for org.freedesktop.systemd1
# whose Exec is /bin/false. There is no systemd here, and startplasma calls
# org.freedesktop.systemd1.Manager.SetEnvironment UNCONDITIONALLY (it is not
# gated on the systemdBoot setting below), so leaving the stub in place makes
# every such call burn dbus's full 120s service_start_timeout before failing.
# Drop it and dbus answers "not provided by any .service files" immediately.
rm -f "$WORK/root/usr/share/dbus-1/services/org.freedesktop.systemd1.service"
# ld.so.cache: the image is built offline, so make sure it matches the tree.
"$WORK/enter.sh" 'ldconfig' || true

# Plasma must run as an ordinary desktop user. The image is a container base
# and therefore has no login user by default; create the deterministic test
# account only when it is absent so incremental image rebuilds stay stable.
if ! grep -q '^narf:' "$WORK/root/etc/passwd"; then
  "$WORK/enter.sh" 'useradd --create-home --uid 1000 --shell /bin/bash narf'
fi
install -d -m 0755 "$WORK/root/home/narf/.config" "$WORK/root/etc/systemd/system/graphical.target.wants"
printf '[General]\nsystemdBoot=false\n' > "$WORK/root/home/narf/.config/startkderc"
chown -R 1000:1000 "$WORK/root/home/narf"

# The graphical session is a normal systemd service, deliberately not the
# legacy narf-start.sh diagnostic wrapper. PID 1 orders it after the system
# bus, gives it a private user-owned runtime directory, and starts Plasma
# through a fresh session bus. logind is intentionally not a requirement:
# Plasma can run without it, and a login-manager compatibility failure must
# not suppress the graphical compositor.
printf '%s\n' \
  '[Unit]' \
  'Description=NARF Plasma Wayland Session' \
  'Wants=dbus-broker.service' \
  'After=dbus-broker.service' \
  '' \
  '[Service]' \
  'Type=exec' \
  'User=narf' \
  'Environment=HOME=/home/narf' \
  'Environment=XDG_RUNTIME_DIR=/run/narf-plasma' \
  'Environment=XDG_SESSION_TYPE=wayland' \
  'Environment=XDG_CURRENT_DESKTOP=KDE' \
  'Environment=QT_QPA_PLATFORM=wayland' \
  'Environment=KWIN_DRM_NO_AMS=1' \
  'Environment=KWIN_DRM_DEVICES=/dev/dri/card0' \
  'Environment=LIBGL_ALWAYS_SOFTWARE=1' \
  'Environment=GALLIUM_DRIVER=llvmpipe' \
  'RuntimeDirectory=narf-plasma' \
  'RuntimeDirectoryMode=0700' \
  'ExecStart=/usr/bin/dbus-run-session -- /usr/bin/startplasma-wayland' \
  'Restart=on-failure' \
  'RestartSec=3s' \
  'TimeoutStartSec=180s' \
  '' \
  '[Install]' \
  'WantedBy=graphical.target' \
  > "$WORK/root/etc/systemd/system/narf-plasma.service"
ln -sfn ../narf-plasma.service \
  "$WORK/root/etc/systemd/system/graphical.target.wants/narf-plasma.service"

install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-systemd-start.sh" \
  "$WORK/root/narf-start.sh"

# ------------------------------------------------------------------ pack ---
for m in $(mount | grep "$WORK/root" | awk '{print $3}' | sort -r); do
  umount -l "$m" 2>/dev/null || true
done

if [ "$(id -u)" -eq 0 ]; then
  UNSHARE_CMD=""
else
  UNSHARE_CMD="unshare --user --map-auto --map-root-user"
fi
$UNSHARE_CMD mke2fs -q -F -t ext2 -b 1024 -I 128 \
  -O ^has_journal,^extent,^64bit,^metadata_csum,^dir_index,^resize_inode,^huge_file,^flex_bg,^ext_attr \
  -d "$WORK/root" "$OUT" "$((IMG_MB * 1024))"

echo "built $OUT ($(du -h "$OUT" | cut -f1)) — Fedora $FEDORA_VER KDE rootfs"
echo "boot it with: NARF_VBLK_IMG=$OUT cargo xtask run-interactive ..."
