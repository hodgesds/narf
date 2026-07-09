#!/bin/bash
set -e

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
OUT="$ROOT/target/narf-kde-vblk.img"
# Persistent workdir (survives across runs) so a failed pack / tweak doesn't
# force a 1.8 GiB re-download+re-install. Set KDE_REBUILD_ROOTFS=1 to force a
# clean apk install; otherwise a populated rootfs is reused.
WORK="$ROOT/target/kde-build-work"
mkdir -p "$WORK"

if [ "${KDE_REBUILD_ROOTFS:-0}" = 1 ] || [ ! -x "$WORK/root/usr/bin/startplasma-wayland" ]; then
  echo "Downloading Alpine minirootfs..."
  rm -rf "$WORK/root"
  wget -qO "$WORK/alpine-minirootfs.tar.gz" "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.2-x86_64.tar.gz"

  mkdir -p "$WORK/root"
  tar -xzf "$WORK/alpine-minirootfs.tar.gz" -C "$WORK/root"

  echo "Setting up DNS..."
  cp /etc/resolv.conf "$WORK/root/etc/resolv.conf"

  echo "Installing KDE Plasma and dependencies using proot..."
/tmp/proot -0 -R "$WORK/root" -b /dev -b /sys -b /proc /bin/sh -c '
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    apk update &&
    apk add --no-cache \
    plasma-desktop \
    plasma-workspace \
    plasma-wayland-protocols \
    kwin \
    dbus \
    dbus-x11 \
    eudev \
    wayland \
    mesa-dri-gallium \
    mesa-egl \
    mesa-gbm \
    qt6-qtwayland \
    qt5-qtwayland \
    bash \
    su-exec \
    strace \
    font-dejavu &&
    { adduser -D -u 1000 kdeuser || adduser -D kdeuser || true; }
'
fi

echo "Ensuring kdeuser exists (proot adduser is unreliable)..."
grep -q '^kdeuser:' "$WORK/root/etc/passwd" || \
  echo 'kdeuser:x:1000:1000:kdeuser:/home/kdeuser:/bin/bash' >> "$WORK/root/etc/passwd"
grep -q '^kdeuser:' "$WORK/root/etc/group" || \
  echo 'kdeuser:x:1000:' >> "$WORK/root/etc/group"
mkdir -p "$WORK/root/home/kdeuser"

echo "Creating startup script..."
cat << 'EOF' > "$WORK/root/bin/start_kde.sh"
#!/bin/bash
# Diagnostic Plasma launcher. First bring-up runs as ROOT so KWin's direct
# device backend can open /dev/dri + /dev/input without an elogind session
# (Alpine KWin links libelogind); all output goes to the console for capture.
set -x
# NARF's ext2 rootfs is read-mostly (KDE cache/config writes to it EINVAL and
# stall kbuildsycoca). Put HOME + all XDG dirs on the kernel's writable /tmp
# tmpfs so ksycoca, kconfig locks, and Qt caches actually write.
export HOME=/tmp/kde-home
export XDG_RUNTIME_DIR=/tmp/xdg-runtime
export XDG_CACHE_HOME=$HOME/.cache
export XDG_CONFIG_HOME=$HOME/.config
export XDG_DATA_HOME=$HOME/.local/share
export XDG_STATE_HOME=$HOME/.local/state
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"
chmod 0700 "$XDG_RUNTIME_DIR"
unset WAYLAND_DISPLAY              # KWin is the SERVER — it creates the socket.
export KWIN_DRM_NO_AMS=1           # NARF has no atomic KMS — force legacy modeset.
export QT_QPA_PLATFORM=wayland
export QT_LOGGING_RULES="kwin_*.debug=true"

echo "=== KDE-PROBE devices ==="
ls -l /dev/dri /dev/input 2>&1
echo "=== KDE-PROBE launching startplasma-wayland (root) ==="
dbus-run-session -- startplasma-wayland 2>&1
echo "=== KDE-PROBE startplasma exited rc=$? ==="
EOF
chmod +x "$WORK/root/bin/start_kde.sh"

mkdir -p "$ROOT/target"
rm -f "$OUT"

echo "Creating 2 GiB ext2 image at $OUT..."
mke2fs -q -F -t ext2 -b 1024 \
  -O ^has_journal,^extent,^64bit,^metadata_csum,^dir_index,^resize_inode,^huge_file,^flex_bg,^ext_attr \
  -d "$WORK/root" "$OUT" 2097152

echo "built $OUT ($(du -h "$OUT" | cut -f1)) — Alpine KDE rootfs"
echo "Next step: create distro_kde to mount and run it!"
