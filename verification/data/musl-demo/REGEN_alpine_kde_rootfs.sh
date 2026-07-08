#!/bin/sh
# Build an Alpine Linux rootfs disk image packed with KDE Plasma.
#
# NARF mounts this ext2 image (on the QEMU virtio-blk device) at /mnt; the
# /bin/distro_kde launcher then chroot()s into it and execs startplasma-wayland.
#
# Requires: docker, mke2fs (e2fsprogs >= 1.43 for `-d`), unprivileged.
set -e

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
OUT="$ROOT/target/narf-kde-vblk.img"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "Building KDE Alpine rootfs using Docker..."

cat << 'EOF' > "$WORK/Dockerfile"
FROM alpine:3.21

# Install KDE Plasma, Wayland, and rendering dependencies
RUN apk update && \
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
    font-dejavu

# KDE often refuses to run as root, so we create a standard user
RUN adduser -D -u 1000 kdeuser

# A simple wrapper to start KDE
RUN echo '#!/bin/bash' > /bin/start_kde.sh && \
    echo 'export XDG_RUNTIME_DIR=/tmp/runtime-kdeuser' >> /bin/start_kde.sh && \
    echo 'mkdir -p $XDG_RUNTIME_DIR' >> /bin/start_kde.sh && \
    echo 'chown kdeuser:kdeuser $XDG_RUNTIME_DIR' >> /bin/start_kde.sh && \
    echo 'chmod 0700 $XDG_RUNTIME_DIR' >> /bin/start_kde.sh && \
    echo 'su-exec kdeuser dbus-run-session startplasma-wayland' >> /bin/start_kde.sh && \
    chmod +x /bin/start_kde.sh

EOF

docker build -t narf-alpine-kde "$WORK"

echo "Exporting rootfs from Docker container..."
CONTAINER_ID=$(docker create narf-alpine-kde)
mkdir -p "$WORK/root"
docker export $CONTAINER_ID | tar -xC "$WORK/root"
docker rm $CONTAINER_ID

mkdir -p "$ROOT/target"
rm -f "$OUT"

# 2 GiB ext2 image (2097152 * 1KiB blocks) to hold all of KDE
echo "Creating 2 GiB ext2 image at $OUT..."
mke2fs -q -F -t ext2 -b 1024 \
  -O ^has_journal,^extent,^64bit,^metadata_csum,^dir_index,^resize_inode,^huge_file,^flex_bg,^ext_attr \
  -d "$WORK/root" "$OUT" 2097152

echo "built $OUT ($(du -h "$OUT" | cut -f1)) — Alpine KDE rootfs"
echo "Next step: create distro_kde to mount and run it!"
