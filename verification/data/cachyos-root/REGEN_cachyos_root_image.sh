#!/bin/bash
# Build a CachyOS-like GPT disk image for `cargo xtask cachyos-root-smoke`.
#
# The image mirrors the installed CachyOS layout NARF has to boot on bare
# metal: a GPT disk with a FAT32 ESP and a btrfs root carrying the CachyOS
# subvolumes (@, @home, @root, @srv, @cache, @tmp, @log), the same mkfs
# features as the host root (nodesize 16 KiB, block-group-tree,
# free-space-tree, no-holes, zstd) and the host's fstab with only the UUIDs
# changed. The userspace is the real CachyOS one: pacman installs `base` plus
# the CachyOS settings packages into a private root, from the host's own
# repositories and package cache.
#
# Fully unprivileged and host-safe:
# - Everything runs inside a user namespace (`unshare --map-auto`), so
#   pacman's chown calls and the image's uid-0 ownership work without root.
# - pacman runs with its own --root, --dbpath and gpg dir. The host's sync
#   databases, mirror lists and *public* keyring are COPIED into the work
#   tree; nothing under /etc, /var/lib/pacman or /var/cache/pacman is
#   written. The host package cache is only a read-only second CacheDir;
#   anything not cached there is downloaded into the work tree and
#   signature-checked against the copied keyring.
# - No block device is opened. The output is a regular file.
#
# The filesystem UUIDs are deliberately NOT the host's: a btrfs image that
# shares the live root's fsid must never be attachable on the host.
#
#   CACHYOS_ROOT_IMG=<path>      output image (default target/narf-cachyos-root.img)
#   CACHYOS_ROOT_REBUILD=1       reinstall the rootfs from scratch
#   CACHYOS_ROOT_BGT=0           build btrfs without block-group-tree
#   CACHYOS_ROOT_PACKAGES="..."  extra packages to install
set -euo pipefail

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
OUT="${CACHYOS_ROOT_IMG:-$ROOT/target/narf-cachyos-root.img}"
WORK="$ROOT/target/cachyos-root-work"
STAGE="$WORK/stage"
R="$STAGE/@"

# Fixed identities, so the smoke's cmdline is static. Keep in sync with
# build/xtask/src/cachyos_root.rs.
BTRFS_UUID=c4c405ee-0000-4a11-9e57-00000000c0de
ESP_VOLID=CA50EF15
ESP_UUID=CA50-EF15
DISK_GUID=c4c405ee-0000-4d15-8000-000000000001
ESP_PARTUUID=c4c405ee-0000-4d15-8000-0000000000e5
ROOT_PARTUUID=c4c405ee-0000-4d15-8000-0000000000b7

ESP_MIB=128
BTRFS_MIB="${CACHYOS_ROOT_BTRFS_MIB:-4096}"
BGT="${CACHYOS_ROOT_BGT:-1}"

PACKAGES="base btrfs-progs dosfstools sudo cachyos-settings cachyos-keyring \
cachyos-mirrorlist cachyos-v4-mirrorlist ${CACHYOS_ROOT_PACKAGES:-}"

mkdir -p "$WORK"

# ------------------------------------------------------- pacman config ---
make_pacman_conf() {
  mkdir -p "$WORK/gnupg" "$WORK/pkgcache" "$WORK/mirrors"
  # Public keyring only (the private-keys dir is root-only and not needed
  # to verify signatures).
  cp -f /etc/pacman.d/gnupg/pubring.kbx /etc/pacman.d/gnupg/trustdb.gpg \
    /etc/pacman.d/gnupg/gpg.conf "$WORK/gnupg/"
  chmod 700 "$WORK/gnupg"
  cp -f /etc/pacman.d/*mirrorlist "$WORK/mirrors/"
  {
    echo "[options]"
    echo "Architecture = auto"
    echo "SigLevel = Required DatabaseOptional"
    echo "LocalFileSigLevel = Optional"
    echo "GPGDir = $WORK/gnupg"
    echo "CacheDir = $WORK/pkgcache"
    echo "CacheDir = /var/cache/pacman/pkg"
    echo "HookDir = $R/etc/pacman.d/hooks"
    echo "DisableSandbox"
    echo "ParallelDownloads = 8"
    # Same repositories, in the same order, as the host.
    awk '/^\[/ && $0 != "[options]" { print; inrepo=1; next }
         /^\[options\]/ { inrepo=0; next }
         inrepo && /^Include/ { sub(/\/etc\/pacman.d\//, "'"$WORK"'/mirrors/"); print }
         inrepo && /^(Server|SigLevel)/ { print }' /etc/pacman.conf
  } > "$WORK/pacman.conf"
}

# Run "$@" as uid 0 of a private user+mount+pid namespace.
in_ns() {
  unshare --user --map-auto --map-root-user --mount --pid --fork --kill-child -- "$@"
}

# ------------------------------------------------------------- rootfs ---
if [ "${CACHYOS_ROOT_REBUILD:-0}" = 1 ] || [ ! -x "$R/usr/lib/systemd/systemd" ]; then
  echo "cachyos-root: installing CachyOS userspace into $R"
  if [ -d "$STAGE" ]; then
    # Files owned by mapped uids can only be removed from inside the ns.
    in_ns rm -rf "$STAGE"
  fi
  mkdir -p "$R/var/lib/pacman/sync" "$R/etc/pacman.d/hooks"
  make_pacman_conf
  cp -f /var/lib/pacman/sync/*.db "$R/var/lib/pacman/sync/"
  cp -f /var/lib/pacman/sync/*.db.sig "$R/var/lib/pacman/sync/" 2>/dev/null || true
  # shellcheck disable=SC2086
  in_ns /bin/bash -c '
    set -euo pipefail
    R="$1"; CONF="$2"; shift 2
    mkdir -p "$R/dev" "$R/proc" "$R/sys" "$R/tmp" "$R/run"
    mount --rbind /dev "$R/dev"
    mount --make-rslave "$R/dev"
    mount -t proc proc "$R/proc"
    mount --rbind /sys "$R/sys"
    mount --make-rslave "$R/sys"
    mount -t tmpfs tmpfs "$R/tmp"
    mount -t tmpfs tmpfs "$R/run"
    pacman --config "$CONF" --root "$R" --dbpath "$R/var/lib/pacman" \
      --noconfirm --needed --noprogressbar -S "$@"
  ' -- "$R" "$WORK/pacman.conf" $PACKAGES
fi

# -------------------------------------------------------- configuration ---
echo "cachyos-root: configuring the image"
in_ns /bin/bash -c '
  set -euo pipefail
  R="$1"; STAGE="$2"; BTRFS_UUID="$3"; ESP_UUID="$4"
  # The host fstab, with this image'"'"'s UUIDs.
  cat > "$R/etc/fstab" <<EOF
# /etc/fstab: static file system information.
# CachyOS default btrfs layout (NARF cachyos-root-smoke image).
#
# <file system>             <mount point>  <type>  <options>  <dump>  <pass>
UUID=$ESP_UUID                            /boot/efi      vfat    defaults,umask=0077 0 2
UUID=$BTRFS_UUID /              btrfs   subvol=/@,defaults,noatime,compress=zstd:1 0 0
UUID=$BTRFS_UUID /home          btrfs   subvol=/@home,defaults,noatime,compress=zstd:1 0 0
UUID=$BTRFS_UUID /root          btrfs   subvol=/@root,defaults,noatime,compress=zstd:1 0 0
UUID=$BTRFS_UUID /srv           btrfs   subvol=/@srv,defaults,noatime,compress=zstd:1 0 0
UUID=$BTRFS_UUID /var/cache     btrfs   subvol=/@cache,defaults,noatime,compress=zstd:1 0 0
UUID=$BTRFS_UUID /var/tmp       btrfs   subvol=/@tmp,defaults,noatime,compress=zstd:1 0 0
UUID=$BTRFS_UUID /var/log       btrfs   subvol=/@log,defaults,noatime,compress=zstd:1 0 0
tmpfs                                     /tmp           tmpfs   defaults,noatime,mode=1777 0 0
EOF
  echo cachyos-narf > "$R/etc/hostname"
  # A fixed machine-id: an empty one makes systemd treat the boot as a
  # first boot and systemd-firstboot would prompt on the console.
  echo 4e415246c4c405ee0000000000000001 > "$R/etc/machine-id"
  echo "LANG=C.UTF-8" > "$R/etc/locale.conf"
  echo "KEYMAP=us" > "$R/etc/vconsole.conf"
  ln -sfn /usr/share/zoneinfo/UTC "$R/etc/localtime"
  # root / narf, the same test credentials as NARF'"'"'s own userspace.
  hash=$(openssl passwd -6 -salt narfcachyos narf)
  sed -i "s|^root:[^:]*:|root:${hash}:|" "$R/etc/shadow"
  ln -sfn /usr/lib/systemd/system/multi-user.target \
    "$R/etc/systemd/system/default.target"
  mkdir -p "$R/etc/systemd/system/getty.target.wants"
  ln -sfn /usr/lib/systemd/system/getty@.service \
    "$R/etc/systemd/system/getty.target.wants/getty@tty1.service"
  # CachyOS subvolumes: the mount points stay as empty directories in @,
  # their contents move into the matching subvolume.
  for pair in home:@home root:@root srv:@srv var/cache:@cache var/tmp:@tmp var/log:@log; do
    dir=${pair%%:*}; sub=${pair##*:}
    mkdir -p "$R/$dir"
    rm -rf "$STAGE/$sub"
    mkdir -p "$STAGE/$sub"
    chmod --reference="$R/$dir" "$STAGE/$sub"
    chown --reference="$R/$dir" "$STAGE/$sub"
    if [ -n "$(ls -A "$R/$dir")" ]; then
      cp -a "$R/$dir/." "$STAGE/$sub/"
      find "$R/$dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    fi
  done
  mkdir -p "$R/boot/efi"
  # The pacman package cache is a separate directory, never inside @cache.
  rm -rf "$STAGE/@cache/pacman/pkg"/* 2>/dev/null || true
' -- "$R" "$STAGE" "$BTRFS_UUID" "$ESP_UUID"

# --------------------------------------------------------------- disks ---
echo "cachyos-root: building filesystems"
FEATURES="free-space-tree,no-holes"
if [ "$BGT" = 1 ]; then
  FEATURES="block-group-tree,$FEATURES"
fi
rm -f "$WORK/root.btrfs" "$WORK/esp.fat"
truncate -s "${BTRFS_MIB}M" "$WORK/root.btrfs"
in_ns mkfs.btrfs -q -f -U "$BTRFS_UUID" -L cachyos -n 16384 -s 4096 \
  -O "$FEATURES" --compress zstd:1 --rootdir "$STAGE" \
  --subvol rw:@ --subvol rw:@home --subvol rw:@root --subvol rw:@srv \
  --subvol rw:@cache --subvol rw:@tmp --subvol rw:@log \
  "$WORK/root.btrfs"

truncate -s "${ESP_MIB}M" "$WORK/esp.fat"
mkfs.fat -F 32 -i "$ESP_VOLID" -n EFI "$WORK/esp.fat" >/dev/null
mmd -i "$WORK/esp.fat" ::/EFI ::/EFI/BOOT
printf 'NARF cachyos-root-smoke ESP\n' > "$WORK/esp-readme.txt"
mcopy -i "$WORK/esp.fat" "$WORK/esp-readme.txt" ::/EFI/BOOT/README.TXT

ESP_START=2048
ESP_SECTORS=$((ESP_MIB * 2048))
ROOT_START=$((ESP_START + ESP_SECTORS))
ROOT_SECTORS=$((BTRFS_MIB * 2048))
TOTAL_SECTORS=$((ROOT_START + ROOT_SECTORS + 2048))

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT.tmp"
truncate -s $((TOTAL_SECTORS * 512)) "$OUT.tmp"
sfdisk -q "$OUT.tmp" <<EOF
label: gpt
label-id: $DISK_GUID
start=$ESP_START, size=$ESP_SECTORS, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=$ESP_PARTUUID, name="EFI system partition"
start=$ROOT_START, size=$ROOT_SECTORS, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=$ROOT_PARTUUID, name="root"
EOF
dd if="$WORK/esp.fat" of="$OUT.tmp" bs=1M seek=$((ESP_START / 2048)) conv=notrunc,sparse status=none
dd if="$WORK/root.btrfs" of="$OUT.tmp" bs=1M seek=$((ROOT_START / 2048)) conv=notrunc,sparse status=none
mv -f "$OUT.tmp" "$OUT"
echo "cachyos-root: wrote $OUT (btrfs UUID=$BTRFS_UUID, features $FEATURES)"
