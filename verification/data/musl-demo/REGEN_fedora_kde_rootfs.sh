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
      xrdb cpp xkeyboard-config \
      bash coreutils util-linux procps-ng strace file less findutils \
      dejavu-sans-fonts kde-cli-tools konsole foot \
      kactivitymanagerd kglobalacceld kscreen \
      xdg-desktop-portal xdg-desktop-portal-kde plasma-polkit-agent'
  "$WORK/enter.sh" 'dnf clean all'
fi

# Older incremental work trees may predate xrdb's external preprocessor
# dependency even though xrdb itself is installed.
if [ ! -x "$WORK/root/usr/bin/cpp" ]; then
  "$WORK/enter.sh" 'dnf -y --setopt=install_weak_deps=False install cpp'
  "$WORK/enter.sh" 'dnf clean all'
fi
# KWin's Xwayland and the kcminit keyboard module require the compiled XKB
# rules tree.  With weak dependencies disabled it is not guaranteed to arrive
# with Plasma; without it kcminit never reaches its ready-pipe handoff.
if [ ! -d "$WORK/root/usr/share/X11/xkb/rules" ]; then
  "$WORK/enter.sh" 'dnf -y --setopt=install_weak_deps=False install xkeyboard-config'
  "$WORK/enter.sh" 'dnf clean all'
fi
# Plasma session daemons that arrive as WEAK dependencies of plasma-workspace
# and are therefore dropped by install_weak_deps=False. They are not optional
# for a session that reaches a drawn desktop:
#   kactivitymanagerd  — owns org.kde.ActivityManager; plasmashell blocks on
#                        that name at startup and otherwise eats a 120 s D-Bus
#                        activation timeout waiting for a name nobody provides.
#   kglobalacceld      — owns org.kde.KGlobalAccel, started by plasma_session.
#   kscreen            — kscreen_backend_launcher, output/geometry config.
# Guarded per-binary so older incremental work trees top up without a full
# rootfs rebuild (same idiom as cpp / xkeyboard-config above).
if [ ! -x "$WORK/root/usr/bin/kactivitymanagerd" ] ||
   [ ! -x "$WORK/root/usr/bin/kglobalacceld" ] ||
   [ ! -x "$WORK/root/usr/bin/kscreen_backend_launcher" ]; then
  "$WORK/enter.sh" 'dnf -y --setopt=install_weak_deps=False install \
      kactivitymanagerd kglobalacceld kscreen'
  "$WORK/enter.sh" 'dnf clean all'
fi

# --------------------------------------------------------------- staging ---
echo "Staging NARF-specific bits..."

# An incremental work tree may contain the previous diagnostic desktop image.
# Remove its units, gates, probes, and console overrides before packing so a
# regenerated image contains only the production startup path.
rm -f \
  "$WORK/root/etc/systemd/system/narf-plasma-probe.service" \
  "$WORK/root/etc/systemd/system/narf-journal-tap.service" \
  "$WORK/root/etc/systemd/system/graphical.target.wants/narf-plasma-probe.service" \
  "$WORK/root/etc/systemd/system/graphical.target.wants/narf-journal-tap.service" \
  "$WORK/root/etc/systemd/system/graphical.target.d/narf-plasma-gate.conf" \
  "$WORK/root/etc/systemd/user.conf" \
  "$WORK/root/usr/local/libexec/narf-plasma-probe" \
  "$WORK/root/usr/local/libexec/narf-journal-tap" \
  "$WORK/root/usr/local/libexec/narf-drm-probe" \
  "$WORK/root/usr/local/libexec/narf-pty-probe"
for narf_unit in plasma-kwin_wayland.service plasma-plasmashell.service \
                 plasma-kded6.service plasma-ksmserver.service; do
  rm -f "$WORK/root/usr/lib/systemd/user/${narf_unit}.d/99-narf-console.conf"
done

# Fedora ships /usr/bin mode 0555. Several diagnostics below swap package
# binaries for wrappers there, and the unprivileged build user owns the
# directory but has no write bit. Open it for staging and restore the
# packaged mode before mke2fs reads the tree.
chmod u+w "$WORK/root/usr/bin"
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
# Plasma synchronously queries org.freedesktop.locale1 before it can launch
# plasma_session.  This verification image does not need the locale daemon's
# keyboard-policy service, while activating its fully sandboxed systemd unit
# exercises a still-incomplete broker/PID1 compatibility path and can wait
# indefinitely.  With no activator, dbus-broker returns ServiceUnknown and
# startplasma follows its documented warning/fallback path immediately.
# Keep this scoped to the acceptance image; it is not a kernel wake fix.
rm -f "$WORK/root/usr/share/dbus-1/system-services/org.freedesktop.locale1.service"
# ld.so.cache: the image is built offline, so make sure it matches the tree.
"$WORK/enter.sh" 'ldconfig' || true

# Plasma must run as an ordinary desktop user. The image is a container base
# and therefore has no login user by default; create the deterministic test
# account only when it is absent so incremental image rebuilds stay stable.
if ! grep -q '^narf:' "$WORK/root/etc/passwd"; then
  "$WORK/enter.sh" 'useradd --create-home --uid 1000 --shell /bin/bash narf'
fi
# Fedora assigns primary DRM nodes to `video` (normally 0660) and render nodes
# to `render` at 0666. Keep both memberships for incremental work trees too;
# this image has no logind seat manager to install per-user device ACLs.
"$WORK/enter.sh" 'usermod --append --groups video,render narf'
install -d -m 0755 "$WORK/root/etc/systemd/system/graphical.target.wants"
# Serial is already the acceptance console. Fedora's tty getty units cannot
# own these synthetic terminals correctly yet and crash/restart throughout a
# boot, consuming a vCPU and adding unrelated PID1/SIGCHLD/timer churn.
ln -sfn /dev/null "$WORK/root/etc/systemd/system/console-getty.service"
ln -sfn /dev/null "$WORK/root/etc/systemd/system/getty@tty1.service"
# AccountsService is only useful for login/account administration.  This image
# has one fixed desktop user, while the daemon's SQLite state cache currently
# cannot persist on NARF's ext2 path and emits a distracting disk-I/O error at
# every graphical boot.  Prevent both its graphical-target pull-in and D-Bus
# activation; ordinary passwd/NSS account lookup remains available.
ln -sfn /dev/null "$WORK/root/etc/systemd/system/accounts-daemon.service"
rm -f "$WORK/root/usr/share/dbus-1/system-services/org.freedesktop.Accounts.service"
# Everything under /home/narf belongs to uid 1000, which `--map-auto` places
# on a subuid the invoking user cannot write to from outside the namespace.
# Stage the per-user config through the same fake-root helper that created
# the account, or an incremental rebuild fails with EACCES here.
"$WORK/enter.sh" '
  install -d -m 0755 -o narf -g narf /home/narf/.config
  printf "[General]\nsystemdBoot=false\n" > /home/narf/.config/startkderc
  printf "[KSplash]\nEngine=none\nTheme=None\n" > /home/narf/.config/ksplashrc
  chown -R narf:narf /home/narf'
# Fedora's global startkderc is selected before the per-user override during
# this bootstrap path. This image has no per-user systemd manager, so force
# classic startup globally as well; otherwise plasma_waitforname burns D-Bus's
# full 120-second activation timeout waiting for user units that cannot start.
printf '[General]\nsystemdBoot=false\n' > "$WORK/root/etc/xdg/startkderc"
# The splash is cosmetic and not part of the compositor/shell acceptance
# gate. Disable it while its independent userspace #GP is tracked separately.
printf '[KSplash]\nEngine=none\nTheme=None\n' > "$WORK/root/etc/xdg/ksplashrc"
# startplasma still probes the well-known splash name even with Theme=None.
# Without a per-user systemd manager Fedora's activator runs
# plasma_waitforname until D-Bus's 120-second timeout, so make the optional
# name fail immediately instead of installing a guaranteed timeout path.
rm -f "$WORK/root/usr/share/dbus-1/services/org.kde.KSplash.service"

install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-plasma-session-monitor.sh" \
  "$WORK/root/usr/local/libexec/narf-plasma-session-monitor"
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-plasma-classic-supervisor.sh" \
  "$WORK/root/usr/local/libexec/narf-plasma-classic-supervisor"
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-drm-policy.sh" \
  "$WORK/root/usr/local/libexec/narf-drm-policy"
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-udev-seat-gate.sh" \
  "$WORK/root/usr/local/libexec/narf-udev-seat-gate"

# Keep the real distro-device pipeline as an independently assertable gate.
# A compositor black screen is too late and too ambiguous a signal: this unit
# names the exact udev database + logind property contract Plasma Login uses.
printf '%s\n' \
  '[Unit]' \
  'Description=Verify udev DRM seat integration on NARF' \
  'Wants=systemd-udevd.service systemd-logind.service' \
  'After=systemd-udevd.service systemd-logind.service' \
  'Before=narf-plasma.service' \
  '' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/local/libexec/narf-udev-seat-gate' \
  'StandardOutput=journal+console' \
  'StandardError=journal+console' \
  '' \
  '[Install]' \
  'WantedBy=graphical.target' \
  > "$WORK/root/etc/systemd/system/narf-udev-seat-gate.service"
ln -sfn ../narf-udev-seat-gate.service \
  "$WORK/root/etc/systemd/system/graphical.target.wants/narf-udev-seat-gate.service"

# Keep DRM policy setup in its own root service. The `+` executable prefix on
# an ExecStartPre of a User= service exercises systemd's privileged-command
# credential path, which the current Linux-compat layer does not yet complete.
printf '%s\n' \
  '[Unit]' \
  'Description=Apply NARF DRM device policy' \
  '' \
  '[Service]' \
  'Type=oneshot' \
  'User=root' \
  'Group=root' \
  'ExecStart=/usr/local/libexec/narf-drm-policy' \
  'StandardOutput=journal+console' \
  'StandardError=journal+console' \
  > "$WORK/root/etc/systemd/system/narf-drm-policy.service"

# Restore the stock XKB compiler if a previous diagnostic image wrapped it.
if [ -x "$WORK/root/usr/bin/xkbcomp.narf-real" ]; then
  mv -f "$WORK/root/usr/bin/xkbcomp.narf-real" "$WORK/root/usr/bin/xkbcomp"
fi

# kcminit runs xrdb synchronously during its phase-zero fonts/style setup. If
# Xwayland has already failed, a permanent X11 round trip must not prevent the
# Wayland-only shell from starting. Preserve the package binary and bound only
# this optional compatibility step.
if [ ! -x "$WORK/root/usr/bin/xrdb.narf-real" ]; then
  mv "$WORK/root/usr/bin/xrdb" "$WORK/root/usr/bin/xrdb.narf-real"
fi
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-xrdb-guard.sh" \
  "$WORK/root/usr/bin/xrdb"

# Xwayland currently fails while compiling its generated XKB keymap but can
# leave its display socket accepting connections.  The phase-zero style KCM
# performs a synchronous XCB connect after xrdb returns, so clear DISPLAY only
# for kcminit.  Native Wayland session processes keep the compositor's normal
# environment, while this optional X11 compatibility initialization fails
# quickly instead of gating sendReady().
if [ ! -e "$WORK/root/usr/bin/kcminit_startup.narf-real" ]; then
  mv "$WORK/root/usr/bin/kcminit_startup" \
    "$WORK/root/usr/bin/kcminit_startup.narf-real"
fi
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-kcminit-wayland-guard.sh" \
  "$WORK/root/usr/bin/kcminit_startup"

# Restore the stock session manager if a previous diagnostic image wrapped it.
if [ -x "$WORK/root/usr/local/libexec/ksmserver-real/ksmserver" ]; then
  mv -f "$WORK/root/usr/local/libexec/ksmserver-real/ksmserver" \
    "$WORK/root/usr/bin/ksmserver"
fi

# Restore the package binary if an older incremental work tree contains the
# rejected QDBUS_DEBUG wrapper. That diagnostic changed the process identity,
# emitted no Qt records, and perturbed the kcminit transition.
if [ -e "$WORK/root/usr/bin/plasma_session.narf-real" ]; then
  mv -f "$WORK/root/usr/bin/plasma_session.narf-real" \
    "$WORK/root/usr/bin/plasma_session"
fi

# The session service starts after its two real prerequisites: the user
# manager/session bus and DRM ownership policy.  They have no ordering edge
# between them, so PID 1 starts both jobs in parallel.
#
# Qt's QML JIT is DISABLED. 7b6ab22b turned it on, reasoning that mprotect's
# W^X arm returns NeedsCapJit and jit_cap_default_policy() grants a JitCap by
# default, so the RW->RX flip no longer EINVALs. That reasoning was never
# validated and it is wrong about which transition Qt asks for: JavaScriptCore's
# ExecutableAllocator wants a W|X END STATE, and mprotect_core refuses that
# outright for ANY task -- the cap gates the flip, and "nothing grants a W|X end
# state". Measured consequence:
#   kwin_wayland_wrapper: mprotect failed in ExecutableAllocator::makeWritable:
#                         Invalid argument
#   fatal-fault: comm=plasma-keyboard sig=11 #PF faultva=10 rax=0
# i.e. the allocator returns NULL and the input method segfaults dereferencing
# it. Do not re-enable without first running an A/B that shows plasma-keyboard
# surviving; NARF's W^X refusal is a deliberate design position, not an
# oversight to route around.
# Those were set when the RW->RX flip returned EINVAL, but the kernel now
# implements it: mprotect's W^X arm returns WxTransition::NeedsCapJit, and
# `jit_cap_default_policy` GRANTS a JitCap by default (memory/src/wx.rs) —
# denial is opt-in per task, not the default — after which `jit_mprotect`
# performs the flip. W^X is still enforced; nothing grants a W|X end state.
# plasmashell is QML-heavy and this sits on its critical path, so running
# interpreted was costing real startup time for no security benefit.
#
# KMS presentation of a VirGL resource is not wired yet, so the compositor's
# final scanout remains on the proven dumb-buffer/QPainter path for this image.
# The in-tree Bochs DRM device deliberately exposes only the dumb-buffer
# scanout ABI. Keep application GL on Mesa's CPU renderer until its
# virtio-gpu render-node replacement presents real KMS scanout.
# NOTE: keep comments OUT of the printf argument list below. A `#` inside a
# line-continued arg list silently swallows every remaining argument, and
# `bash -n` still passes — so the unit file loses its ExecStart with no error.
printf '%s\n' \
  '[Unit]' \
  'Description=NARF Plasma Wayland Session' \
  'Wants=dbus-broker.service' \
  'Wants=user@1000.service' \
  'After=user@1000.service' \
  'Requires=narf-drm-policy.service' \
  'After=dbus-broker.service narf-drm-policy.service' \
  '' \
  '[Service]' \
  'Type=simple' \
  'User=narf' \
  'Group=video' \
  'Environment=HOME=/home/narf' \
  'Environment=XDG_RUNTIME_DIR=/run/user/1000' \
  'Environment=XDG_SESSION_TYPE=wayland' \
  'Environment=XDG_CURRENT_DESKTOP=KDE' \
  'Environment=XKB_DEFAULT_MODEL=pc105' \
  'Environment=XKB_DEFAULT_LAYOUT=us' \
  'Environment=QT_QPA_PLATFORM=wayland' \
  'Environment=KWIN_DRM_NO_AMS=1' \
  'Environment=KWIN_DRM_DEVICES=/dev/dri/card0' \
  'Environment=QV4_FORCE_INTERPRETER=1' \
  'Environment=QT_ENABLE_REGEXP_JIT=0' \
  'ExecStart=/usr/local/libexec/narf-plasma-session-monitor' \
  'StandardOutput=journal+console' \
  'StandardError=journal+console' \
  'Restart=on-failure' \
  'RestartSec=3s' \
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
chmod u-w "$WORK/root/usr/bin"
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
