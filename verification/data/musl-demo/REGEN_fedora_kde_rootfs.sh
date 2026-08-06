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

# Capture the narrow D-Bus gate between KWin startup and plasmashell startup.
# The monitor runs on the same fresh session bus as Plasma, so serial and
# reply_serial values can be correlated without syscall-level tracing.
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-plasma-session-monitor.sh" \
  "$WORK/root/usr/local/libexec/narf-plasma-session-monitor"
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-plasma-classic-supervisor.sh" \
  "$WORK/root/usr/local/libexec/narf-plasma-classic-supervisor"
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-drm-policy.sh" \
  "$WORK/root/usr/local/libexec/narf-drm-policy"

# The libdrm probe narf-drm-policy runs. Built here rather than shipped as a
# binary so it tracks the source; linked against the HOST's libdrm headers but
# resolved at run time against the GUEST's libdrm.so.2, which is the whole
# point — it reports what the guest's own libdrm concludes about NARF's DRM
# nodes instead of what we think it should conclude.
#
# Non-fatal on purpose: a host without libdrm headers should still be able to
# regenerate the image. But say so loudly, because narf-drm-policy prints
# "probe binary MISSING" rather than failing, and a silently absent probe
# looks exactly like a probe that found nothing.
if command -v gcc >/dev/null 2>&1 && [ -f /usr/include/xf86drm.h ]; then
  if gcc -O1 -o "$WORK/root/usr/local/libexec/narf-drm-probe" \
      "$ROOT/verification/data/musl-demo/drm_device_probe.c" \
      -I/usr/include/libdrm -ldrm 2>/dev/null; then
    chmod 0755 "$WORK/root/usr/local/libexec/narf-drm-probe"
    echo "Built narf-drm-probe (libdrm device probe)"
  else
    echo "WARNING: narf-drm-probe failed to build; DRM enumeration probe will be absent"
  fi
else
  echo "WARNING: no gcc or libdrm headers on host; skipping narf-drm-probe"
fi

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

# Preserve the exact generated keymap stream that Xwayland hands to xkbcomp.
# This is a diagnostic for the current Plasma gate: the image's static XKB
# corpus compiles correctly offline, while the live compiler reports malformed
# stdin.  Keep the package binary under a stable private name so incremental
# image regeneration remains idempotent.
if [ ! -x "$WORK/root/usr/bin/xkbcomp.narf-real" ]; then
  mv "$WORK/root/usr/bin/xkbcomp" "$WORK/root/usr/bin/xkbcomp.narf-real"
fi
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-xkbcomp-capture.sh" \
  "$WORK/root/usr/bin/xkbcomp"

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

# Record whether plasma_session's own ksmserver StartServiceJob ever execs a
# process. The real binary moves to a private directory but keeps its
# basename, so /proc/<pid>/comm stays `ksmserver` for the acceptance probe.
install -d "$WORK/root/usr/local/libexec/ksmserver-real"
if [ ! -x "$WORK/root/usr/local/libexec/ksmserver-real/ksmserver" ]; then
  mv "$WORK/root/usr/bin/ksmserver" \
    "$WORK/root/usr/local/libexec/ksmserver-real/ksmserver"
fi
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-ksmserver-trace.sh" \
  "$WORK/root/usr/bin/ksmserver"

# Restore the package binary if an older incremental work tree contains the
# rejected QDBUS_DEBUG wrapper. That diagnostic changed the process identity,
# emitted no Qt records, and perturbed the kcminit transition.
if [ -e "$WORK/root/usr/bin/plasma_session.narf-real" ]; then
  mv -f "$WORK/root/usr/bin/plasma_session.narf-real" \
    "$WORK/root/usr/bin/plasma_session"
fi

# The graphical session is a normal systemd service, deliberately not the
# legacy narf-start.sh diagnostic wrapper. PID 1 orders it after the system
# bus, gives it a private user-owned runtime directory, and starts Plasma
# through a fresh session bus. logind is intentionally not a requirement:
# Plasma can run without it, and a login-manager compatibility failure must
# not suppress the graphical compositor. Type=simple also avoids making the
# session's lifetime depend on systemd's exec-notification handshake while the
# Linux-compat process startup path is still slower than native Linux.
# Wants/After user@1000.service: the user manager must be started by PID 1,
# not by the session at runtime. narf-plasma.service runs as User=narf
# (uid 1000), and an unprivileged `systemctl start user@1000.service` is
# refused with "Access denied ... requires interactive authentication"
# because that path goes through polkit. As a unit dependency root starts
# it, with no polkit involved. user@.service in turn pulls in
# user-runtime-dir@1000.service, which creates /run/user/1000 — where the
# manager publishes the session bus the session then connects to.
#
# QV4_FORCE_INTERPRETER / QT_ENABLE_REGEXP_JIT below: NARF enforces W^X —
# nothing grants a W|X end state and the RW->RX flip needs CapKind::Jit
# (userspace mprotect_core). Qt's QML JIT allocator performs exactly that
# flip and gets EINVAL, which the journal shows as "mprotect failed in
# ExecutableAllocator::makeWritable: Invalid argument". Run QML interpreted
# rather than weaken a deliberate kernel security property for bring-up
# convenience; plasmashell is QML-heavy so this sits on its critical path.
#
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
  'Environment=XDG_RUNTIME_DIR=/run/narf-plasma' \
  'Environment=XDG_SESSION_TYPE=wayland' \
  'Environment=XDG_CURRENT_DESKTOP=KDE' \
  'Environment=XKB_DEFAULT_MODEL=pc105' \
  'Environment=XKB_DEFAULT_LAYOUT=us' \
  'Environment=QT_LOGGING_RULES=org.kde.kcminit.debug=true;kwin_core.debug=true;kwin_wayland_drm.debug=true;kwin_scene_opengl.debug=true;kwin_qpainter.debug=true' \
  'Environment=QT_QPA_PLATFORM=wayland' \
  'Environment=QV4_FORCE_INTERPRETER=1' \
  'Environment=QT_ENABLE_REGEXP_JIT=0' \
  'Environment=KWIN_DRM_NO_AMS=1' \
  'Environment=KWIN_COMPOSE=Q' \
  'Environment=KWIN_DRM_DEVICES=/dev/dri/card0' \
  'Environment=LIBGL_ALWAYS_SOFTWARE=1' \
  'Environment=GALLIUM_DRIVER=llvmpipe' \
  'Environment=MESA_LOADER_DRIVER_OVERRIDE=kms_swrast' \
  'Environment=MESA_DEBUG=1' \
  'Environment=EGL_LOG_LEVEL=debug' \
  'Environment=LIBGL_DEBUG=verbose' \
  'RuntimeDirectory=narf-plasma' \
  'RuntimeDirectoryMode=0700' \
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

# Do not confuse Type=simple's successful fork with a working desktop.
# KillMode=process: the probe leaves a background sampler running past
# PLASMA-READY — the only window into whether the shell is parked or merely
# slow — and the default control-group kill would reap it with the oneshot. This
# oneshot is ordered after the session service and keeps the graphical target
# pending until both the compositor and shell have remained alive long enough
# to be observed twice. Its console heartbeats also expose the last surviving
# process when startup stalls.
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-plasma-probe.sh" \
  "$WORK/root/usr/local/libexec/narf-plasma-probe"
printf '%s\n' \
  '[Unit]' \
  'Description=Verify NARF Plasma processes' \
  'Wants=narf-plasma.service' \
  'After=narf-plasma.service' \
  '' \
  '[Service]' \
  'Type=oneshot' \
  'User=narf' \
  'ExecStart=/usr/local/libexec/narf-plasma-probe' \
  'StandardOutput=journal+console' \
  'StandardError=journal+console' \
  'TimeoutStartSec=15min' \
  'KillMode=process' \
  '' \
  '[Install]' \
  'WantedBy=graphical.target' \
  > "$WORK/root/etc/systemd/system/narf-plasma-probe.service"
ln -sfn ../narf-plasma-probe.service \
  "$WORK/root/etc/systemd/system/graphical.target.wants/narf-plasma-probe.service"

# Root-side journal tap. narf-plasma-probe runs as User=narf and therefore
# CANNOT read /var/log/journal/<id>/user-1000.journal ("Operation not
# permitted"), which is where every Plasma user unit's output goes — kwin's
# exit reason included. This service has no User=, so it runs as root and can.
install -m 0755 \
  "$ROOT/verification/data/musl-demo/fedora-journal-tap.sh" \
  "$WORK/root/usr/local/libexec/narf-journal-tap"
printf '%s\n' \
  '[Unit]' \
  'Description=Mirror the uid-1000 journal to the console' \
  'Wants=systemd-journald.service' \
  'After=systemd-journald.service' \
  '' \
  '[Service]' \
  'Type=simple' \
  'ExecStart=/usr/local/libexec/narf-journal-tap' \
  'StandardOutput=journal+console' \
  'StandardError=journal+console' \
  'Restart=always' \
  'RestartSec=2' \
  '' \
  '[Install]' \
  'WantedBy=graphical.target' \
  > "$WORK/root/etc/systemd/system/narf-journal-tap.service"
ln -sfn ../narf-journal-tap.service \
  "$WORK/root/etc/systemd/system/graphical.target.wants/narf-journal-tap.service"
# A Wants= symlink lets graphical.target succeed after a failed oneshot.
# Make the probe a required, ordered start job so graphical.target is proof of
# PLASMA-READY rather than merely proof that the probe was attempted.
install -d "$WORK/root/etc/systemd/system/graphical.target.d"
printf '%s\n' \
  '[Unit]' \
  'Requires=narf-plasma-probe.service' \
  'After=narf-plasma-probe.service' \
  > "$WORK/root/etc/systemd/system/graphical.target.d/narf-plasma-gate.conf"

# Plasma's components run as systemd USER UNITS, so their stderr goes to the
# journal and NOTHING about a crash reaches the serial console — which is the
# only channel this bring-up can read. `journalctl --user` cannot help: it
# fails with "Operation not permitted" opening
# /var/log/journal/<id>/user-1000.journal, so the journal is unreadable from
# inside the guest too.
#
# Mirror these units' output to the console. This is what makes a compositor
# exit diagnosable at all: kwin dying is what tears the session down
# (plasma-workspace-wayland.target BindsTo plasma-kwin_wayland.service, and
# graphical-session.target takes every PartOf unit with it), and its reason
# was previously invisible.
for narf_unit in plasma-kwin_wayland.service plasma-plasmashell.service \
                 plasma-kded6.service plasma-ksmserver.service; do
  install -d "$WORK/root/usr/lib/systemd/user/${narf_unit}.d"
  printf '%s\n' \
    '[Service]' \
    'StandardOutput=journal+console' \
    'StandardError=journal+console' \
    > "$WORK/root/usr/lib/systemd/user/${narf_unit}.d/99-narf-console.conf"
done

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
