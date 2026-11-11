#!/bin/bash
# Image hook for the QEMU soak (`run-soak.sh`): what the CachyOS smoke image
# needs on top of `base` to carry a desktop-like load.
#
# Run by REGEN_cachyos_root_image.sh (CACHYOS_ROOT_HOOK) as the image's root,
# inside its user namespace, with the rootfs path as $1 and before the
# subvolume split. Inputs come from the environment:
#   SOAK_PUBKEY  ssh public key file accepted for root and narf
#   SOAK_TREE    a source tree copied to /home/narf/src (optional)
#   SOAK_NATIVE  the built soak-native binary (optional; the ESP copy wins)
set -euo pipefail
R="$1"
HERE=$(cd "$(dirname "$0")" && pwd)

# A normal user, uid 1000 like the desktop login, so an ssh login gets a
# user manager, /run/user/1000 and a session bus.
if ! grep -q '^narf:' "$R/etc/passwd"; then
  hash=$(openssl passwd -6 -salt narfcachyos narf)
  echo 'narf:x:1000:1000:NARF soak:/home/narf:/usr/bin/bash' >> "$R/etc/passwd"
  echo 'narf:x:1000:' >> "$R/etc/group"
  echo "narf:${hash}:19000:0:99999:7:::" >> "$R/etc/shadow"
fi
mkdir -p "$R/home/narf/src"
if [ -n "${SOAK_TREE:-}" ] && [ -d "$SOAK_TREE" ] && [ ! -d "$R/home/narf/src/$(basename "$SOAK_TREE")" ]; then
  cp -a --no-preserve=ownership "$SOAK_TREE" "$R/home/narf/src/"
fi
chown -R 1000:1000 "$R/home/narf"

# sshd with key logins only; the keys live outside the home subvolumes.
mkdir -p "$R/etc/ssh/sshd_config.d" "$R/etc/ssh/narf-soak-keys"
cat > "$R/etc/ssh/sshd_config.d/10-narf-soak.conf" <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
AuthorizedKeysFile /etc/ssh/narf-soak-keys/%u
EOF
for user in root narf; do
  install -m 0644 "$SOAK_PUBKEY" "$R/etc/ssh/narf-soak-keys/$user"
done

# The workload unit. It only runs when the command line asks for it, so the
# image still boots as the plain smoke image.
mkdir -p "$R/opt/narf-soak" "$R/etc/systemd/system/multi-user.target.wants"
for f in "$HERE/soak-guest.sh" "$HERE/soak-guest.py" "${SOAK_NATIVE:-}"; do
  [ -f "$f" ] && install -m 0755 "$f" "$R/opt/narf-soak/$(basename "$f")"
done
cat > "$R/opt/narf-soak/bootstrap.sh" <<'EOF'
#!/bin/bash
# Prefer the copy on the ESP: the host refreshes it there before every run
# without rebuilding the image.
for _ in $(seq 1 20); do
  [ -r /boot/efi/soak/soak-guest.sh ] && break
  sleep 1
done
src=/opt/narf-soak
[ -r /boot/efi/soak/soak-guest.sh ] && src=/boot/efi/soak
mkdir -p /run/narf-soak
cp "$src"/* /run/narf-soak/ 2>/dev/null
chmod 0755 /run/narf-soak/* 2>/dev/null
echo "narf-soak: workload from $src" > /dev/ttyS0
exec /usr/bin/bash /run/narf-soak/soak-guest.sh
EOF
chmod 0755 "$R/opt/narf-soak/bootstrap.sh"
cat > "$R/etc/systemd/system/narf-soak.service" <<'EOF'
[Unit]
Description=NARF QEMU soak workload
ConditionKernelCommandLine=narf_soak
After=local-fs.target network.target dbus.service sshd.service systemd-user-sessions.service systemd-logind.service

[Service]
Type=simple
ExecStart=/usr/bin/bash /opt/narf-soak/bootstrap.sh
StandardOutput=journal
StandardError=journal
LimitCORE=infinity
LimitNOFILE=65536
TasksMax=infinity
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
for unit in /usr/lib/systemd/system/sshd.service /etc/systemd/system/narf-soak.service; do
  ln -sfn "$unit" "$R/etc/systemd/system/multi-user.target.wants/$(basename "$unit")"
done
