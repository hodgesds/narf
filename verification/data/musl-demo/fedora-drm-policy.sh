#!/bin/sh
# Apply and expose the synthetic DRM-node policy used by the Fedora Plasma
# acceptance image. Numeric IDs avoid making early graphical startup depend on
# NSS; Fedora's `video` group is gid 39 in this image.
set -x
/usr/bin/ls -ln /dev/dri
/usr/bin/chown 0:39 /dev/dri/card0
/usr/bin/chmod 0660 /dev/dri/card0
/usr/bin/chmod 0666 /dev/dri/renderD128
/usr/bin/ls -ln /dev/dri

# What libdrm actually sees when it classifies the DRM node's bus.
#
# drmGetDevices2 -> drmParseSubsystemType readlink()s
# /sys/dev/char/226:0/device/subsystem and compares the BASENAME against
# "pci"/"platform"/"usb"; only then does it read the vendor/device ids. Mesa
# reports "MESA-LOADER: failed to retrieve device information" when that
# classification fails, and kwin exits behind it.
#
# Adding the subsystem symlink alone did NOT clear the error, so dump what is
# really there rather than reasoning from libdrm's source a second time.
echo "DRMPROBE: --- /sys/dev/char/226:0 ---"
/usr/bin/readlink /sys/dev/char/226:0 || echo "DRMPROBE: 226:0 not a symlink"
echo "DRMPROBE: --- card0/device/ contents ---"
/usr/bin/ls -l /sys/class/drm/card0/device/ 2>&1 | head -20
echo "DRMPROBE: --- device/subsystem readlink (the load-bearing one) ---"
/usr/bin/readlink /sys/class/drm/card0/device/subsystem \
  || echo "DRMPROBE: device/subsystem UNREADABLE as a link"
echo "DRMPROBE: --- does it resolve? ---"
/usr/bin/ls -d /sys/class/drm/card0/device/subsystem/ 2>&1 | head -3
echo "DRMPROBE: --- ids libdrm would read ---"
for a in vendor device subsystem_vendor subsystem_device revision; do
  printf 'DRMPROBE: %s=' "$a"
  /usr/bin/cat "/sys/class/drm/card0/device/$a" 2>&1 | head -1
done
echo "DRMPROBE: --- /sys/bus/pci/devices ---"
/usr/bin/ls -l /sys/bus/pci/devices/ 2>&1 | head -10

# Is the config blob actually READABLE from userspace? A sysfs binary attr
# that is registered but not wired into the VFS read path looks identical,
# from Mesa's error message, to one that is absent. Verify the fix is
# observable before blaming the consumer for rejecting it.
echo "DRMPROBE: --- device/config readability ---"
/usr/bin/ls -l /sys/class/drm/card0/device/config 2>&1 | head -2
printf 'DRMPROBE: config bytes read = '
/usr/bin/dd if=/sys/class/drm/card0/device/config bs=64 count=1 2>/dev/null | /usr/bin/wc -c
echo "DRMPROBE: --- first 16 bytes (expect 34 12 11 11 ...) ---"
/usr/bin/od -An -tx1 -N16 /sys/class/drm/card0/device/config 2>&1 | head -2

# Can the SESSION USER actually open the render node?
#
# eglInitialize fails with "DRI2: failed to get compatible render device"
# AFTER Mesa has already picked a CPU renderer, so driver lookup succeeded
# and the fault is in render-DEVICE selection. Kernel-side the render node
# dispatches to the same card as card0 (dispatch_card render=true) and allows
# VERSION/GET_CAP, so the nodes should be matchable — which leaves "can it be
# opened at all, as uid 1000" as the untested assumption.
echo "DRMPROBE: --- render node open test (as narf) ---"
/usr/bin/ls -ln /dev/dri/renderD128 2>&1 | head -2
/usr/bin/setpriv --reuid=1000 --regid=39 --clear-groups \
  /bin/sh -c ': < /dev/dri/renderD128' 2>&1 \
  && echo "DRMPROBE: renderD128 OPEN OK as uid 1000" \
  || echo "DRMPROBE: renderD128 OPEN FAILED as uid 1000"
/usr/bin/setpriv --reuid=1000 --regid=39 --clear-groups \
  /bin/sh -c ': < /dev/dri/card0' 2>&1 \
  && echo "DRMPROBE: card0 OPEN OK as uid 1000" \
  || echo "DRMPROBE: card0 OPEN FAILED as uid 1000"
