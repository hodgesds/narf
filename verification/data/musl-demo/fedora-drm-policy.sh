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
